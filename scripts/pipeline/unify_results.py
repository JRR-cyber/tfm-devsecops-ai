"""Consolidate the scanners' output into a single SARIF 2.1.0 log (Paso 2.6).

The unified log keeps one SARIF run per scanner job, untouched except for:

- ``automationDetails.id``: set to ``<job>/`` (e.g. ``trivy-fs/``) so that two
  runs of the same tool (Trivy on lockfiles and on the image) stay apart.
- ``partialFingerprints["tfmContextHash/v1"]``: added to every result. It is
  the key used to match findings before and after a patch (Fase 4), so it must
  not depend on line numbers: it hashes the job, the rule, the file and the
  normalised text of the flagged lines, plus an occurrence index among
  identical keys (the same scheme as GitHub's ``primaryLocationLineHash``).
  Tools fill ``partialFingerprints`` inconsistently (or not at all), so the
  native ones are kept but this one is the common key.

TruffleHog emits JSON lines, not SARIF; they are converted to a SARIF run.
The raw secret is never copied (the workflow already strips it).

Input layout (one file or folder per scanner job, as the workflow writes it):
    semgrep.sarif  codeql/*.sarif  trivy-fs.sarif  trivy-image.sarif  trufflehog.jsonl

Usage:
    python scripts/pipeline/unify_results.py <results_dir> <out_sarif> [--repo-root DIR] [--summary FILE]
"""

import argparse
import hashlib
import json
import os
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
FINGERPRINT_KEY = "tfmContextHash/v1"
EXPECTED_JOBS = ["semgrep", "codeql", "trivy-fs", "trivy-image", "trufflehog"]
MAX_CONTEXT_LINES = 5
WHITESPACE_RE = re.compile(r"\s+")


def job_of(path: Path, results_dir: Path) -> str:
    """Job name from the input location: codeql/x.sarif -> codeql, trivy-fs.sarif -> trivy-fs."""
    rel = path.relative_to(results_dir)
    return rel.parts[0] if len(rel.parts) > 1 else path.stem


def normalise_uri(uri: str) -> str:
    uri = uri.removeprefix("file://")
    for prefix in ("/repo/", "/work/", "/src/"):
        uri = uri.removeprefix(prefix)
    return uri.removeprefix("./")


def trufflehog_run(jsonl: Path) -> dict:
    """SARIF run equivalent to TruffleHog's JSON-lines output."""
    rules, results = {}, []
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        detector = item.get("DetectorName", "Unknown")
        rule_id = f"trufflehog/{detector}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": detector,
            "shortDescription": {"text": f"Hard-coded {detector} credential"},
            "properties": {"tags": ["security", "secret", "external/cwe/cwe-798"]},
        })
        source = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        verified = "verified" if item.get("Verified") else "unverified"
        results.append({
            "ruleId": rule_id,
            "level": "error",
            "message": {"text": f"{detector} credential ({verified}): {item.get('Redacted') or '[redacted]'}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": normalise_uri(source.get("file", ""))},
                "region": {"startLine": int(source.get("line") or 1)},
            }}],
            "properties": {"verified": bool(item.get("Verified")), "decoder": item.get("DecoderName")},
        })
    return {
        "tool": {"driver": {
            "name": "TruffleHog",
            "informationUri": "https://github.com/trufflesecurity/trufflehog",
            "rules": list(rules.values()),
        }},
        "results": results,
    }


def load_runs(results_dir: Path) -> list[tuple[str, dict]]:
    runs = []
    for path in sorted(results_dir.rglob("*.sarif")):
        sarif = json.loads(path.read_text(encoding="utf-8"))
        runs += [(job_of(path, results_dir), run) for run in sarif.get("runs", [])]
    for path in sorted(results_dir.rglob("*.jsonl")):
        runs.append((job_of(path, results_dir), trufflehog_run(path)))
    return runs


class SourceLines:
    """Cached access to the repository files the findings point at."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.cache: dict[str, list[str] | None] = {}

    def get(self, uri: str, start: int, end: int) -> str | None:
        if uri not in self.cache:
            path = (self.root / uri).resolve()
            ok = path.is_file() and path.is_relative_to(self.root)
            self.cache[uri] = path.read_text(encoding="utf-8", errors="replace").splitlines() if ok else None
        lines = self.cache[uri]
        if not lines or start < 1 or start > len(lines):
            return None
        end = min(max(end, start), start + MAX_CONTEXT_LINES - 1, len(lines))
        return WHITESPACE_RE.sub(" ", " ".join(lines[start - 1:end])).strip()


def primary_location(result: dict) -> tuple[str, int, int]:
    for loc in result.get("locations", [])[:1]:
        phys = loc.get("physicalLocation", {})
        region = phys.get("region", {})
        start = int(region.get("startLine", 0))
        return normalise_uri(phys.get("artifactLocation", {}).get("uri", "")), start, int(region.get("endLine", start))
    return "", 0, 0


def add_fingerprints(job: str, run: dict, sources: SourceLines) -> None:
    keyed = []
    for result in run.get("results", []):
        uri, start, end = primary_location(result)
        # No readable source line (e.g. a package inside a container image): the
        # message identifies the finding instead (package, installed version, CVE).
        context = sources.get(uri, start, end) or result.get("message", {}).get("text", "")
        rule = result.get("ruleId") or str(result.get("rule", {}).get("id", ""))
        key = "\0".join([job, rule, uri, context])
        keyed.append((key, start, result))

    seen: Counter[str] = Counter()
    for key, _, result in sorted(keyed, key=lambda k: (k[0], k[1])):
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        result.setdefault("partialFingerprints", {})[FINGERPRINT_KEY] = f"{digest}:{seen[key]}"
        seen[key] += 1


def flow_length(result: dict) -> int:
    """Longest threadFlow (number of steps) of a result, 0 if it has no codeFlows."""
    return max((len(tf.get("locations", []))
                for cf in result.get("codeFlows", []) for tf in cf.get("threadFlows", [])), default=0)


def summary_markdown(runs: list[dict], missing: list[str]) -> str:
    rows = defaultdict(lambda: {"results": 0, "levels": Counter(), "flows": []})
    for run in runs:
        job = run["automationDetails"]["id"].rstrip("/")
        row = rows[job]
        row["tool"] = run["tool"]["driver"].get("name", job)
        for result in run.get("results", []):
            row["results"] += 1
            row["levels"][result.get("level", "warning")] += 1
            if (n := flow_length(result)):
                row["flows"].append(n)

    out = ["## Hallazgos unificados", "",
           "| Job | Herramienta | Hallazgos | error | warning | note | Con codeFlows | Pasos por traza (mediana) |",
           "|---|---|---:|---:|---:|---:|---:|---:|"]
    for job, row in sorted(rows.items()):
        flows = row["flows"]
        median = f"{statistics.median(flows):g}" if flows else "-"
        lv = row["levels"]
        out.append(f"| {job} | {row['tool']} | {row['results']} | {lv['error']} | {lv['warning']} "
                   f"| {lv['note']} | {len(flows)} | {median} |")
    if missing:
        out += ["", f"**Aviso:** sin resultados de: {', '.join(missing)}"]
    return "\n".join(out) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, help="append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    args = parser.parse_args()

    sources = SourceLines(args.repo_root)
    runs = []
    for job, run in load_runs(args.results_dir):
        run["automationDetails"] = {"id": f"{job}/"}
        add_fingerprints(job, run, sources)
        runs.append(run)

    present = {run["automationDetails"]["id"].rstrip("/") for run in runs}
    missing = [job for job in EXPECTED_JOBS if job not in present]
    unified = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": runs,
        "properties": {"tfm": {
            "commit": os.environ.get("GITHUB_SHA"),
            "fingerprint": FINGERPRINT_KEY,
            "missingJobs": missing,
        }},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(unified, indent=1), encoding="utf-8")

    summary = summary_markdown(runs, missing)
    print(summary)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as fh:
            fh.write(summary)


if __name__ == "__main__":
    main()
