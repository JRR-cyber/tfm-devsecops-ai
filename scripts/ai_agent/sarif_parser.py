"""Parse the unified SARIF into Finding objects the agent consumes (Paso 3.2).

The unified log (``scripts/pipeline/unify_results.py``) keeps one SARIF run per
scanner job, untouched except for ``automationDetails.id`` and the
``partialFingerprints["tfmContextHash/v1"]`` matching key. As a result, every
scanner records severity and rule metadata in its own place, and this module is
the single point that normalises them:

- **CodeQL**: numeric ``security-severity`` (CVSS-like 0-10) and the CWE tags
  live in the rules under ``tool.extensions[].rules``; each result points at its
  rule through ``result.rule`` / ``ruleId``. CodeQL is also the only scanner that
  emits ``codeFlows`` (the taint trace), so ``has_trace`` is only ever true here
  (decision D8).
- **Trivy** (fs + image): numeric ``security-severity`` (CVSS) in
  ``tool.driver.rules``; ``level`` on each result.
- **Semgrep**: *no* numeric severity — only ``defaultConfiguration.level``
  (error/warning/note) and CWE tags. Turning that into a CVSS number is the job
  of the documented Semgrep severity mapping in Paso 3.3, not of this parser.
- **TruffleHog**: secrets, always ``level: error``, no numeric severity.

So the unified SARIF does *not* strip severity; this parser surfaces it where it
exists and leaves ``security_severity`` as ``None`` where the tool gives none,
for 3.3 to fill via the mapping. The parser does not filter, triage or judge —
it only turns SARIF into typed records.

Usage:
    python scripts/ai_agent/sarif_parser.py <unified.sarif> [--repo-root DIR] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

FINGERPRINT_KEY = "tfmContextHash/v1"
CWE_RE = re.compile(r"cwe[-/ ]?(\d+)", re.IGNORECASE)
MAX_SNIPPET_LINES = 5


def normalise_uri(uri: str) -> str:
    """Same normalisation unify_results.py uses, so paths line up with it."""
    uri = uri.removeprefix("file://").replace("\\", "/")
    for prefix in ("/repo/", "/work/", "/src/"):
        uri = uri.removeprefix(prefix)
    return uri.removeprefix("./")


def cwes_from_tags(tags: list[str]) -> list[str]:
    """Pull CWE ids out of rule tags, in order, without duplicates.

    Covers CodeQL's ``external/cwe/cwe-1333`` and Semgrep's ``CWE-1333: ...``.
    """
    out: list[str] = []
    for tag in tags:
        for num in CWE_RE.findall(tag):
            cwe = f"CWE-{int(num)}"   # strip leading zeros: cwe-089 -> CWE-89 (labels.csv style)
            if cwe not in out:
                out.append(cwe)
    return out


@dataclass(frozen=True)
class CodeFlowStep:
    """One step of a taint trace: where the tainted value flows through."""

    file: str
    start_line: int
    message: str


@dataclass
class Finding:
    """A single scanner result, normalised across tools."""

    fingerprint: str                      # partialFingerprints["tfmContextHash/v1"]
    job: str                              # codeql | semgrep | trivy-fs | trivy-image | trufflehog
    tool: str                             # tool.driver.name
    rule_id: str
    message: str
    file: str                             # normalised, repo-relative
    start_line: int
    end_line: int
    level: str | None                     # error | warning | note (SARIF), if known
    security_severity: float | None       # CVSS 0-10 when the tool provides one, else None
    cwes: list[str] = field(default_factory=list)
    code_flows: list[list[CodeFlowStep]] = field(default_factory=list)
    snippet: str | None = None

    @property
    def label_key(self) -> str:
        """Bare fingerprint digest (no ``:occurrence``) — the key used in
        ``benchmarks/triage/labels.csv``. The full fingerprint keeps the
        occurrence index for pre/post-patch matching (Fase 4); the ground-truth
        triage labels are keyed on the digest alone (a ``vuln_group``), so this
        is what you join on to evaluate the triage decision (Fase 5)."""
        return self.fingerprint.split(":")[0]

    @property
    def has_trace(self) -> bool:
        """True iff some taint trace has >= 2 steps (the triage-set criterion T1/D8)."""
        return any(len(flow) >= 2 for flow in self.code_flows)

    @property
    def trace_length(self) -> int:
        """Longest taint trace, 0 if none."""
        return max((len(flow) for flow in self.code_flows), default=0)

    def as_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "job": self.job,
            "tool": self.tool,
            "rule_id": self.rule_id,
            "message": self.message,
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "level": self.level,
            "security_severity": self.security_severity,
            "cwes": self.cwes,
            "has_trace": self.has_trace,
            "trace_length": self.trace_length,
            "code_flows": [
                [{"file": s.file, "start_line": s.start_line, "message": s.message} for s in flow]
                for flow in self.code_flows
            ],
            "snippet": self.snippet,
        }


class SourceReader:
    """Cached read of the flagged source lines, to attach a snippet (optional)."""

    def __init__(self, root: Path | None):
        self.root = root.resolve() if root else None
        self._cache: dict[str, list[str] | None] = {}

    def snippet(self, uri: str, start: int, end: int) -> str | None:
        if not self.root or start < 1:
            return None
        if uri not in self._cache:
            path = (self.root / uri).resolve()
            ok = path.is_file() and path.is_relative_to(self.root)
            self._cache[uri] = (
                path.read_text(encoding="utf-8", errors="replace").splitlines() if ok else None
            )
        lines = self._cache[uri]
        if not lines or start > len(lines):
            return None
        end = min(max(end, start), start + MAX_SNIPPET_LINES - 1, len(lines))
        return "\n".join(lines[start - 1:end])


def _rule_index(run: dict) -> dict[str, dict]:
    """Map rule id -> rule object across the driver and every tool extension.

    CodeQL keeps its real rules (with security-severity) in ``tool.extensions``;
    Semgrep/Trivy keep them in ``tool.driver``. Results reference them by id, so a
    flat id->rule map resolves all of them.
    """
    index: dict[str, dict] = {}
    components = [run.get("tool", {}).get("driver", {})]
    components += run.get("tool", {}).get("extensions", [])
    for comp in components:
        for rule in comp.get("rules", []):
            index.setdefault(rule.get("id", ""), rule)
    return index


def _security_severity(rule: dict) -> float | None:
    raw = rule.get("properties", {}).get("security-severity")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _primary_region(result: dict) -> tuple[str, int, int]:
    for loc in result.get("locations", [])[:1]:
        phys = loc.get("physicalLocation", {})
        region = phys.get("region", {})
        start = int(region.get("startLine", 0) or 0)
        end = int(region.get("endLine", start) or start)
        return normalise_uri(phys.get("artifactLocation", {}).get("uri", "")), start, end
    return "", 0, 0


def _code_flows(result: dict) -> list[list[CodeFlowStep]]:
    """Each codeFlow reduced to the steps of its longest threadFlow."""
    flows: list[list[CodeFlowStep]] = []
    for cf in result.get("codeFlows", []):
        longest: list[dict] = max(
            (tf.get("locations", []) for tf in cf.get("threadFlows", [])),
            key=len,
            default=[],
        )
        steps = []
        for tfloc in longest:
            loc = tfloc.get("location", {})
            phys = loc.get("physicalLocation", {})
            steps.append(CodeFlowStep(
                file=normalise_uri(phys.get("artifactLocation", {}).get("uri", "")),
                start_line=int(phys.get("region", {}).get("startLine", 0) or 0),
                message=loc.get("message", {}).get("text", ""),
            ))
        if steps:
            flows.append(steps)
    return flows


def parse_sarif(path: Path, repo_root: Path | None = None) -> list[Finding]:
    """Read the unified SARIF and return one Finding per result, all runs flattened."""
    sarif = json.loads(Path(path).read_text(encoding="utf-8"))
    reader = SourceReader(repo_root)
    findings: list[Finding] = []

    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool_name = driver.get("name", "")
        job = run.get("automationDetails", {}).get("id", tool_name).rstrip("/")
        rules = _rule_index(run)

        for result in run.get("results", []):
            rule_id = result.get("ruleId") or str(result.get("rule", {}).get("id", ""))
            rule = rules.get(rule_id, {})
            uri, start, end = _primary_region(result)
            level = result.get("level") or rule.get("defaultConfiguration", {}).get("level")
            findings.append(Finding(
                fingerprint=result.get("partialFingerprints", {}).get(FINGERPRINT_KEY, ""),
                job=job,
                tool=tool_name,
                rule_id=rule_id,
                message=result.get("message", {}).get("text", ""),
                file=uri,
                start_line=start,
                end_line=end,
                level=level,
                security_severity=_security_severity(rule),
                cwes=cwes_from_tags(rule.get("properties", {}).get("tags", [])),
                code_flows=_code_flows(result),
                snippet=reader.snippet(uri, start, end),
            ))
    return findings


def _summary(findings: list[Finding]) -> str:
    by_job: dict[str, Counter] = {}
    for f in findings:
        row = by_job.setdefault(f.job, Counter())
        row["results"] += 1
        if f.has_trace:
            row["trace"] += 1
        if f.security_severity is not None:
            row["cvss"] += 1
    out = ["| Job | Hallazgos | Con traza (>=2) | Con CVSS numerico |",
           "|---|---:|---:|---:|"]
    for job in sorted(by_job):
        r = by_job[job]
        out.append(f"| {job} | {r['results']} | {r['trace']} | {r['cvss']} |")
    out.append(f"| **total** | **{len(findings)}** | "
               f"**{sum(1 for f in findings if f.has_trace)}** | "
               f"**{sum(1 for f in findings if f.security_severity is not None)}** |")
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sarif", type=Path, help="unified/findings.sarif")
    parser.add_argument("--repo-root", type=Path, default=None,
                        help="repo root, to attach source snippets")
    parser.add_argument("--json", action="store_true", help="dump findings as JSON instead of a summary")
    args = parser.parse_args()

    findings = parse_sarif(args.sarif, args.repo_root)
    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=1, ensure_ascii=False))
    else:
        print(_summary(findings))


if __name__ == "__main__":
    main()
