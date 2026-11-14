"""Local post-patch rescan with the CodeQL CLI (Paso 4.2).

After the agent applies a patch (in an isolated worktree, 4.1) it must check
whether the vulnerability is gone and whether the patch introduced new ones.
Pushing every attempt to CI would cost ~2 min per attempt and leave branches on
GitHub, which a reflexive loop of up to 3 attempts x 33 cases cannot afford, so
the rescan runs locally with the **same analysis CI runs**:

- CodeQL CLI pinned to the version recorded in CI's SARIF
  (``tool.driver.semanticVersion`` = 2.27.4 on run 43605673798; the action's
  default bundle is 2.27.0 but the runner had a newer cached one), refusing to
  run with another version unless explicitly allowed;
- the same suite (``security-extended``), language and ``build-mode: none``;
- the output re-shaped like the unified artifact: one run with
  ``automationDetails.id = "codeql/"`` and ``partialFingerprints["tfmContextHash/v1"]``
  computed by **importing** ``unify_results.add_fingerprints`` (never a copy and
  never a change to that file), so pre/post matching (4.3) uses the exact key
  the rest of the pipeline uses.

Scope: only CodeQL is rescanned (the auto-remediation candidates are CodeQL
findings with a trace). Rescanning the whole repository per attempt is slow, so
the database is built from the finding's **project** only (Juice Shop, or one
SecBench.js case directory) and the SARIF URIs are rewritten back to
repository-relative paths. Checked, not assumed (``--compare <ci unified sarif>``
diffs local vs CI by fingerprint): over the dataset's 31 scopes all 253 CI
findings are recovered and 4 extra appear (cross-file flows resolved differently
when only the project is visible); a whole-repo local scan matches CI exactly
(345/345). Pre and post are both scanned locally with the same scope, so the
extras show up on both sides and do not change a verdict. Details in README.

The scan must run on a clean tree (a fix worktree): untracked/ignored files such
as Juice Shop's ``node_modules`` or ``frontend/dist`` would be extracted too.

Usage:
    python scripts/ai_agent/rescan.py --source-root . --scope src/app/juice-shop \
        --out ../tfm-worktrees/_rescan/js-main [--compare unified/findings.sarif]
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pipeline"))
from unify_results import SourceLines, add_fingerprints, normalise_uri  # noqa: E402

CODEQL_VERSION = "2.27.4"   # = CI SARIF tool.driver.semanticVersion (run 43605673798)
QUERY_SUITE = "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"
LANGUAGE = "javascript-typescript"
CATEGORY = "/language:javascript-typescript"   # same as the workflow's analyze step
JOB = "codeql"
FINGERPRINT_KEY = "tfmContextHash/v1"

_SECBENCH_CASE = re.compile(r"^(benchmarks/secbench-js/cases/[^/]+/[^/]+)/")
_JUICE_SHOP = "src/app/juice-shop"


class RescanError(RuntimeError):
    """The CodeQL CLI is missing, has the wrong version, or a step failed."""


@dataclass
class RescanResult:
    sarif: Path          # unified-shaped SARIF (one codeql/ run, with tfmContextHash)
    scope: str           # repo-relative project scanned ("" = whole repository)
    version: str         # CodeQL CLI version actually used
    seconds: float       # wall time of database create + analyze (overhead metric)
    results: int


def scope_for(path: str) -> str:
    """The project a finding belongs to: one SecBench case, Juice Shop, or the repo."""
    path = normalise_uri(path)
    if (m := _SECBENCH_CASE.match(path)):
        return m.group(1)
    if path.startswith(_JUICE_SHOP + "/"):
        return _JUICE_SHOP
    return ""


def find_codeql(explicit: str | None = None) -> str:
    """Path to the CodeQL CLI: --codeql, then $CODEQL_CLI, then PATH."""
    cli = explicit or os.environ.get("CODEQL_CLI") or shutil.which("codeql")
    if not cli:
        raise RescanError("CodeQL CLI not found: install the bundle and add it to PATH "
                          "or set CODEQL_CLI (see scripts/ai_agent/README.md, 4.2)")
    return cli


def codeql_version(cli: str) -> str:
    res = subprocess.run([cli, "version", "--format=terse"], text=True, capture_output=True)
    if res.returncode != 0:
        raise RescanError(f"`codeql version` failed: {res.stderr.strip()}")
    return res.stdout.strip()


def untracked_paths(source_root: Path, scope: str) -> list[str]:
    """Files under ``scope`` that git does not track (untracked *or* ignored).

    CI scans a fresh checkout, which only has tracked files. A developer checkout
    of Juice Shop also holds ``node_modules``, ``build/`` and ``frontend/dist``
    (thousands of generated, minified JS files): CodeQL would extract them, run
    for a very long time and report findings CI never sees. Directories are
    collapsed (``--directory``) so the check stays fast.
    """
    res = subprocess.run(["git", "ls-files", "--others", "--directory", "--no-empty-directory",
                          "--", scope or "."], cwd=source_root, text=True, capture_output=True)
    if res.returncode != 0:
        raise RescanError(f"{source_root} is not a git checkout: {res.stderr.strip()}")
    return res.stdout.splitlines()


def _run(cmd: list[str], what: str) -> None:
    res = subprocess.run(cmd, text=True, capture_output=True)
    if res.returncode != 0:
        tail = "\n".join((res.stderr or res.stdout).strip().splitlines()[-15:])
        raise RescanError(f"{what} failed (exit {res.returncode}):\n{tail}")


def _prefix_uris(node, prefix: str) -> None:
    """Rewrite every %SRCROOT%-relative artifact URI to be repository-relative."""
    if isinstance(node, dict):
        uri = node.get("uri")
        if isinstance(uri, str) and node.get("uriBaseId", "%SRCROOT%") == "%SRCROOT%" \
                and "://" not in uri and not uri.startswith("/"):
            node["uri"] = f"{prefix}/{uri}"
        for value in node.values():
            _prefix_uris(value, prefix)
    elif isinstance(node, list):
        for value in node:
            _prefix_uris(value, prefix)


def unify_codeql_sarif(raw: dict, scope: str, source_root: Path) -> dict:
    """Shape a raw CodeQL SARIF like the unified artifact (one codeql/ run)."""
    runs = raw.get("runs", [])
    if len(runs) != 1:
        raise RescanError(f"expected one CodeQL run, got {len(runs)}")
    run = runs[0]
    if scope:
        _prefix_uris(run.get("results", []), scope)
        _prefix_uris(run.get("artifacts", []), scope)
    run["automationDetails"] = {"id": f"{JOB}/"}
    add_fingerprints(JOB, run, SourceLines(source_root))
    return {"$schema": raw.get("$schema"), "version": raw.get("version", "2.1.0"), "runs": [run],
            "properties": {"tfm": {"fingerprint": FINGERPRINT_KEY, "scope": scope, "local": True}}}


def rescan(source_root: Path, out_dir: Path, scope: str = "", cli: str | None = None,
           threads: int = 0, allow_version_mismatch: bool = False,
           allow_untracked: bool = False) -> RescanResult:
    """Build a CodeQL database of ``scope`` under ``source_root`` and analyse it.

    ``source_root`` should be a clean tree with only tracked files — a fix
    worktree (4.1) is exactly that — so the scan sees what CI sees.
    """
    source_root = source_root.resolve()
    project = source_root / scope if scope else source_root
    if not project.is_dir():
        raise RescanError(f"scope {scope!r} is not a directory under {source_root}")
    extra = untracked_paths(source_root, scope)
    if extra and not allow_untracked:
        shown = ", ".join(extra[:5]) + (f" (+{len(extra) - 5} more)" if len(extra) > 5 else "")
        raise RescanError(f"{len(extra)} untracked/ignored path(s) under the scope, which CI "
                          f"would not scan: {shown}. Rescan a clean worktree instead "
                          "(or pass --allow-untracked for a dev run).")

    cli = find_codeql(cli)
    version = codeql_version(cli)
    if version != CODEQL_VERSION and not allow_version_mismatch:
        raise RescanError(f"CodeQL CLI {version} != {CODEQL_VERSION} (the version CI used); "
                          "results would not be comparable. Install the pinned bundle "
                          "or pass --allow-version-mismatch for a dev run.")

    out_dir.mkdir(parents=True, exist_ok=True)
    db, raw_path, sarif_path = out_dir / "db", out_dir / "codeql-raw.sarif", out_dir / "codeql.sarif"
    start = time.monotonic()
    _run([cli, "database", "create", str(db), f"--language={LANGUAGE}", "--build-mode=none",
          f"--source-root={project}", "--overwrite", f"--threads={threads}"],
         "codeql database create")
    _run([cli, "database", "analyze", str(db), QUERY_SUITE, "--format=sarif-latest",
          f"--output={raw_path}", f"--sarif-category={CATEGORY}", f"--threads={threads}"],
         "codeql database analyze")
    seconds = time.monotonic() - start

    unified = unify_codeql_sarif(json.loads(raw_path.read_text(encoding="utf-8")), scope, source_root)
    sarif_path.write_text(json.dumps(unified, indent=1), encoding="utf-8")
    return RescanResult(sarif=sarif_path, scope=scope, version=version,
                        seconds=round(seconds, 1), results=len(unified["runs"][0]["results"]))


def _results_in_scope(sarif: Path, scope: str) -> dict[str, tuple[str, str, int]]:
    """fingerprint -> (rule, file, line) for the codeql/ run, restricted to scope."""
    data = json.loads(sarif.read_text(encoding="utf-8"))
    out = {}
    for run in data.get("runs", []):
        if run.get("automationDetails", {}).get("id") != f"{JOB}/":
            continue
        for res in run.get("results", []):
            phys = res["locations"][0]["physicalLocation"]
            uri = normalise_uri(phys["artifactLocation"]["uri"])
            if scope and not uri.startswith(scope + "/"):
                continue
            out[res["partialFingerprints"][FINGERPRINT_KEY]] = (
                res.get("ruleId", ""), uri, phys.get("region", {}).get("startLine", 0))
    return out


def compare(local: Path, reference: Path, scope: str) -> str:
    """Report how the local rescan matches a reference (CI unified) SARIF, by fingerprint."""
    loc, ref = _results_in_scope(local, scope), _results_in_scope(reference, scope)
    both = loc.keys() & ref.keys()
    lines = [f"scope {scope or '(repo)'}: local {len(loc)}, reference {len(ref)}, "
             f"matched {len(both)}, only-local {len(loc) - len(both)}, only-reference {len(ref) - len(both)}"]
    for title, keys, src in (("only local:", loc.keys() - ref.keys(), loc),
                             ("only reference:", ref.keys() - loc.keys(), ref)):
        if keys:
            lines.append(title)
            lines += [f"  {src[k][0]}  {src[k][1]}:{src[k][2]}" for k in sorted(keys, key=lambda k: src[k])]
    return "\n".join(lines)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--source-root", type=Path, default=Path("."),
                        help="repository root to scan (a fix worktree, or the main checkout)")
    parser.add_argument("--scope", default=None,
                        help="repo-relative project dir (default: whole repo); see also --scope-of")
    parser.add_argument("--scope-of", help="derive the scope from a finding's file path")
    parser.add_argument("--out", type=Path, required=True, help="directory for the database and SARIF")
    parser.add_argument("--codeql", help="path to the CodeQL CLI (default: $CODEQL_CLI or PATH)")
    parser.add_argument("--threads", type=int, default=0, help="0 = one per core")
    parser.add_argument("--allow-version-mismatch", action="store_true", help="dev runs only")
    parser.add_argument("--allow-untracked", action="store_true",
                        help="dev runs only: scan even if the scope has untracked/ignored files")
    parser.add_argument("--compare", type=Path, help="reference unified SARIF (e.g. CI's) to diff against")
    args = parser.parse_args()

    scope = scope_for(args.scope_of) if args.scope_of else (args.scope or "").strip("/")
    try:
        result = rescan(args.source_root, args.out, scope, args.codeql, args.threads,
                        args.allow_version_mismatch, args.allow_untracked)
    except RescanError as exc:
        raise SystemExit(f"error: {exc}")
    print(f"CodeQL {result.version}  scope={result.scope or '(repo)'}  "
          f"{result.results} results  {result.seconds}s  -> {result.sarif}")
    if args.compare:
        print(compare(result.sarif, args.compare, scope))


if __name__ == "__main__":
    main()
