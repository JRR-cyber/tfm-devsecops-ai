"""Offline checks of the PARSE_ERROR outcome (D12 addendum of 2026-11-26).

A patch that leaves the only file in CodeQL's scope unparseable made
``codeql database create`` stop (exit 32) and the runner treated it as an
infrastructure failure. These checks pin the fix: it is a rejected attempt with
the parse error as feedback, and every other CodeQL failure is still raised.

The diagnostics are copied from the real failure (remediation pass 1,
tinyserver2, cot/trace, attempt 1).

usage: python scripts/phase5_review/test_parse_error.py
"""
from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ai_agent"))

import regression  # noqa: E402
import remediation_pr  # noqa: E402
import repair_loop  # noqa: E402
import rescan  # noqa: E402
import results  # noqa: E402
import worktree  # noqa: E402
from remediate import Patch  # noqa: E402
from sarif_parser import Finding  # noqa: E402

SCOPE = "benchmarks/secbench-js/cases/path-traversal/tinyserver2_0.5.2"
FILE = f"{SCOPE}/src/tinyserver.js"
PARSE = {"timestamp": "2026-11-26T20:24:08.4302907+01:00",
         "source": {"id": "js/parse-error", "name": "Could not process some files due to syntax errors",
                    "extractorName": "javascript"},
         "markdownMessage": "A parse error occurred: `Unexpected token`. Check the syntax of the file.",
         "severity": "warning", "location": {"file": "src\\tinyserver.js", "startLine": 27,
                                             "startColumn": 7, "endLine": 27, "endColumn": 7}}
NO_CODE = {"timestamp": "2026-11-26T20:24:08.8030678+01:00",
           "source": {"id": "cli/no-code-found", "name": "No JavaScript/TypeScript code found"},
           "plaintextMessage": "CodeQL detected code written in JavaScript/TypeScript but could not "
                               "process any of it.", "severity": "error"}

passed = failed = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global passed, failed
    passed, failed = passed + ok, failed + (not ok)
    print(f"[{'ok' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))


def write_db(db: Path, *diags: dict) -> None:
    (db / "diagnostic" / "extractors" / "javascript").mkdir(parents=True, exist_ok=True)
    (db / "diagnostic" / "cli-diagnostics-add-1.json").write_text(
        json.dumps(NO_CODE) + "\n", encoding="utf-8")
    (db / "diagnostic" / "extractors" / "javascript" / "autobuilder-1.jsonl").write_text(
        "".join(json.dumps(d) + "\n" for d in diags), encoding="utf-8")


def finding() -> Finding:
    return Finding(fingerprint="f7327adc:0", job="codeql", tool="CodeQL", rule_id="js/path-injection",
                   message="path depends on a user value", file=FILE, start_line=27, end_line=27,
                   level="error", security_severity=7.5)


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)

    # 1. patch_parse_errors
    db = tmp / "a" / "db"
    write_db(db, PARSE)
    got = regression.patch_parse_errors(db, SCOPE, [FILE])
    check("parse error in the patched file is found, with line and column",
          got == "src/tinyserver.js:27:7: Unexpected token", got)
    check("a Windows-style changed path matches too",
          regression.patch_parse_errors(db, SCOPE, [FILE.replace("/", "\\")]) == got)
    check("parse error in another file is not the patch's",
          regression.patch_parse_errors(db, SCOPE, [f"{SCOPE}/src/other.js"]) == "")
    db2 = tmp / "b" / "db"
    write_db(db2)
    check("no js/parse-error diagnostic -> nothing", regression.patch_parse_errors(db2, SCOPE, [FILE]) == "")
    check("no database at all -> nothing", regression.patch_parse_errors(tmp / "none", SCOPE, [FILE]) == "")

    # 2. verify_patch: rescan stubbed, the rest real (git rev-parse on this repo)
    base_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                              capture_output=True, check=True).stdout.strip()
    out_root = tmp / "rescan"
    baseline = out_root / "baseline" / base_sha[:12] / SCOPE.replace("/", "_")
    baseline.mkdir(parents=True)
    (baseline / "codeql.sarif").write_text("{}", encoding="utf-8")       # cached baseline
    wt_dir = tmp / "wt"
    (wt_dir / SCOPE / "src").mkdir(parents=True)

    @contextlib.contextmanager
    def fake_worktree(*_a, **_k):
        yield SimpleNamespace(path=wt_dir)

    def fake_apply(_diff, _path):
        return SimpleNamespace(ok=True, detail="applied (fake)", changed={FILE: "broken("})

    def rescan_fails(diags):
        def run(_src, out_dir, _scope, _cli):
            write_db(Path(out_dir) / "db", *diags)
            raise rescan.RescanError("codeql database create failed (exit 32): ... could not process any of it")
        return run

    saved = (worktree.worktree, remediation_pr.apply_by_content, rescan.rescan)
    worktree.worktree, remediation_pr.apply_by_content = fake_worktree, fake_apply
    try:
        rescan.rescan = rescan_fails([PARSE])
        v = regression.verify_patch(finding(), "diff", ROOT, base_sha, out_root=out_root)
        check("verify_patch: unparseable patch -> applied, parse_error set, no comparison",
              v.applied and v.parse_error.startswith("src/tinyserver.js:27:7") and v.comparison is None
              and v.checks == [] and "post" in v.seconds, repr(v))

        rescan.rescan = rescan_fails([])
        try:
            regression.verify_patch(finding(), "diff", ROOT, base_sha, out_root=out_root)
            check("verify_patch: other CodeQL failure is still raised as infrastructure", False, "no raise")
        except rescan.RescanError:
            check("verify_patch: other CodeQL failure is still raised as infrastructure", True)
    finally:
        worktree.worktree, remediation_pr.apply_by_content, rescan.rescan = saved

    # 3. the loop's judge and the log record
    patch = Patch(diff="--- a/x\n+++ b/x\n", explanation="", strategy="cot", raw="raw")
    accepted, feedback = repair_loop.judge(finding(), patch, v)
    check("judge rejects the attempt", accepted is False)
    check("feedback names the parse error and asks for valid JavaScript",
          "not valid JavaScript" in feedback and "src/tinyserver.js:27:7: Unexpected token" in feedback
          and "exclude" not in feedback, feedback)
    rec = results.remediation_outcome(finding(), patch, v, base_sha)
    check("log record: status PARSE_ERROR with the error and the rescan seconds",
          rec["status"] == results.PARSE_ERROR and rec["parse_error"] == v.parse_error
          and rec["rescan_seconds"] == v.seconds and rec["checks"] == [], repr(rec))

    # 4. unchanged paths: a normal applied verification still needs its comparison
    ok_v = regression.Verification(False, "hunk 1 did not match", None, True, {})
    accepted, feedback = repair_loop.judge(finding(), patch, ok_v)
    check("apply failure keeps its old feedback", not accepted and feedback.startswith("The diff could not be applied"))
    check("apply failure keeps its old status",
          results.remediation_outcome(finding(), patch, ok_v)["status"] == results.APPLY_FAILED)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
