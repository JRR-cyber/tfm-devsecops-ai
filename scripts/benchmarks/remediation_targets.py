"""Pre-register the target finding of every remediation case (Paso 4.10).

``benchmarks/dataset.csv`` names each case by its *sink* (file + line), but the
agent repairs a *finding*: the reflexive loop judges FIXED / NOT_FIXED on one
fingerprint. Near a sink CodeQL often reports more than one traced finding (two
rules on the same line, or a path flagged on several lines), so the case -> finding
choice has to be fixed once, before any patch, by a deterministic rule:

1. CodeQL findings with a taint trace (C8) in the sink file, within ±10 lines of
   the sink (the C7 window of ``dataset.md``);
2. for SecBench.js, only the rules C7 accepted for the case (``codeql_sink_rules``
   of ``benchmarks/secbench-js/detection.csv``, i.e. a CWE of the vulnerability
   class);
3. rules whose taint source is the package's own input before rules that model
   the process environment or command line (``ENVIRONMENT_RULES``): SecBench's
   exploits attack the package through its API, so a finding whose trace starts
   at ``process.execPath`` / ``process.cwd()`` / ``process.argv`` is not the CVE's
   vector (the 4.10 rehearsal picked such findings for connection-tester,
   dns-sync, giting and bestzip, and the triage rightly called three of them FP);
4. the closest one to the sink line; ties by rule id, then fingerprint.

The other findings in the window are counted in ``near_sink`` (they stay in the
code; for SecBench the exploit oracle still checks the vulnerability as a whole).

``auto_remediable`` is the pipeline's policy filter (CVSS >= 7, 3.3) on CodeQL's
``security-severity``: CodeQL scores per rule, not per vulnerability, so most
SecBench command-injection (6.3) and prototype-pollution (6.1) cases fall below
it although their CVEs are rated High/Critical.

Fingerprints are line-independent (``tfmContextHash/v1``), so the file stays valid
while the vendored code does not change.

Usage:
    python scripts/benchmarks/remediation_targets.py <unified findings.sarif> [--check]
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts" / "ai_agent"))

from sarif_parser import parse_sarif  # noqa: E402
from severity import score  # noqa: E402

DATASET = REPO / "benchmarks" / "dataset.csv"
DETECTION = REPO / "benchmarks" / "secbench-js" / "detection.csv"
TARGETS = REPO / "benchmarks" / "remediation-targets.csv"
WINDOW = 10
# CodeQL rules whose sources are the process environment / command line, not the
# package's API input (see rule 3 of the docstring).
ENVIRONMENT_RULES = {"js/shell-command-injection-from-environment",
                     "js/indirect-command-line-injection"}
FIELDS = ["id", "source", "fingerprint", "rule", "file", "line", "sink_line", "cvss",
          "auto_remediable", "near_sink"]


def select(sarif: Path) -> list[dict]:
    findings = [f for f in parse_sarif(sarif, REPO) if f.has_trace]
    rules = {r["case_id"]: set(filter(None, r["codeql_sink_rules"].split(";")))
             for r in csv.DictReader(DETECTION.open(encoding="utf-8"))}
    rows = []
    for case in csv.DictReader(DATASET.open(encoding="utf-8")):
        sink = int(case["line"])
        allowed = rules.get(case["id"])
        near = {f.label_key: f for f in findings
                if f.file == case["file"] and abs(f.start_line - sink) <= WINDOW
                and (not allowed or f.rule_id in allowed)}
        if not near:
            raise SystemExit(f"{case['id']}: no traced CodeQL finding near the sink")
        f = min(near.values(), key=lambda f: (f.rule_id in ENVIRONMENT_RULES,
                                              abs(f.start_line - sink), f.rule_id, f.label_key))
        rows.append({"id": case["id"], "source": case["source"], "fingerprint": f.label_key,
                     "rule": f.rule_id, "file": f.file, "line": f.start_line, "sink_line": sink,
                     "cvss": f.security_severity, "auto_remediable": score(f).auto_remediable,
                     "near_sink": len(near) - 1})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sarif", type=Path, help="unified SARIF of the CI pipeline")
    parser.add_argument("--check", action="store_true",
                        help="only compare with the committed file (exit 1 if different)")
    args = parser.parse_args()
    rows = [{k: str(v) for k, v in r.items()} for r in select(args.sarif)]
    if args.check:
        current = list(csv.DictReader(TARGETS.open(encoding="utf-8")))
        if current != rows:
            raise SystemExit("remediation-targets.csv differs from this SARIF")
        print(f"{len(rows)} targets: identical")
        return
    with TARGETS.open("w", encoding="utf-8", newline="\n") as fh:
        w = csv.DictWriter(fh, FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    policy = sum(r["auto_remediable"] == "True" for r in rows)
    print(f"{len(rows)} targets -> {TARGETS.relative_to(REPO)} "
          f"({policy} pass CVSS>=7, {sum(r['near_sink'] != '0' for r in rows)} with other findings near the sink)")


if __name__ == "__main__":
    main()
