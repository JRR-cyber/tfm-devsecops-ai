"""End-to-end agent orchestrator (Fase 3 capstone): SARIF -> triage -> fix -> PR.

Ties the pipeline together for the auto-remediation candidate set:

    parse (3.2)  ->  filter CVSS>=7 AND has_trace (3.3)  ->  triage TP/FP (3.4,
    with trace 3.4 + RAG 3.5, strategy 3.6)  ->  if TP: patch as diff (3.6)  ->
    apply + branch + PR (3.7, assistive, human approves)

The candidate set is CVSS>=7 intersected with "has a taint trace" (CodeQL): the
severity filter says *worth fixing*, the trace gate says *this is the terrain the
hybrid method works on* (Semgrep/Trivy/TruffleHog highs are reported, not patched).

Live stages (triage, remediate) need GROQ_API_KEY. The PR stage is dry-run by
default (applies in memory, shows the result); --commit writes a local branch,
--open also pushes and opens the PR.

Usage:
    python scripts/ai_agent/triage_engine.py <unified.sarif> --repo-root .          # list candidates
    GROQ_API_KEY=... python scripts/ai_agent/triage_engine.py <unified.sarif> \
        --repo-root . --fingerprint <fp> --run [--strategy cot] [--commit] [--open]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from remediation_pr import prepare_pr
from sarif_parser import SourceReader, parse_sarif
from severity import score
from strategies import STRATEGIES, ZERO_SHOT


def candidates(findings: list) -> list:
    """CVSS>=7 AND has a taint trace — the auto-remediation candidate set."""
    return [f for f in findings if score(f).auto_remediable and f.has_trace]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--fingerprint", help="run one finding end-to-end (else just list candidates)")
    parser.add_argument("--strategy", default=ZERO_SHOT, choices=STRATEGIES)
    parser.add_argument("--run", action="store_true", help="call the LLM (needs GROQ_API_KEY)")
    parser.add_argument("--commit", action="store_true", help="create the fix branch + commit")
    parser.add_argument("--open", action="store_true", help="push and open the PR (gh)")
    args = parser.parse_args()

    findings = parse_sarif(args.sarif, args.repo_root)
    cand = candidates(findings)

    if not args.fingerprint:
        print(f"{len(cand)} auto-remediation candidates (CVSS>=7 AND with trace):\n")
        for f in cand:
            print(f"  {f.label_key[:8]}  CVSS {f.security_severity}  {f.rule_id}  {f.file}:{f.start_line}")
        print("\nRe-run with --fingerprint <id> --run to triage and propose a fix.")
        return

    target = next((f for f in cand if args.fingerprint in (f.fingerprint, f.label_key)), None)
    if target is None:
        raise SystemExit(f"{args.fingerprint} is not an auto-remediation candidate")
    if not args.run:
        raise SystemExit("add --run to call the LLM for triage + remediation")

    from groq_client import GroqClient
    from remediate import remediate
    from triage import decide

    client = GroqClient()
    reader = SourceReader(args.repo_root)

    verdict = decide(target, client, reader, with_trace=True, with_rag=True, strategy=args.strategy)
    print(f"triage: {verdict.verdict} (conf={verdict.confidence}) — {verdict.rationale}\n")
    if verdict.verdict != "TP":
        print("not a TP: the agent reports it, no patch proposed.")
        return

    patch = remediate(target, client, reader, with_trace=True, with_rag=True, strategy=args.strategy)
    if not patch.diff:
        print("no diff produced by the model.")
        return
    print("proposed patch:\n" + patch.diff + "\n")
    print(prepare_pr(target, patch.diff, args.repo_root, verdict=verdict.verdict,
                     commit=args.commit, open_pr=args.open))


if __name__ == "__main__":
    main()
