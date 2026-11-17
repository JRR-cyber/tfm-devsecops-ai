"""End-to-end agent orchestrator (Fase 3 capstone): SARIF -> triage -> fix -> PR.

Ties the pipeline together for the auto-remediation candidate set:

    parse (3.2)  ->  filter CVSS>=7 AND has_trace (3.3)  ->  triage TP/FP (3.4,
    with trace 3.4 + RAG 3.5, strategy 3.6)  ->  if TP: reflexive repair loop
    (patch as diff 3.6, verified by CodeQL 4.2-4.4 and the D9 oracles 4.8, up to
    3 attempts 4.7)  ->  publish (4.9): verified fix -> PR labelled ai-fixed
    [+ ai-needs-review]; escalated -> issue labelled ai-escalated. Assistive: a
    human approves every merge.

The candidate set is CVSS>=7 intersected with "has a taint trace" (CodeQL): the
severity filter says *worth fixing*, the trace gate says *this is the terrain the
hybrid method works on* (Semgrep/Trivy/TruffleHog highs are reported, not patched).

Live stages (triage, remediate) need GROQ_API_KEY; the loop needs the CodeQL CLI
and Docker (oracles). Publication is dry-run by default (shows the PR or issue it
would create); --commit writes the local fix branch, --open also publishes
(push + PR, or issue). Every attempt is logged (4.5) in --log.

Usage:
    python scripts/ai_agent/triage_engine.py <unified.sarif> --repo-root .          # list candidates
    GROQ_API_KEY=... python scripts/ai_agent/triage_engine.py <unified.sarif> \
        --repo-root . --fingerprint <fp> --run [--strategy cot] [--commit] [--open]
"""

from __future__ import annotations

import argparse
from pathlib import Path

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
    parser.add_argument("--open", action="store_true",
                        help="publish: push + PR (verified fix) or issue (escalated), with gh")
    parser.add_argument("--draft", action="store_true",
                        help="open the PR as a draft titled [DEMO · NO MERGE] (benchmark demos)")
    parser.add_argument("--codeql", help="path to the CodeQL CLI (default: $CODEQL_CLI or PATH)")
    parser.add_argument("--no-oracles", action="store_true", help="CodeQL only (skip the D9 oracles)")
    parser.add_argument("--log", type=Path, default=Path("results/dev/engine.jsonl"))
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
    from publish import decide as decide_publication, publish
    from repair_loop import oracle_checks, repair
    from rescan import codeql_version, find_codeql
    from results import TRIAGE, ResultLog, RunKey, environment, triage_outcome
    from triage import decide

    repo_root = args.repo_root.resolve()
    client = GroqClient()
    reader = SourceReader(repo_root)
    cli = find_codeql(args.codeql)
    log = ResultLog(args.log, environment(repo_root, codeql_version(cli)))

    key = RunKey(TRIAGE, target.label_key, args.strategy, True, True)
    if log.done(key):                       # resume: do not pay for the triage again
        verdict = log.get(key)["verdict"]
        print(f"triage (from the log): {verdict}\n")
    else:
        v = decide(target, client, reader, with_trace=True, with_rag=True, strategy=args.strategy)
        log.append(key, triage_outcome(target, v))
        verdict = v.verdict
        print(f"triage: {v.verdict} (conf={v.confidence}) — {v.rationale}\n")
    if verdict != "TP":
        print("not a TP: the agent reports it, no patch proposed.")
        return

    # 4.7-4.8: reflexive loop with CodeQL and the D9 oracles; 4.9: label or escalate.
    loop = repair(target, client, repo_root, reader=reader, strategy=args.strategy, log=log,
                  cli=cli, checks=None if args.no_oracles else oracle_checks(repo_root))
    print(loop.summary() + "\n")
    decision = decide_publication(target, loop, repo_root, verdict=verdict)
    print(f"publication: {decision.kind}, labels {decision.labels}")
    print(publish(decision, target, repo_root, commit=args.commit, open_=args.open,
                  draft=args.draft))


if __name__ == "__main__":
    main()
