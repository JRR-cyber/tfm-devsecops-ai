"""Reflexive repair loop: patch, verify, feed the failure back, retry (Paso 4.7).

For one finding the agent gets up to ``max_attempts`` (3, fixed by the roadmap)
tries to produce an acceptable patch:

    attempt k:  remediate (with the rejected attempts 1..k-1 as feedback)
                -> verify_patch (worktree of the base, CodeQL rescan, 4.1-4.4,
                   plus the D9 oracles once 4.8 plugs them in as ``checks``)
                -> judge: accepted?  yes -> stop;  no -> feedback -> attempt k+1

An attempt is **accepted** only if the diff applies, the target is FIXED (4.3:
digest gone and not relocated), the patch introduced **no NEW finding** (a
security regression), and every extra oracle passes. Otherwise the reason becomes
the feedback of the next attempt. After ``max_attempts`` rejections the loop
stops and the finding is **escalated** to a human (4.9 labels the PR).

Design decisions (README "Bucle reflexivo (4.7)"):

- Every attempt is applied to the **original** file at the same base commit,
  never on top of a previous attempt: each verification is independent and the
  model is told so.
- Attempt 1 gets exactly the Phase 3 prompt; from attempt 2 on, the rejected
  diffs and the verifier's reasons are appended (``remediate.render_history``).
  The strategy, trace and RAG of the condition stay fixed across attempts.
- Every attempt is logged (4.5) with its number, ``accepted`` and the
  ``feedback`` it produced, as soon as it finishes. A relaunched run rebuilds the
  history from the log and continues at the next attempt.
- An **infrastructure** failure (CodeQL crash, network) raises and is *not*
  logged: it says nothing about the model, so the attempt is retried on resume.

Usage (live, needs GROQ_API_KEY and the CodeQL CLI of 4.2):
    python scripts/ai_agent/repair_loop.py <unified.sarif> --fingerprint <fp> --repo-root . \
        [--strategy cot] [--no-trace] [--no-rag] [--log results/dev/repair.jsonl]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from regression import FIXED, Check, Verification, verify_patch
from remediate import Patch, remediate
from results import REMEDIATION, ResultLog, RunKey, remediation_outcome
from sarif_parser import Finding, SourceReader
from strategies import ZERO_SHOT

MAX_ATTEMPTS = 3          # roadmap: at most 3 attempts per vulnerability
ACCEPTED, ESCALATED = "ACCEPTED", "ESCALATED"
_MSG_CHARS = 200          # CodeQL messages quoted in the feedback are cut to this


def _where(f: Finding) -> str:
    return f"{f.rule_id} at {f.file}:{f.start_line}"


def _msg(f: Finding) -> str:
    text = " ".join((f.message or "").split())
    return text if len(text) <= _MSG_CHARS else text[:_MSG_CHARS] + "..."


def judge(finding: Finding, patch: Patch, verification: Verification | None) -> tuple[bool, str]:
    """(accepted, feedback). The feedback is written for the model to act on."""
    if not patch.diff:
        return False, "Your reply contained no unified diff. Return exactly one ```diff block."
    if verification is None or not verification.applied:
        detail = verification.detail if verification else "not verified"
        return False, (f"The diff could not be applied ({detail}). The context and '-' lines "
                       "must be copied verbatim from the original file shown above "
                       "(same indentation, quotes and spacing); change only the lines the fix needs.")

    c = verification.comparison
    problems = []
    if c.status != FIXED:
        if c.relocated:
            post = next(b for a, b in c.moved if a.label_key == c.target)
            problems.append(f"CodeQL still reports {_where(post)}: the edit changed the flagged "
                            "line but the tainted data still reaches the sink.")
        else:
            post = next((f for f in c.persisting if f.label_key == c.target), None)
            where = _where(post) if post else f"{finding.rule_id} in {finding.file}"
            problems.append(f"CodeQL still reports {where}: the tainted data still reaches "
                            "the sink unchanged.")
    if c.new:
        listed = "; ".join(f"{_where(f)} ({_msg(f)})" for f in c.new)
        problems.append(f"The patch introduced new findings: {listed}. "
                        "Fix the vulnerability without introducing these.")
    for check in verification.checks:
        if not check.ok:
            problems.append(f"Check '{check.name}' failed: {check.detail}")
    return (not problems), " ".join(problems)


@dataclass
class Attempt:
    number: int
    patch_diff: str
    accepted: bool
    feedback: str
    record: dict             # the line written to the results log


@dataclass
class LoopResult:
    finding: Finding
    outcome: str             # ACCEPTED | ESCALATED
    attempts: list[Attempt] = field(default_factory=list)
    resumed: int = 0         # attempts taken from the log instead of re-run

    @property
    def iterations(self) -> int:
        return len(self.attempts)

    @property
    def accepted_diff(self) -> str | None:
        return next((a.patch_diff for a in self.attempts if a.accepted), None)

    def summary(self) -> str:
        lines = [f"{self.outcome} after {self.iterations} attempt(s)"
                 + (f" ({self.resumed} resumed from the log)" if self.resumed else "")]
        for a in self.attempts:
            status = a.record.get("status")
            lines.append(f"  #{a.number} {status}{' -> accepted' if a.accepted else ''}"
                         + (f": {a.feedback}" if a.feedback else ""))
        return "\n".join(lines)


def _rev(repo_root: Path, ref: str) -> str:
    import subprocess
    return subprocess.run(["git", "rev-parse", ref], cwd=repo_root, text=True,
                          capture_output=True, check=True).stdout.strip()


def repair(finding: Finding, client, repo_root: Path, *, reader: SourceReader | None = None,
           strategy: str = ZERO_SHOT, with_trace: bool = True, with_rag: bool = True,
           max_attempts: int = MAX_ATTEMPTS, base: str = "main", log: ResultLog | None = None,
           cli: str | None = None, checks: list[Check] | None = None,
           verify=verify_patch) -> LoopResult:
    """Run the reflexive loop on one finding under one experimental condition.

    ``verify`` is injectable for offline tests; in real runs it is ``verify_patch``.
    """
    repo_root = repo_root.resolve()
    reader = reader or SourceReader(repo_root)
    base_sha = _rev(repo_root, base)        # every attempt is verified on the same commit
    result = LoopResult(finding, ESCALATED)
    history: list[tuple[str, str]] = []

    for number in range(1, max_attempts + 1):
        key = RunKey(REMEDIATION, finding.label_key, strategy, with_trace, with_rag, number)
        if log is not None and log.done(key):          # resume: rebuild from the log
            rec = log.get(key)
            attempt = Attempt(number, rec.get("diff") or "", bool(rec.get("accepted")),
                              rec.get("feedback") or "", rec)
            result.resumed += 1
        else:
            patch = remediate(finding, client, reader, with_trace=with_trace, with_rag=with_rag,
                              strategy=strategy, history=history)
            verification = (verify(finding, patch.diff, repo_root, base_sha, cli=cli, checks=checks)
                            if patch.diff else None)
            accepted, feedback = judge(finding, patch, verification)
            rec = {**remediation_outcome(finding, patch, verification, base_sha),
                   "accepted": accepted, "feedback": feedback, "max_attempts": max_attempts}
            if log is not None:
                rec = log.append(key, rec)
            attempt = Attempt(number, patch.diff, accepted, feedback, rec)

        result.attempts.append(attempt)
        if attempt.accepted:
            result.outcome = ACCEPTED
            break
        history.append((attempt.patch_diff, attempt.feedback))
    return result


def oracle_checks(repo_root: Path) -> list[Check]:
    """All D9 oracles (4.8); each one returns None for findings it does not cover."""
    import oracle_juiceshop
    import oracle_secbench
    return oracle_juiceshop.checks(repo_root) + oracle_secbench.checks(repo_root)


def main() -> None:
    import argparse

    from rescan import codeql_version, find_codeql
    from results import environment
    from sarif_parser import parse_sarif
    from strategies import STRATEGIES

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sarif", type=Path, help="unified SARIF the target comes from")
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--strategy", default=ZERO_SHOT, choices=STRATEGIES)
    parser.add_argument("--no-trace", action="store_true")
    parser.add_argument("--no-rag", action="store_true")
    parser.add_argument("--max-attempts", type=int, default=MAX_ATTEMPTS)
    parser.add_argument("--base", default="main")
    parser.add_argument("--codeql", help="path to the CodeQL CLI (default: $CODEQL_CLI or PATH)")
    parser.add_argument("--log", type=Path, default=Path("results/dev/repair.jsonl"),
                        help="results log (default under results/, which git ignores)")
    parser.add_argument("--no-oracles", action="store_true",
                        help="CodeQL only: skip the D9 oracles (exploit / functional tests)")
    args = parser.parse_args()

    findings = parse_sarif(args.sarif, args.repo_root)
    hits = [f for f in findings if args.fingerprint in (f.fingerprint, f.label_key)]
    if not hits:   # accept an unambiguous prefix (reports show 8 characters)
        hits = list({f.label_key: f for f in findings
                     if f.label_key.startswith(args.fingerprint)}.values())
    if len(hits) != 1:
        raise SystemExit(f"{'no' if not hits else 'ambiguous'} finding for fingerprint {args.fingerprint}")
    target = hits[0]

    from groq_client import GroqClient

    cli = find_codeql(args.codeql)
    log = ResultLog(args.log, environment(args.repo_root, codeql_version(cli)))
    if log.repaired:
        print(f"(repaired {log.repaired} truncated line(s) in {args.log})")
    result = repair(target, GroqClient(), args.repo_root, strategy=args.strategy,
                    with_trace=not args.no_trace, with_rag=not args.no_rag,
                    max_attempts=args.max_attempts, base=args.base, log=log, cli=cli,
                    checks=None if args.no_oracles else oracle_checks(args.repo_root.resolve()))
    print(result.summary())
    if result.accepted_diff:
        print("\naccepted patch:\n" + result.accepted_diff)
    print(f"\nlog: {args.log}")


if __name__ == "__main__":
    main()
