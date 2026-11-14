"""Generate a remediation patch as a unified diff (Paso 3.6).

For a finding judged a true positive with CVSS >= 7.0, the agent proposes a fix.
The fix is produced as a **unified diff** (the roadmap's format), so Phase 4 can
apply it, rescan and match pre/post by fingerprint, and a human reviews the PR.

The prompt carries the same structured context as the triage (snippet, taint
trace, and — on by default here, since you cannot patch what you cannot see — the
enclosing function from the lightweight RAG). The three prompting strategies
(zero-shot / few-shot / CoT) are applied through ``strategies.decorate``, exactly
as in triage, so Phase 5 compares them on remediation too.

Generating the diff is this step's deliverable; applying it, rescanning and the
reflexive repair loop belong to Phase 4.

Usage (offline, print the prompt):
    python scripts/ai_agent/remediate.py <unified.sarif> --fingerprint <fp> --repo-root . [--strategy cot]
Usage (live, needs GROQ_API_KEY):
    GROQ_API_KEY=... python scripts/ai_agent/remediate.py <unified.sarif> --fingerprint <fp> --repo-root . --run
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sarif_parser import Finding, SourceReader
from strategies import STRATEGIES, ZERO_SHOT, decorate
from trace_context import render_context

SYSTEM_PROMPT = """\
You are a senior application-security engineer fixing a confirmed vulnerability. \
Produce the smallest change that removes the vulnerability without altering the \
code's legitimate behaviour. Prefer the established safe API (parameterised \
queries, validation/escaping at the boundary, safe path handling) over ad-hoc \
string checks.

Output the fix as a single unified diff (``diff -u`` format) inside one ```diff \
code block: a `--- a/<path>` and `+++ b/<path>` header with the finding's real \
file path, then `@@` hunks. Change only what the fix needs. Do not output anything \
except the diff block.\
"""

USER_TEMPLATE = "Vulnerability to fix:\n\n{context}\n\nReturn the unified diff."

# Fixed few-shot exemplar for remediation (used only by the few-shot strategy).
REMEDIATE_EXAMPLES: list[tuple[str, str]] = [
    (
        "Rule: js/sql-injection\nLocation: routes/item.ts:12\n"
        "Flagged code:\n  db.query('SELECT * FROM items WHERE id = ' + req.query.id)",
        "```diff\n--- a/routes/item.ts\n+++ b/routes/item.ts\n@@\n"
        "-  db.query('SELECT * FROM items WHERE id = ' + req.query.id)\n"
        "+  db.query('SELECT * FROM items WHERE id = ?', [req.query.id])\n```",
    ),
]

DIFF_FENCE_RE = re.compile(r"```(?:diff|patch)?\s*\n(.*?)```", re.DOTALL)
DIFF_LINE_RE = re.compile(r"(?m)^(--- |\+\+\+ |@@ )")


@dataclass
class Patch:
    """A proposed fix: the unified diff plus provenance for audit/experiments."""

    diff: str                 # the unified diff, empty if the model returned none
    explanation: str          # any prose outside the diff block
    strategy: str
    raw: str                  # the model's raw reply


def build_prompt(finding: Finding, reader: SourceReader | None = None,
                 with_trace: bool = True, with_rag: bool = True,
                 strategy: str = ZERO_SHOT) -> tuple[str, str]:
    """Return (system, user) for generating the patch of a finding."""
    context = render_context(finding, reader, with_trace=with_trace, with_rag=with_rag)
    system, user = SYSTEM_PROMPT, USER_TEMPLATE.format(context=context)
    return decorate(system, user, strategy, REMEDIATE_EXAMPLES)


def parse_patch(text: str, strategy: str) -> Patch:
    """Extract the unified diff from the model's reply, tolerant of prose/CoT."""
    match = DIFF_FENCE_RE.search(text)
    if match:
        diff = match.group(1).strip()
        explanation = (text[:match.start()] + text[match.end():]).strip()
    elif DIFF_LINE_RE.search(text):
        # No fence but diff-looking lines: take from the first diff marker on.
        start = DIFF_LINE_RE.search(text).start()
        diff, explanation = text[start:].strip(), text[:start].strip()
    else:
        diff, explanation = "", text.strip()
    return Patch(diff=diff, explanation=explanation, strategy=strategy, raw=text)


def remediate(finding: Finding, client, reader: SourceReader | None = None,
              with_trace: bool = True, with_rag: bool = True,
              strategy: str = ZERO_SHOT) -> Patch:
    """Build the prompt, ask the model, and parse the proposed diff."""
    system, user = build_prompt(finding, reader, with_trace=with_trace,
                                with_rag=with_rag, strategy=strategy)
    reply = client.complete(system, user)
    return parse_patch(reply.text, strategy=strategy)


def main() -> None:
    import argparse
    from pathlib import Path
    from sarif_parser import parse_sarif

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--no-trace", action="store_true")
    parser.add_argument("--no-rag", action="store_true")
    parser.add_argument("--strategy", default=ZERO_SHOT, choices=STRATEGIES)
    parser.add_argument("--run", action="store_true", help="call Groq for a live patch")
    args = parser.parse_args()

    findings = parse_sarif(args.sarif, args.repo_root)
    target = next((f for f in findings
                   if args.fingerprint in (f.fingerprint, f.label_key)), None)
    if target is None:
        raise SystemExit(f"no finding with fingerprint {args.fingerprint}")

    reader = SourceReader(args.repo_root)
    with_trace, with_rag = not args.no_trace, not args.no_rag
    system, user = build_prompt(target, reader, with_trace=with_trace,
                                with_rag=with_rag, strategy=args.strategy)

    if args.run:
        from groq_client import GroqClient
        patch = remediate(target, GroqClient(), reader, with_trace=with_trace,
                          with_rag=with_rag, strategy=args.strategy)
        print(f"# strategy={patch.strategy} rule={target.rule_id} file={target.file}\n")
        print(patch.diff or "(no diff returned)")
        if patch.explanation:
            print("\n# note:\n" + patch.explanation)
    else:
        print("===== SYSTEM =====\n" + system)
        print("\n===== USER =====\n" + user)


if __name__ == "__main__":
    main()
