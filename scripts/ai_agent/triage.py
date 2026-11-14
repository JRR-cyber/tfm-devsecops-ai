"""LLM triage decision: is a finding a true vulnerability or a false positive (Paso 3.4).

This is the core of the hybrid architecture. Given a finding and (optionally) its
taint trace as structured context, the LLM decides TP / FP / UNCERTAIN — the same
vocabulary as the ground-truth triage set (``benchmarks/triage/labels.csv``), so
its output can be scored against it in Phase 5.

The taint trace is a **separable** input (see ``trace_context.render_context``):
the same prompt is built with or without it, which is exactly the with/without-
trace control of Phase 5.3. The system prompt is identical in both conditions, so
the only thing that changes is whether the model gets to see the source->sink flow.

Prompting *strategy* (zero-shot / few-shot / CoT) and patch generation belong to
Paso 3.6; this module implements the baseline zero-shot triage decision.

Usage (offline, just print the prompt):
    python scripts/ai_agent/triage.py <unified.sarif> --fingerprint <fp> --repo-root . [--no-trace]
Usage (live decision, needs GROQ_API_KEY):
    GROQ_API_KEY=... python scripts/ai_agent/triage.py <unified.sarif> --fingerprint <fp> --repo-root . --run
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from sarif_parser import Finding, SourceReader
from strategies import STRATEGIES, ZERO_SHOT, decorate
from trace_context import render_context

VERDICTS = ("TP", "FP", "UNCERTAIN")

# Fixed few-shot exemplars for the triage task (used only by the few-shot
# strategy). Kept short and generic so they teach the output shape and the
# guard-aware reasoning without leaking the benchmark's own cases.
TRIAGE_EXAMPLES: list[tuple[str, str]] = [
    (
        "Rule: js/sql-injection\nLocation: routes/item.ts:12\n"
        "Flagged code:\n  db.query('SELECT * FROM items WHERE id = ' + req.query.id)\n"
        "Taint trace (source -> sink), 2 steps:\n  1. [source] req.query.id\n  2. [sink] db.query(...)",
        '{"verdict": "TP", "confidence": 0.95, "rationale": "req.query.id is concatenated '
        'into the SQL string with no parameterisation or validation, so it is injectable."}',
    ),
    (
        "Rule: js/path-injection\nLocation: routes/file.ts:20\n"
        "Flagged code:\n  res.sendFile(path.resolve('public/', name))\n"
        "Surrounding code:\n  if (name.includes('/')) return res.status(400).end()\n"
        "  res.sendFile(path.resolve('public/', name))",
        '{"verdict": "FP", "confidence": 0.9, "rationale": "A guard rejects any name '
        "containing '/', so '../' cannot reach the sink and traversal is blocked.\"}",
    ),
]

SYSTEM_PROMPT = """\
You are a security triage analyst reviewing static-analysis findings for a code \
review. For each finding you decide whether it is a real, exploitable \
vulnerability or a false positive.

Definitions:
- TP (true positive): the reported vulnerability is real and exploitable as shown.
- FP (false positive): it is not exploitable here, e.g. the attacker-controlled \
input is validated, sanitised or neutralised before it reaches the dangerous \
operation, or the operation is not actually dangerous in this context.
- UNCERTAIN: the information given is not enough to decide.

If a taint trace is provided, use it: check whether the tainted value really \
reaches the sink without being sanitised along the way. If no trace is provided, \
reason from the code and message alone. Judge only what the evidence supports; do \
not assume a guard that is not shown, and do not assume exploitability you cannot \
justify.

Respond with a single JSON object and nothing else:
{"verdict": "TP" | "FP" | "UNCERTAIN", "confidence": <float 0-1>, "rationale": "<one or two sentences>"}\
"""

USER_TEMPLATE = "Finding to triage:\n\n{context}\n\nReturn your JSON decision."


@dataclass
class TriageVerdict:
    """The model's triage decision, aligned with labels.csv's vocabulary."""

    verdict: str              # TP | FP | UNCERTAIN
    confidence: float | None
    rationale: str
    with_trace: bool          # which condition produced it (for Phase 5.3)
    raw: str                  # the model's raw reply, kept for audit


def build_prompt(finding: Finding, reader: SourceReader | None = None,
                 with_trace: bool = True, with_rag: bool = False,
                 strategy: str = ZERO_SHOT) -> tuple[str, str]:
    """Return (system, user) for the triage decision on a finding."""
    context = render_context(finding, reader, with_trace=with_trace, with_rag=with_rag)
    system, user = SYSTEM_PROMPT, USER_TEMPLATE.format(context=context)
    return decorate(system, user, strategy, TRIAGE_EXAMPLES)


def parse_verdict(text: str, with_trace: bool) -> TriageVerdict:
    """Extract the verdict from the model's reply, tolerant of extra prose."""
    verdict, confidence, rationale = "UNCERTAIN", None, ""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            obj = json.loads(match.group(0))
            raw_verdict = str(obj.get("verdict", "")).upper().strip()
            if raw_verdict in VERDICTS:
                verdict = raw_verdict
            if obj.get("confidence") is not None:
                confidence = float(obj["confidence"])
            rationale = str(obj.get("rationale", "")).strip()
        except (ValueError, TypeError):
            pass
    if not rationale:
        # No parseable JSON: fall back to the first verdict token mentioned.
        token = re.search(r"\b(TP|FP|UNCERTAIN)\b", text.upper())
        if token:
            verdict = token.group(1)
        rationale = text.strip()
    return TriageVerdict(verdict=verdict, confidence=confidence,
                         rationale=rationale, with_trace=with_trace, raw=text)


def decide(finding: Finding, client, reader: SourceReader | None = None,
           with_trace: bool = True, with_rag: bool = False,
           strategy: str = ZERO_SHOT) -> TriageVerdict:
    """Build the prompt, ask the model, and parse its triage verdict.

    ``client`` is a GroqClient (or anything with ``.complete(system, user)``).
    """
    system, user = build_prompt(finding, reader, with_trace=with_trace,
                                with_rag=with_rag, strategy=strategy)
    reply = client.complete(system, user)
    return parse_verdict(reply.text, with_trace=with_trace)


def main() -> None:
    import argparse
    from pathlib import Path
    from sarif_parser import parse_sarif

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--fingerprint", required=True, help="tfmContextHash/v1 of the finding")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--no-trace", action="store_true", help="blind condition (omit the trace)")
    parser.add_argument("--rag", action="store_true", help="add the lightweight RAG context (3.5)")
    parser.add_argument("--strategy", default=ZERO_SHOT, choices=STRATEGIES,
                        help="prompting strategy (3.6)")
    parser.add_argument("--run", action="store_true", help="call Groq for a live decision")
    args = parser.parse_args()

    findings = parse_sarif(args.sarif, args.repo_root)
    # Accept the full fingerprint (digest:occurrence) or the bare digest that
    # benchmarks/triage/labels.csv uses.
    target = next((f for f in findings
                   if args.fingerprint in (f.fingerprint, f.label_key)), None)
    if target is None:
        raise SystemExit(f"no finding with fingerprint {args.fingerprint}")

    reader = SourceReader(args.repo_root)
    with_trace = not args.no_trace
    system, user = build_prompt(target, reader, with_trace=with_trace,
                                with_rag=args.rag, strategy=args.strategy)

    if args.run:
        from groq_client import GroqClient
        verdict = decide(target, GroqClient(), reader, with_trace=with_trace,
                         with_rag=args.rag, strategy=args.strategy)
        print(json.dumps({
            "fingerprint": target.fingerprint, "rule": target.rule_id,
            "with_trace": verdict.with_trace, "with_rag": args.rag, "strategy": args.strategy,
            "verdict": verdict.verdict, "confidence": verdict.confidence,
            "rationale": verdict.rationale,
        }, indent=1, ensure_ascii=False))
    else:
        print("===== SYSTEM =====\n" + system)
        print("\n===== USER =====\n" + user)


if __name__ == "__main__":
    main()
