"""The three prompting strategies the experiments compare (Paso 3.6).

These are the independent variable of Phase 5: zero-shot / few-shot / CoT. They
are prompt *transformations*, applied the same way to any task (triage or
remediation), so the comparison is clean — only the strategy changes:

- **zero-shot**: ask directly, no examples.
- **few-shot**: prepend a few worked examples (task-specific, passed in) before
  the real input.
- **CoT (chain-of-thought)**: ask the model to reason step by step before giving
  the answer in the required format.

The strategy never touches the finding's context (snippet, trace, RAG); those
stay the controlled constants. ``decorate`` returns the (system, user) pair to
send.
"""

from __future__ import annotations

ZERO_SHOT = "zero-shot"
FEW_SHOT = "few-shot"
COT = "cot"
STRATEGIES = (ZERO_SHOT, FEW_SHOT, COT)

COT_INSTRUCTION = (
    "\n\nBefore answering, reason step by step about the evidence: identify the "
    "source, whether anything sanitises or guards the value before the sink, and "
    "whether the result is exploitable. Then give your final answer in the exact "
    "format requested above, as the last thing you output."
)


def decorate(system: str, user: str, strategy: str,
             examples: list[tuple[str, str]] | None = None) -> tuple[str, str]:
    """Apply a prompting strategy to a base (system, user) prompt.

    ``examples`` is a list of (input, ideal_answer) pairs used only by few-shot.
    """
    if strategy not in STRATEGIES:
        raise ValueError(f"unknown strategy {strategy!r}; use one of {STRATEGIES}")

    if strategy == COT:
        return system + COT_INSTRUCTION, user

    if strategy == FEW_SHOT:
        blocks = []
        for i, (example_in, example_out) in enumerate(examples or [], 1):
            blocks.append(f"Example {i}:\n{example_in}\n\nExpected answer:\n{example_out}")
        if blocks:
            user = "\n\n".join(blocks) + "\n\n---\n\nNow the real case:\n\n" + user
        return system, user

    return system, user   # zero-shot
