"""Render a finding (and its taint trace) as structured prompt context (Paso 3.4).

The taint trace is the hybrid architecture's distinctive input: CodeQL's
``codeFlows`` describe how tainted data goes from a *source* (user input) through
intermediate steps to a *sink* (the dangerous operation). This module turns that
into readable text the LLM can reason over, annotating each step with the actual
line of code it touches.

The trace is rendered as a **separable block** on purpose: `render_context` takes
``with_trace``. The "blind" memorisation control of Phase 5.3 reuses the exact
same context with ``with_trace=False``, so the only variable that changes between
the two conditions is the presence of the trace — nothing else.
"""

from __future__ import annotations

from sarif_parser import Finding, SourceReader


def render_trace(finding: Finding, reader: SourceReader | None = None) -> str:
    """The longest taint trace as a numbered source -> sink list, code per step."""
    if not finding.code_flows:
        return ""
    flow = max(finding.code_flows, key=len)
    out = [f"Taint trace (source -> sink), {len(flow)} steps:"]
    last = len(flow) - 1
    for i, step in enumerate(flow):
        tag = " [source]" if i == 0 else (" [sink]" if i == last else "")
        out.append(f"  {i + 1}.{tag} {step.file}:{step.start_line}  {step.message}".rstrip())
        code = reader.snippet(step.file, step.start_line, step.start_line) if reader else None
        if code:
            out.append(f"        {code.strip()}")
    return "\n".join(out)


def render_context(finding: Finding, reader: SourceReader | None = None,
                   with_trace: bool = True, with_rag: bool = False) -> str:
    """Structured description of a finding for the triage prompt.

    ``with_trace`` and ``with_rag`` toggle the two optional context blocks (the
    taint trace and the lightweight RAG). Everything else is fixed, so turning
    either off changes only that block — the separable inputs Phase 5 compares
    (``with_trace=False`` is the blind control of 5.3).
    """
    parts = [
        f"Rule: {finding.rule_id}",
        f"CWE: {', '.join(finding.cwes) if finding.cwes else 'n/a'}",
        f"Location: {finding.file}:{finding.start_line}",
        f"Message: {finding.message}",
    ]
    snippet = finding.snippet
    if snippet is None and reader is not None:
        snippet = reader.snippet(finding.file, finding.start_line, finding.end_line)
    if snippet:
        parts.append(f"Flagged code:\n{snippet}")
    if with_trace:
        trace = render_trace(finding, reader)
        if trace:
            parts.append(trace)
    if with_rag:
        from context_rag import render_rag
        rag = render_rag(finding, reader)
        if rag:
            parts.append("Surrounding code (imports and related functions):\n" + rag)
    return "\n\n".join(parts)
