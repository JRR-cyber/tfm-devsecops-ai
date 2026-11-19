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

import re

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


_LINK = re.compile(r"\[([^\]]+)\]\((\d+)\)")
# A link that names where tainted data comes from ("depends on [library input](2)",
# "injected from [...]", "copied from [source](1)", "on a [user-provided value]")
# is a taint *source*: data-flow information that belongs to the trace block.
_SOURCE_BEFORE = re.compile(r"(?:depends on|injected from|copied from|from|on an?|but an?|"
                            r"an unsanitized)\s*$", re.IGNORECASE)
_SOURCE_LABEL = re.compile(r"input|user-provided|user controlled|untrusted|argument|"
                           r"environment", re.IGNORECASE)


def render_references(finding: Finding, reader: SourceReader | None = None) -> str:
    """Code of the locations the message links to, minus those on the taint trace.

    CodeQL messages name locations as links, e.g. "This [regular expression](1)
    that depends on [library input](2) ...". For ReDoS the regex is often defined
    far from the sink (a module-level constant), so without this the model judges
    a regex it never saw (4.10 rehearsal: fresh, tough-cookie). Data-flow
    information is left out: locations that are steps of a code flow and links that
    name a taint source. They belong to the trace block, so the no-trace condition
    of 5.3 does not get them through here.
    """
    on_trace = {(s.file, s.start_line) for flow in finding.code_flows for s in flow}
    out, seen = [], set()
    for m in _LINK.finditer(finding.message):
        label, num = m.group(1), m.group(2)
        loc = finding.related.get(int(num))
        if (loc is None or (loc.file, loc.start_line) in on_trace | seen
                or _SOURCE_BEFORE.search(finding.message[:m.start()])
                or _SOURCE_LABEL.search(label)):
            continue
        seen.add((loc.file, loc.start_line))
        code = reader.snippet(loc.file, loc.start_line, loc.start_line) if reader else None
        out.append(f"  ({num}) {label}: {loc.file}:{loc.start_line}"
                   + (f"\n        {code.strip()}" if code else ""))
    return ("Locations referenced by the message:\n" + "\n".join(out)) if out else ""


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
    refs = render_references(finding, reader)
    if refs:
        parts.append(refs)
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
