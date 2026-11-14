"""Lightweight RAG: extra code context for the vulnerable file (Paso 3.5).

The taint trace (3.4) lists the source->sink flow, but mitigations often sit
*outside* that flow — a guard a couple of lines before the sink, a validation
helper called elsewhere. The triage smoke test showed exactly this: keyServer.ts
is a false positive because of the ``if (!file.includes('/'))`` guard on the line
above the sink, which the trace and the one-line snippet do not show, so the model
wrongly calls it a true positive.

This module gathers that surrounding context, statically and cheaply (no
embeddings, no vector store — "lightweight" RAG):

- the file's imports / requires,
- the function that encloses the sink (so the guard above it is visible),
- sibling top-level functions the enclosing one calls by name.

Like the trace, the RAG block is a **separable** input: ``render_context`` takes
``with_rag``, so Phase 5 can compare trace / RAG / both independently.
"""

from __future__ import annotations

import re

from sarif_parser import Finding, SourceReader

IMPORT_RE = re.compile(r"^\s*(import\b|export\s+.*\bfrom\b|const\s+.*=\s*require\(|.*\brequire\()")
NAME_RE = re.compile(r"\b(?:function|const|let|var)\s+([A-Za-z_$][\w$]*)")
MAX_BLOCK_LINES = 80
MAX_RELATED = 2


def file_imports(lines: list[str]) -> list[str]:
    """Top-of-file import / require lines (scan stops at the first real code)."""
    out: list[str] = []
    for line in lines:
        if IMPORT_RE.match(line):
            out.append(line.rstrip())
        elif line.strip() and not line.lstrip().startswith(("//", "/*", "*", "import", "export")):
            # first substantive non-import line: imports are done
            if out:
                break
    return out


def _top_level_blocks(lines: list[str]) -> list[tuple[int, int]]:
    """(start, end) line indices of every brace block that opens at depth 0.

    Naive brace counting (ignores braces in strings/comments); good enough for a
    lightweight heuristic on the small handler files this targets.
    """
    ranges, depth, start = [], 0, None
    for i, line in enumerate(lines):
        for ch in line:
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}" and depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    ranges.append((start, i))
                    start = None
    return ranges


def enclosing_function(lines: list[str], sink_line: int) -> tuple[int, int] | None:
    """(start, end) 1-based line range of the top-level block enclosing the sink."""
    sink_idx = sink_line - 1
    for start, end in _top_level_blocks(lines):
        if start <= sink_idx <= end:
            return start + 1, end + 1
    return None


def _block_name(lines: list[str], start: int) -> str | None:
    match = NAME_RE.search(lines[start - 1])
    return match.group(1) if match else None


def related_functions(lines: list[str], enclosing: tuple[int, int]) -> list[tuple[str, int, int]]:
    """Sibling top-level functions whose name the enclosing function calls."""
    body = "\n".join(lines[enclosing[0] - 1:enclosing[1]])
    out: list[tuple[str, int, int]] = []
    for start, end in _top_level_blocks(lines):
        rng = (start + 1, end + 1)
        if rng == enclosing:
            continue
        name = _block_name(lines, rng[0])
        if name and re.search(rf"\b{re.escape(name)}\s*\(", body):
            out.append((name, *rng))
        if len(out) >= MAX_RELATED:
            break
    return out


def _clip(lines: list[str], start: int, end: int, around: int) -> str:
    """The code for a 1-based line range, clipped to MAX_BLOCK_LINES around a line."""
    if end - start + 1 > MAX_BLOCK_LINES:
        half = MAX_BLOCK_LINES // 2
        start, end = max(start, around - half), min(end, around + half)
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))


def render_rag(finding: Finding, reader: SourceReader | None) -> str:
    """Imports + enclosing function + related functions of the vulnerable file."""
    if reader is None:
        return ""
    lines = reader.lines(finding.file)
    if not lines:
        return ""

    parts: list[str] = []
    imports = file_imports(lines)
    if imports:
        parts.append("Imports:\n" + "\n".join(imports))

    enclosing = enclosing_function(lines, finding.start_line)
    if enclosing:
        parts.append(f"Enclosing function ({finding.file}:{enclosing[0]}-{enclosing[1]}):\n"
                     + _clip(lines, *enclosing, around=finding.start_line))
        for name, start, end in related_functions(lines, enclosing):
            parts.append(f"Related function {name} ({finding.file}:{start}-{end}):\n"
                         + _clip(lines, start, end, around=start))

    return "\n\n".join(parts)
