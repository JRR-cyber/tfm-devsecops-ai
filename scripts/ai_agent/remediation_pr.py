"""Apply a proposed patch and prepare the remediation PR (Paso 3.7).

Assistive posture: the agent applies the fix on a ``fix/ai-remediation-...``
branch and prepares a pull request; a human approves every merge. The agent never
merges, and never touches ``main``.

Applying the diff: the model emits unified diffs with empty ``@@`` headers (no
line numbers), so ``git apply`` cannot place them. Instead the patch is applied
**by content**: each hunk's old block (its context + ``-`` lines) is located
verbatim in the file and replaced by the new block (context + ``+`` lines). If the
old block is not found, the apply fails and says so — a real outcome that the
Phase 4 reflexive loop will act on, never a silent guess.

Note on the benchmark: this deliberately "fixes" intentionally-vulnerable
benchmark code. That is the remediation exercise, so the branch is an isolated
experimental artifact that is never merged to main and does not run Juice Shop's
RSN / codefixes sync (those govern real contributions, not throwaway fix branches).

Usage (dry-run, apply in memory and show the result — default, touches nothing):
    python scripts/ai_agent/remediation_pr.py <unified.sarif> --fingerprint <fp> \
        --patch-file patch.diff --repo-root .
Add ``--commit`` to create the branch and commit locally; add ``--open`` to also
push and open the PR with gh (outward-facing — only with explicit approval).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from sarif_parser import Finding


@dataclass
class ApplyResult:
    ok: bool
    detail: str
    changed: dict[str, str] = field(default_factory=dict)   # path -> new content


Op = tuple[str, str]          # (" " context | "-" removed | "+" added, line text)


def parse_ops(diff: str, blank_as_context: bool = False) -> tuple[str | None, list[list[Op]]]:
    """Return (file path, hunks), each hunk its lines as (op, text) in diff order.

    ``blank_as_context`` reads an empty line inside a hunk as a blank context line
    (models often drop the leading space of blank context lines).
    """
    path: str | None = None
    hunks: list[list[Op]] = []
    ops: list[Op] = []
    in_hunk = False

    def flush() -> None:
        if in_hunk and ops:
            hunks.append(ops)

    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = re.sub(r"^b/", "", line[4:].strip())
        elif line.startswith("--- "):
            continue
        elif line.startswith("@@"):
            flush()
            ops, in_hunk = [], True
        elif in_hunk:
            if line[:1] in ("-", "+", " "):
                ops.append((line[:1], line[1:]))
            elif blank_as_context and line == "":
                ops.append((" ", ""))
    flush()
    if blank_as_context:      # trailing blank context lines are an artefact of the reply
        for h in hunks:
            while h and h[-1] == (" ", ""):
                h.pop()
    return path, [h for h in hunks if h]


def _blocks(ops: list[Op]) -> tuple[str, str]:
    return ("\n".join(t for o, t in ops if o != "+"), "\n".join(t for o, t in ops if o != "-"))


def parse_diff(diff: str, blank_as_context: bool = False) -> tuple[str | None, list[tuple[str, str]]]:
    """Return (file path, [(old_block, new_block), ...]) from a unified diff."""
    path, hunks = parse_ops(diff, blank_as_context)
    return path, [_blocks(h) for h in hunks]


_LINENO = re.compile(r"^\d+: ?")
_LEAD = re.compile(r"^[ \t]*")
EXACT, LINENO, WHITESPACE = "exact", "lineno", "whitespace"


def _strip_linenos(ops: list[Op]) -> list[Op] | None:
    """Drop the ``NN: `` prefixes the prompt shows (``context_rag``) and the model
    sometimes copies; only if every non-blank old/context line carries one."""
    if not all(_LINENO.match(t) for o, t in ops if o != "+" and t.strip()):
        return None
    return [(o, _LINENO.sub("", t, count=1)) for o, t in ops]


def _width(lead: str, unit: int) -> int:
    return lead.count(" ") + lead.count("\t") * unit


def _indent_unit(leads: list[str]) -> int:
    """Indentation step of a block (smallest positive difference), default 2."""
    widths = sorted({_width(l, 4) for l in leads})
    steps = [b - a for a, b in zip(widths, widths[1:]) if b > a]
    return min(steps) if steps else 2


def _match_ignoring_indent(text: str, ops: list[Op]) -> tuple[str | None, str]:
    """Apply a hunk comparing lines without leading/trailing whitespace.

    The old lines (context + removed) must match exactly one place in the file
    (else no change and the reason). Context lines keep the file's own text. Added
    lines are re-indented in the file's style: the model's indentation shifted by
    the most common model -> file offset of the aligned old lines (in indentation
    levels, and as tabs when the file indents with tabs), so a single odd line
    (e.g. a comment at column 0) does not skew the rest.
    """
    from collections import Counter

    file_lines = text.split("\n")
    old = [t for o, t in ops if o != "+"]
    key = lambda s: s.strip()
    n = len(old)
    hits = [i for i in range(len(file_lines) - n + 1)
            if all(key(file_lines[i + k]) == key(old[k]) for k in range(n))]
    if len(hits) != 1:
        return None, "not found" if not hits else f"ambiguous ({len(hits)} places)"
    start = hits[0]
    # model lead -> file lead, from the aligned old lines (blank lines carry no indent)
    pairs = [(_LEAD.match(t).group(), _LEAD.match(file_lines[start + k]).group())
             for k, t in enumerate(old) if t.strip()]
    if not pairs:
        return None, "old block is blank"
    unit_m = _indent_unit([m for m, _ in pairs] +
                          [_LEAD.match(t).group() for o, t in ops if o == "+" and t.strip()])
    file_tabs = any("\t" in f for _, f in pairs)
    if file_tabs:     # offsets in indentation levels (model unit -> one tab)
        offset = Counter(f.count("\t") - round(_width(m, unit_m) / unit_m)
                         for m, f in pairs).most_common(1)[0][0]
    else:             # offsets in spaces
        offset = Counter(len(f) - _width(m, unit_m) for m, f in pairs).most_common(1)[0][0]
    out, k = [], 0                                   # k: index into the matched old lines
    for o, t in ops:
        if o == " ":                                 # context: the file's own line
            out.append(file_lines[start + k])
            k += 1
        elif o == "-":
            k += 1
        elif not t.strip():
            out.append("")
        else:
            w = _width(_LEAD.match(t).group(), unit_m)
            out.append(("\t" * max(0, round(w / unit_m) + offset) if file_tabs
                        else " " * max(0, w + offset)) + t.strip())
    return "\n".join(file_lines[:start] + out + file_lines[start + n:]), ""


def apply_by_content(diff: str, repo_root: Path) -> ApplyResult:
    """Apply each hunk by locating its old block and replacing it.

    Each hunk is tried, in order, (1) verbatim; (2) reading blank lines without the
    leading space as blank context; (3) without the ``NN: `` line-number prefixes of
    the prompt, if every old line carries one; (4) comparing lines without their
    indentation, if the old block then matches exactly **one** place (the added
    lines are re-indented in the file's style). Content is never fuzzed: a changed
    token, a skipped line or reordered lines still fail. The detail says which mode
    each hunk needed (``[mode=...]``), so the 4.10 / Phase 5 logs can report how
    many patches relied on the tolerance.
    """
    # The remediation prompt asks for a single-file diff; a multi-file one would
    # be parsed under one path and misapplied, so reject it explicitly.
    if len(re.findall(r"^\+\+\+ ", diff, re.MULTILINE)) > 1:
        return ApplyResult(False, "multi-file diff: only single-file patches are supported")
    path, hunks = parse_diff(diff)
    if not path:
        return ApplyResult(False, "no file path in diff")
    if not hunks:
        return ApplyResult(False, "no hunks in diff")

    target = (repo_root / path).resolve()
    if not (target.is_file() and target.is_relative_to(repo_root.resolve())):
        return ApplyResult(False, f"target not in repo: {path}")

    text = target.read_text(encoding="utf-8")
    _, loose = parse_ops(diff, blank_as_context=True)
    modes = []
    for i, (old_block, new_block) in enumerate(hunks):
        if not old_block:                            # pure addition at the end
            text += new_block
            modes.append(EXACT)
            continue
        if old_block in text:
            text = text.replace(old_block, new_block, 1)
            modes.append(EXACT)
            continue
        ops = loose[i] if i < len(loose) else []
        old_l, new_l = _blocks(ops)
        if ops and old_l in text:                    # only blank context lines differed
            text = text.replace(old_l, new_l, 1)
            modes.append(WHITESPACE)
            continue
        stripped = _strip_linenos(ops) if ops else None
        if stripped is not None:
            old_s, new_s = _blocks(stripped)
            if old_s in text:
                text = text.replace(old_s, new_s, 1)
                modes.append(LINENO)
                continue
        replaced, why = _match_ignoring_indent(text, stripped or ops) if ops else (None, "empty")
        if replaced is None:
            return ApplyResult(False, f"old block of hunk {i + 1} not found in {path} "
                                      f"(also ignoring indentation: {why})")
        text = replaced
        modes.append(f"{LINENO}+{WHITESPACE}" if stripped is not None else WHITESPACE)
    mode = "exact" if all(m == EXACT for m in modes) else ",".join(modes)
    return ApplyResult(True, f"applied {len(hunks)} hunk(s) to {path} [mode={mode}]", {path: text})


def branch_name(finding: Finding) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", finding.rule_id.lower()).strip("-")
    return f"fix/ai-remediation-{slug}-{finding.label_key[:8]}"


def pr_body(finding: Finding, diff: str, verdict: str | None = None) -> str:
    cwes = ", ".join(finding.cwes) if finding.cwes else "n/a"
    lines = [
        "## Remediación asistida por IA (revisión humana obligatoria)",
        "",
        f"- **Regla**: `{finding.rule_id}` ({cwes})",
        f"- **Ubicación**: `{finding.file}:{finding.start_line}`",
        f"- **Fingerprint**: `{finding.label_key}`",
    ]
    if finding.security_severity is not None:
        lines.append(f"- **CVSS**: {finding.security_severity}")
    if verdict:
        lines.append(f"- **Triaje del agente**: {verdict}")
    lines += [
        "",
        "Parche propuesto por el agente (modelo único, ver `scripts/ai_agent/README.md`).",
        "**No fusionar en `main`**: rama de artefacto experimental sobre código del",
        "benchmark, intencionadamente vulnerable. Requiere aprobación humana.",
        "",
        "```diff",
        diff.strip(),
        "```",
    ]
    return "\n".join(lines)


def _git(args: list[str], repo_root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo_root, text=True, capture_output=True)


def prepare_pr(finding: Finding, diff: str, repo_root: Path, verdict: str | None = None,
               commit: bool = False, open_pr: bool = False, base: str = "main",
               body: str | None = None, labels: list[str] | None = None,
               title: str | None = None, draft: bool = False) -> str:
    """Apply the patch and (optionally) create the branch/commit/PR.

    Default (commit=False): dry-run — apply in memory and return a report without
    touching the repo. commit=True creates the fix branch from ``base`` (the branch
    the pipeline scanned) in an isolated git worktree (Paso 4.1) and commits there,
    so a PR against ``base`` contains only the fix and the user's checkout is never
    touched; open_pr=True also pushes and opens the PR with gh (outward-facing).
    The worktree directory is always removed; the branch is kept only on success.

    ``body``/``labels``/``title`` (4.9, ``publish.decide``) override the default PR
    text and add ``--label`` flags.
    """
    branch = branch_name(finding)
    body = body or pr_body(finding, diff, verdict)
    title = title or f"fix(ai): {finding.rule_id}"
    label_args = [x for l in labels or [] for x in ("--label", l)]
    if not commit:
        result = apply_by_content(diff, repo_root)
        report = [f"branch: {branch} (from {base})", result.detail]
        if not result.ok:
            return "\n".join(["APPLY FAILED", *report])
        if labels:
            report.append(f"labels: {', '.join(labels)}  |  title: {title}")
        preview = next(iter(result.changed.values()))
        report.append("\n--- dry-run: resulting file (first 40 lines) ---")
        report += preview.splitlines()[:40]
        return "\n".join(report)

    from worktree import WorktreeError, commit_all, create, remove

    try:
        wt = create(repo_root, branch, base)
    except WorktreeError as exc:
        return f"could not create {branch} from {base}: {exc}"
    ok = False
    try:
        # Apply against the worktree (= base), not the user's checkout.
        result = apply_by_content(diff, wt.path)
        report = [f"branch: {branch} (from {base}, worktree {wt.path})", result.detail]
        if not result.ok:
            return "\n".join(["APPLY FAILED (branch removed)", *report])
        for path, content in result.changed.items():
            (wt.path / path).write_text(content, encoding="utf-8")
        msg = (f"fix(ai): {finding.rule_id} en {finding.file}\n\n"
               "Parche propuesto por el agente. Revisión humana obligatoria.")
        try:
            sha = commit_all(wt, list(result.changed), msg)
        except WorktreeError as exc:
            return "\n".join(["COMMIT FAILED (branch removed)", *report, str(exc)])
        ok = True
        report.append(f"committed on {branch}: {sha[:7]}")

        if open_pr:
            push = _git(["push", "-u", "origin", branch], repo_root)
            if push.returncode != 0:
                report.append(f"PUSH FAILED (branch kept locally): {push.stderr.strip()[-300:]}")
                return "\n".join(report)
            # The body carries emojis and accents: send it as UTF-8 whatever the
            # console code page is (cp1252 on Windows broke the first live demo).
            pr = subprocess.run(
                ["gh", "pr", "create", "--base", base, "--head", branch,
                 "--title", title, "--body-file", "-", *label_args,
                 *(["--draft"] if draft else [])],
                cwd=repo_root, input=body, text=True, encoding="utf-8", capture_output=True)
            if pr.returncode != 0:
                report.append(f"PR NOT CREATED (branch {branch} is pushed; retry with gh pr create "
                              f"--head {branch}): {pr.stderr.strip()[-300:]}")
            else:
                report.append(pr.stdout.strip())
        else:
            report.append(f"(local only; open with: gh pr create --base {base} --head {branch})")
        return "\n".join(report)
    finally:
        remove(repo_root, wt, delete_branch=not ok)


def main() -> None:
    import argparse
    from sarif_parser import parse_sarif

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--patch-file", type=Path, required=True, help="unified diff to apply")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--base", default="main", help="branch the fix starts from and the PR targets")
    parser.add_argument("--commit", action="store_true", help="create branch + commit (local)")
    parser.add_argument("--open", action="store_true", help="also push and open the PR (gh)")
    args = parser.parse_args()

    findings = parse_sarif(args.sarif, args.repo_root)
    target = next((f for f in findings
                   if args.fingerprint in (f.fingerprint, f.label_key)), None)
    if target is None:
        raise SystemExit(f"no finding with fingerprint {args.fingerprint}")

    diff = args.patch_file.read_text(encoding="utf-8")
    print(prepare_pr(target, diff, args.repo_root, commit=args.commit, open_pr=args.open,
                     base=args.base))


if __name__ == "__main__":
    main()
