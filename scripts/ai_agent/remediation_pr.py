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


def parse_diff(diff: str) -> tuple[str | None, list[tuple[str, str]]]:
    """Return (file path, [(old_block, new_block), ...]) from a unified diff."""
    path: str | None = None
    hunks: list[tuple[str, str]] = []
    old: list[str] = []
    new: list[str] = []
    in_hunk = False

    def flush() -> None:
        if in_hunk and (old or new):
            hunks.append(("\n".join(old), "\n".join(new)))

    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = re.sub(r"^b/", "", line[4:].strip())
        elif line.startswith("--- "):
            continue
        elif line.startswith("@@"):
            flush()
            old, new, in_hunk = [], [], True
        elif in_hunk:
            if line.startswith("-"):
                old.append(line[1:])
            elif line.startswith("+"):
                new.append(line[1:])
            elif line.startswith(" "):
                old.append(line[1:])
                new.append(line[1:])
    flush()
    return path, hunks


def apply_by_content(diff: str, repo_root: Path) -> ApplyResult:
    """Apply each hunk by locating its old block verbatim and replacing it."""
    path, hunks = parse_diff(diff)
    if not path:
        return ApplyResult(False, "no file path in diff")
    if not hunks:
        return ApplyResult(False, "no hunks in diff")

    target = (repo_root / path).resolve()
    if not (target.is_file() and target.is_relative_to(repo_root.resolve())):
        return ApplyResult(False, f"target not in repo: {path}")

    text = target.read_text(encoding="utf-8")
    for old_block, new_block in hunks:
        if old_block and old_block not in text:
            return ApplyResult(False, f"old block not found verbatim in {path}")
        text = text.replace(old_block, new_block, 1) if old_block else text + new_block
    return ApplyResult(True, f"applied {len(hunks)} hunk(s) to {path}", {path: text})


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
               commit: bool = False, open_pr: bool = False, base: str = "main") -> str:
    """Apply the patch and (optionally) create the branch/commit/PR.

    Default (commit=False): dry-run — apply in memory and return a report without
    touching the repo. commit=True creates the fix branch from ``base`` (the branch
    the pipeline scanned) and commits there, so a PR against ``base`` contains only
    the fix; open_pr=True also pushes and opens the PR with gh (outward-facing).
    The repo is always returned to the branch it was on.
    """
    branch = branch_name(finding)
    if not commit:
        result = apply_by_content(diff, repo_root)
        report = [f"branch: {branch} (from {base})", result.detail]
        if not result.ok:
            return "\n".join(["APPLY FAILED", *report])
        preview = next(iter(result.changed.values()))
        report.append("\n--- dry-run: resulting file (first 40 lines) ---")
        report += preview.splitlines()[:40]
        return "\n".join(report)

    original = _git(["rev-parse", "--abbrev-ref", "HEAD"], repo_root).stdout.strip()
    created = _git(["switch", "-c", branch, base], repo_root)
    if created.returncode != 0:
        return f"could not create {branch} from {base}: {created.stderr.strip()}"
    try:
        result = apply_by_content(diff, repo_root)
        report = [f"branch: {branch} (from {base})", result.detail]
        if not result.ok:
            _git(["switch", original], repo_root)
            _git(["branch", "-D", branch], repo_root)
            return "\n".join(["APPLY FAILED (branch removed)", *report])
        for path, content in result.changed.items():
            (repo_root / path).write_text(content, encoding="utf-8")
            _git(["add", path], repo_root)
        msg = (f"fix(ai): {finding.rule_id} en {finding.file}\n\n"
               "Parche propuesto por el agente. Revisión humana obligatoria.")
        commit_res = _git(["commit", "-m", msg], repo_root)
        report.append(f"committed on {branch}: {commit_res.returncode == 0}")

        if open_pr:
            _git(["push", "-u", "origin", branch], repo_root)
            pr = subprocess.run(
                ["gh", "pr", "create", "--base", base, "--head", branch,
                 "--title", f"fix(ai): {finding.rule_id}", "--body", pr_body(finding, diff, verdict)],
                cwd=repo_root, text=True, capture_output=True)
            report.append(pr.stdout.strip() or pr.stderr.strip())
        else:
            report.append(f"(local only; open with: gh pr create --base {base} --head {branch})")
        return "\n".join(report)
    finally:
        _git(["switch", original], repo_root)


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
