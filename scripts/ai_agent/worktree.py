"""Isolated git worktrees for applying and verifying patches (Paso 4.1).

Phase 4 needs to apply a candidate patch, rescan it and (if it fails) retry, up
to three times per vulnerability. Doing that by switching branches in the user's
checkout is fragile: it rewrites their working tree, it fails if they have local
changes, and a branch based on ``main`` may not even contain this agent's code.

A ``git worktree`` solves all three: it is a second working directory attached
to the same repository, checked out on its own branch. The fix branch lives
there; the user's checkout (branch, files, index) is never touched.

Layout: worktrees go *outside* the repository (default ``<repo>/../tfm-worktrees``,
override with ``--root`` or ``TFM_WORKTREE_ROOT``), so the CI scanners, pre-commit
and a CodeQL database of the main checkout never see them, and paths stay short
on Windows.

Guard rail (assistive posture): only ``fix/ai-remediation-...`` branches can be
created here. The agent cannot use this module to write to ``main`` or any other
branch.

Usage (manual inspection / cleanup):
    python scripts/ai_agent/worktree.py list
    python scripts/ai_agent/worktree.py remove fix/ai-remediation-<rule>-<fp8> [--delete-branch]
"""

from __future__ import annotations

import os
import re
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

BRANCH_PREFIX = "fix/ai-remediation-"


class WorktreeError(RuntimeError):
    """A git worktree operation failed; the message carries git's stderr."""


@dataclass(frozen=True)
class Worktree:
    path: Path      # the isolated working directory
    branch: str     # fix/ai-remediation-...
    base: str       # the branch it was created from (and the PR targets)


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True)


def _check(res: subprocess.CompletedProcess, what: str) -> str:
    if res.returncode != 0:
        raise WorktreeError(f"{what}: {res.stderr.strip() or res.stdout.strip()}")
    return res.stdout


def default_root(repo_root: Path) -> Path:
    env = os.environ.get("TFM_WORKTREE_ROOT")
    return Path(env) if env else repo_root.resolve().parent / "tfm-worktrees"


def _dir_name(branch: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", branch.removeprefix(BRANCH_PREFIX))


def create(repo_root: Path, branch: str, base: str = "main",
           root: Path | None = None) -> Worktree:
    """Create a new fix branch from ``base`` checked out in its own worktree."""
    if not branch.startswith(BRANCH_PREFIX):
        raise WorktreeError(f"refusing to create {branch!r}: only {BRANCH_PREFIX}* branches")
    repo_root = repo_root.resolve()
    path = (root or default_root(repo_root)) / _dir_name(branch)
    if path.exists():
        raise WorktreeError(f"{path} already exists (stale worktree? run: worktree.py remove {branch})")
    _git(["worktree", "prune"], repo_root)   # forget worktrees whose dir was deleted by hand
    if _git(["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], repo_root).returncode == 0:
        raise WorktreeError(f"branch {branch} already exists (remove it or pick another name)")
    path.parent.mkdir(parents=True, exist_ok=True)
    _check(_git(["worktree", "add", "-b", branch, str(path), base], repo_root),
           f"git worktree add {branch} from {base}")
    return Worktree(path=path, branch=branch, base=base)


def reset(wt: Worktree) -> None:
    """Discard every change in the worktree, back to ``base`` (fresh attempt)."""
    _check(_git(["reset", "--hard", wt.base], wt.path), "git reset")
    _check(_git(["clean", "-fd"], wt.path), "git clean")


def commit_all(wt: Worktree, paths: list[str], message: str) -> str:
    """Stage ``paths`` and commit them on the worktree's branch; return the SHA."""
    _check(_git(["add", "--", *paths], wt.path), "git add")
    _check(_git(["commit", "-m", message], wt.path), "git commit")
    return _check(_git(["rev-parse", "HEAD"], wt.path), "git rev-parse").strip()


def remove(repo_root: Path, wt_or_branch: Worktree | str, delete_branch: bool = False) -> None:
    """Remove the worktree directory; optionally delete its branch too."""
    repo_root = repo_root.resolve()
    branch = wt_or_branch.branch if isinstance(wt_or_branch, Worktree) else wt_or_branch
    if not branch.startswith(BRANCH_PREFIX):
        raise WorktreeError(f"refusing to touch {branch!r}: not a {BRANCH_PREFIX}* branch")
    path = next((p for p, b in list_worktrees(repo_root) if b == branch), None)
    if path is not None:
        _check(_git(["worktree", "remove", "--force", str(path)], repo_root), "git worktree remove")
    _git(["worktree", "prune"], repo_root)
    if delete_branch:
        _git(["branch", "-D", branch], repo_root)


def list_worktrees(repo_root: Path) -> list[tuple[Path, str]]:
    """(path, branch) of every fix/ai-remediation-* worktree of the repo."""
    out = _check(_git(["worktree", "list", "--porcelain"], repo_root), "git worktree list")
    result, path = [], None
    for line in out.splitlines():
        if line.startswith("worktree "):
            path = Path(line[len("worktree "):])
        elif line.startswith("branch refs/heads/") and path is not None:
            branch = line[len("branch refs/heads/"):]
            if branch.startswith(BRANCH_PREFIX):
                result.append((path, branch))
    return result


@contextmanager
def worktree(repo_root: Path, branch: str, base: str = "main", root: Path | None = None,
             keep_branch: bool = True) -> Iterator[Worktree]:
    """Create a worktree, yield it, and always remove the directory afterwards.

    The branch is kept by default (it holds the committed fix the PR points to);
    ``keep_branch=False`` deletes it too (e.g. a failed attempt).
    """
    wt = create(repo_root, branch, base, root)
    try:
        yield wt
    finally:
        remove(repo_root, wt, delete_branch=not keep_branch)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list fix/ai-remediation-* worktrees")
    rm = sub.add_parser("remove", help="remove a worktree by branch name")
    rm.add_argument("branch")
    rm.add_argument("--delete-branch", action="store_true")
    args = parser.parse_args()

    if args.cmd == "list":
        wts = list_worktrees(args.repo_root)
        for path, branch in wts:
            print(f"{branch}  {path}")
        if not wts:
            print("(no fix/ai-remediation-* worktrees)")
    else:
        try:
            remove(args.repo_root, args.branch, delete_branch=args.delete_branch)
        except WorktreeError as exc:
            raise SystemExit(f"error: {exc}")
        print(f"removed worktree of {args.branch}" + (" and the branch" if args.delete_branch else ""))


if __name__ == "__main__":
    main()
