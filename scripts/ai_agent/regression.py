"""Pre/post-patch comparison by fingerprint (Paso 4.3).

Decides whether a patch removed the target vulnerability and whether it
introduced new ones, comparing two rescans of the same project (4.2): *pre* (the
base, unpatched) and *post* (the patched worktree). Findings are matched by
``partialFingerprints["tfmContextHash/v1"]`` — **never by line number**, as the
roadmap requires: a patch shifts lines, and line-based matching would report every
finding below the edit as fixed-and-new.

The fingerprint is ``digest:occurrence``. The occurrence index can shift when an
identical finding appears or disappears, so findings are compared as a
**multiset of digests** (the ``label_key``): per digest, ``min(pre, post)`` are
PERSISTING, the surplus in post is NEW, the surplus in pre DISAPPEARED.

Outcomes:

- target **FIXED** — its digest is gone from post *and* no NEW finding of the same
  rule appeared in the same file. The second condition matters: the digest hashes
  the flagged line's text, so a cosmetic patch on the vulnerable line (renaming a
  variable) changes the digest while the vulnerability stays. Counting that as
  FIXED would be a false success, so it is reported as **NOT_FIXED (relocated)**.
- target **NOT_FIXED** — its digest is still in post (or relocated, as above).
- **NEW** — findings in post with no counterpart in pre: possible security
  regressions introduced by the patch.
- **PERSISTING** — untouched findings (including the 4 scope extras of 4.2, which
  appear on both sides).
- **DISAPPEARED** — other findings that went away (collateral fixes, or findings
  whose flagged text the patch edited; 4.4 refines these against NEW ones).

``verify_patch`` runs the whole check: clean worktree from ``base`` (4.1), baseline
rescan (cached per base commit and scope), apply the patch, post rescan, compare.

Usage:
    # compare two rescans
    python scripts/ai_agent/regression.py compare --pre pre.sarif --post post.sarif --target <fp>
    # full verification of a patch (needs the CodeQL CLI, see 4.2)
    python scripts/ai_agent/regression.py verify <unified.sarif> --fingerprint <fp> \
        --patch-file fix.diff --repo-root .
"""

from __future__ import annotations

import subprocess
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from sarif_parser import Finding, parse_sarif

FIXED, NOT_FIXED = "FIXED", "NOT_FIXED"


@dataclass
class Comparison:
    target: str                       # label_key (digest) of the target finding
    status: str                       # FIXED | NOT_FIXED
    relocated: bool                   # NOT_FIXED because the vuln moved, not stayed
    new: list[Finding] = field(default_factory=list)
    persisting: list[Finding] = field(default_factory=list)
    disappeared: list[Finding] = field(default_factory=list)

    @property
    def regression(self) -> bool:
        """The patch introduced at least one new finding."""
        return bool(self.new)

    def summary(self) -> str:
        status = self.status + (" (relocated: same rule still reported in the file)"
                                if self.relocated else "")
        lines = [f"target {self.target[:8]}: {status}",
                 f"new {len(self.new)}, persisting {len(self.persisting)}, "
                 f"disappeared {len(self.disappeared)}"]
        for title, items in (("NEW:", self.new), ("DISAPPEARED:", self.disappeared)):
            if items:
                lines.append(title)
                lines += [f"  {f.label_key[:8]}  {f.rule_id}  {f.file}:{f.start_line}"
                          f"  CVSS {f.security_severity}" for f in items]
        return "\n".join(lines)

    def as_dict(self) -> dict:
        brief = lambda fs: [{"fingerprint": f.label_key, "rule": f.rule_id, "file": f.file,
                             "line": f.start_line, "cvss": f.security_severity} for f in fs]
        return {"target": self.target, "status": self.status, "relocated": self.relocated,
                "regression": self.regression, "new": brief(self.new),
                "persisting": len(self.persisting), "disappeared": brief(self.disappeared)}


def _by_digest(findings: list[Finding]) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {}
    for f in findings:
        out.setdefault(f.label_key, []).append(f)
    return out


def compare(pre: list[Finding], post: list[Finding], target_key: str) -> Comparison:
    """Classify post-patch findings against pre-patch ones for a target finding."""
    target_key = target_key.split(":")[0]
    pre_by, post_by = _by_digest(pre), _by_digest(post)
    if target_key not in pre_by:
        raise ValueError(f"target {target_key} is not in the pre-patch scan "
                         "(was the baseline scanned with the same scope?)")
    target = pre_by[target_key][0]

    new, persisting, disappeared = [], [], []
    for key in pre_by.keys() | post_by.keys():
        before, after = pre_by.get(key, []), post_by.get(key, [])
        keep = min(len(before), len(after))
        persisting += after[:keep]
        new += after[keep:]
        if key != target_key:
            disappeared += before[keep:]

    still_there = target_key in post_by
    relocated = not still_there and any(
        f.rule_id == target.rule_id and f.file == target.file for f in new)
    status = NOT_FIXED if still_there or relocated else FIXED
    order = lambda fs: sorted(fs, key=lambda f: (f.file, f.start_line, f.rule_id))
    return Comparison(target=target_key, status=status, relocated=relocated,
                      new=order(new), persisting=order(persisting), disappeared=order(disappeared))


# --------------------------------------------------------------------------- verify

@dataclass
class Verification:
    applied: bool
    detail: str                         # apply result, or why it stopped
    comparison: Comparison | None
    baseline_cached: bool
    seconds: dict[str, float]           # baseline / post rescan wall time (overhead)


def _rev(repo_root: Path, ref: str) -> str:
    return subprocess.run(["git", "rev-parse", ref], cwd=repo_root, text=True,
                          capture_output=True, check=True).stdout.strip()


def verify_patch(finding: Finding, diff: str, repo_root: Path, base: str = "main",
                 out_root: Path | None = None, cli: str | None = None) -> Verification:
    """Apply ``diff`` in a throwaway worktree of ``base`` and compare rescans.

    The worktree and its branch are always deleted: verification only measures;
    keeping the fix and opening the PR is ``remediation_pr.prepare_pr``.
    """
    from remediation_pr import apply_by_content, branch_name
    from rescan import rescan, scope_for
    from worktree import default_root, worktree

    repo_root = repo_root.resolve()
    scope = scope_for(finding.file)
    out_root = out_root or default_root(repo_root) / "_rescan"
    base_sha = _rev(repo_root, base)
    baseline_dir = out_root / "baseline" / base_sha[:12] / (scope.replace("/", "_") or "repo")
    seconds: dict[str, float] = {}

    branch = branch_name(finding) + f"-verify-{int(time.time())}"
    with worktree(repo_root, branch, base=base_sha, keep_branch=False) as wt:
        cached = (baseline_dir / "codeql.sarif").is_file()
        if not cached:   # baseline = the worktree before the patch (= base)
            seconds["baseline"] = rescan(wt.path, baseline_dir, scope, cli).seconds

        result = apply_by_content(diff, wt.path)
        if not result.ok:
            return Verification(False, result.detail, None, cached, seconds)
        for path, content in result.changed.items():
            (wt.path / path).write_text(content, encoding="utf-8")

        post = rescan(wt.path, out_root / "post" / branch.split("/")[-1], scope, cli)
        seconds["post"] = post.seconds
        pre_findings = parse_sarif(baseline_dir / "codeql.sarif")
        post_findings = parse_sarif(post.sarif)
        comparison = compare(pre_findings, post_findings, finding.label_key)
        return Verification(True, result.detail, comparison, cached, seconds)


def main() -> None:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    cmp_p = sub.add_parser("compare", help="compare two rescans")
    cmp_p.add_argument("--pre", type=Path, required=True)
    cmp_p.add_argument("--post", type=Path, required=True)
    cmp_p.add_argument("--target", required=True, help="fingerprint (or label_key) of the target")
    ver_p = sub.add_parser("verify", help="apply a patch in a worktree and compare rescans")
    ver_p.add_argument("sarif", type=Path, help="unified SARIF the target comes from")
    ver_p.add_argument("--fingerprint", required=True)
    ver_p.add_argument("--patch-file", type=Path, required=True)
    ver_p.add_argument("--repo-root", type=Path, default=Path("."))
    ver_p.add_argument("--base", default="main")
    ver_p.add_argument("--codeql", help="path to the CodeQL CLI (default: $CODEQL_CLI or PATH)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.cmd == "compare":
        c = compare(parse_sarif(args.pre), parse_sarif(args.post), args.target)
        print(json.dumps(c.as_dict(), indent=1) if args.json else c.summary())
        return

    target = next((f for f in parse_sarif(args.sarif)
                   if args.fingerprint in (f.fingerprint, f.label_key)), None)
    if target is None:
        raise SystemExit(f"no finding with fingerprint {args.fingerprint}")
    v = verify_patch(target, args.patch_file.read_text(encoding="utf-8"), args.repo_root,
                     args.base, cli=args.codeql)
    print(f"apply: {v.detail}  | baseline {'cached' if v.baseline_cached else 'scanned'}"
          f"  | rescan seconds {v.seconds}")
    if v.comparison:
        print(json.dumps(v.comparison.as_dict(), indent=1) if args.json else v.comparison.summary())


if __name__ == "__main__":
    main()
