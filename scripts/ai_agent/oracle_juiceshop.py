"""Juice Shop oracles on the patched worktree (decision D9, Paso 4.8).

For the 3 Juice Shop cases the oracle is the route's own API test file, run
against the patched worktree. Every test is pre-registered
(``benchmarks/oracles/juice-shop-api.json``) as:

- ``functional`` — must keep passing: a failure is a **functional regression**
  (check ``juice-shop-functional``);
- ``vuln`` — asserts that the target vulnerability is exploitable, so a correct
  fix must make it **fail**: one that still passes means the attack still works
  (check ``juice-shop-exploit``, the dynamic security oracle).

The worktree has no ``node_modules`` nor build artifacts (it is a fresh checkout
and the rescan refuses untracked files), so the check links the user's
checkout's ``node_modules``, ``build`` and ``frontend/dist`` into it (directory
junctions on Windows; list in ``worktree.ORACLE_LINKS``) for the duration of the
run, after the post rescan, and always removes the links afterwards. ``build``
and ``frontend/dist`` only satisfy Juice Shop's startup preconditions (files
must exist): the tests import ``server.ts`` and run the worktree's TypeScript
routes through tsx, i.e. the patched code. ``worktree.remove`` also unlinks them
defensively, so ``git worktree remove --force`` can never recurse into the real
directories.

Usage (run the oracle on any tree, e.g. the unpatched checkout = base validation):
    python scripts/ai_agent/oracle_juiceshop.py --tree . --target src/app/juice-shop/routes/login.ts
"""

from __future__ import annotations

import html
import json
import os
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from regression import CheckResult

JUICE_SHOP = "src/app/juice-shop"
REGISTRY = Path("benchmarks/oracles/juice-shop-api.json")
FUNCTIONAL, VULN = "functional", "vuln"
TIMEOUT = 600


def load_registry(repo_root: Path) -> dict:
    return json.loads((repo_root / REGISTRY).read_text(encoding="utf-8"))["cases"]


def _link(link: Path, target: Path) -> None:
    if os.name == "nt":                   # junction: no admin rights / developer mode needed
        res = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                             capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"mklink /J failed: {res.stderr.strip() or res.stdout.strip()}")
    else:
        link.symlink_to(target, target_is_directory=True)


def link_dependencies(tree: Path, source_repo: Path) -> list[Path]:
    """Link the checkout's untracked Juice Shop dirs (``worktree.ORACLE_LINKS``) into ``tree``.

    Returns the links created; a dir the tree already has (e.g. when ``tree`` is
    the checkout itself) is left alone.
    """
    from worktree import ORACLE_LINKS

    links: list[Path] = []
    try:
        for rel in ORACLE_LINKS:
            link, target = tree / rel, (source_repo / rel).resolve()
            if link.exists() or link.is_symlink():
                continue
            if not target.is_dir():
                raise RuntimeError(f"{target} not found: run npm install in {JUICE_SHOP} first "
                                   "(it builds the server and the frontend)")
            link.parent.mkdir(parents=True, exist_ok=True)
            _link(link, target)
            links.append(link)
    except Exception:
        for link in links:
            unlink(link)
        raise
    return links


def unlink(link: Path) -> None:
    """Remove a junction/symlink without touching what it points to."""
    if link.is_symlink() or (hasattr(link, "is_junction") and link.is_junction()):
        os.unlink(link) if link.is_symlink() else os.rmdir(link)


def run_tests(tree: Path, test_file: str) -> dict[str, str]:
    """Run one API test file in ``tree``; return {test name: pass | fail | skip}."""
    app = tree / JUICE_SHOP
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "junit.xml"
        cmd = ["node", "--import", "./test/api/helpers/test-env.mjs", "--import", "tsx",
               "--test", "--test-force-exit", "--test-reporter=junit",
               f"--test-reporter-destination={report}", test_file]
        subprocess.run(cmd, cwd=app, capture_output=True, text=True, timeout=TIMEOUT)
        if not report.is_file():
            raise RuntimeError(f"no test report for {test_file} (the test run crashed)")
        results: dict[str, str] = {}
        for case in ET.parse(report).getroot().iter("testcase"):
            if case.find("skipped") is not None:
                state = "skip"
            elif case.find("failure") is not None or case.find("error") is not None:
                state = "fail"
            else:
                state = "pass"
            # Node's junit reporter escapes names twice (" -> &amp;quot;), so the
            # parsed attribute still holds "&quot;": undo the second layer.
            results[html.unescape(case.get("name", ""))] = state
        return results


def evaluate(spec: dict, results: dict[str, str], seconds: float) -> list[CheckResult]:
    """Turn per-test results into the functional and exploit checks."""
    missing = [n for n in spec["tests"] if n not in results]
    if missing:   # registry and test file disagree: an oracle bug, not a patch outcome
        raise RuntimeError(f"pre-registered tests not found in the report: {missing}")
    broken = [n for n, k in spec["tests"].items() if k == FUNCTIONAL and results.get(n) != "pass"]
    still = [n for n, k in spec["tests"].items() if k == VULN and results.get(n) == "pass"]
    n_f = sum(k == FUNCTIONAL for k in spec["tests"].values())
    n_v = sum(k == VULN for k in spec["tests"].values())
    quote = lambda names: "; ".join(f"'{n}'" for n in names)
    functional = CheckResult(
        "juice-shop-functional", not broken,
        (f"{len(broken)} of {n_f} functional API tests that passed before the patch now fail "
         f"({spec['test_file']}): {quote(broken)}") if broken else f"{n_f}/{n_f} functional tests pass",
        seconds)
    exploit = CheckResult(
        "juice-shop-exploit", not still,
        (f"{len(still)} of {n_v} attack tests still succeed after the patch, so the vulnerability "
         f"is still exploitable: {quote(still)}") if still else f"0/{n_v} attack tests succeed",
        0.0)
    return [functional, exploit]


def check_tree(tree: Path, target_file: str, repo_root: Path) -> list[CheckResult]:
    """Run the oracle for ``target_file`` on ``tree`` (patched worktree or checkout)."""
    spec = load_registry(repo_root).get(target_file)
    if spec is None:
        return []
    links = link_dependencies(tree, repo_root)
    try:
        start = time.monotonic()
        results = run_tests(tree, spec["test_file"])
        return evaluate(spec, results, round(time.monotonic() - start, 1))
    finally:
        for link in links:
            unlink(link)


def checks(repo_root: Path):
    """The D9 checks for Juice Shop findings, in the form ``verify_patch`` expects.

    ``verify_patch`` takes one CheckResult per check callable, but this oracle
    produces two from a single test run, so the run is cached per worktree.
    """
    cache: dict[Path, list[CheckResult]] = {}

    def run(finding, tree: Path) -> list[CheckResult]:
        if tree not in cache:
            cache.clear()
            cache[tree] = check_tree(tree, finding.file, repo_root)
        return cache[tree]

    def functional(finding, tree):
        res = run(finding, tree)
        return res[0] if res else None

    def exploit(finding, tree):
        res = run(finding, tree)
        return res[1] if res else None

    return [functional, exploit]


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--tree", type=Path, default=Path("."), help="tree to test (worktree or checkout)")
    parser.add_argument("--target", required=True, help="repo-relative path of the vulnerable route")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    args = parser.parse_args()
    res = check_tree(args.tree.resolve(), args.target, args.repo_root.resolve())
    if not res:
        raise SystemExit(f"{args.target} is not in {REGISTRY}")
    for r in res:
        print(f"{r.name}: {'OK' if r.ok else 'FAIL'} — {r.detail} ({r.seconds}s)")
    sys.exit(0 if all(r.ok for r in res) else 1)


if __name__ == "__main__":
    main()
