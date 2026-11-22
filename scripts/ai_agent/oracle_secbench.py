"""SecBench.js oracles on the patched worktree (decision D9, Paso 4.8).

Security oracle (dynamic): the case's official SecBench.js exploit is run against
the **patched** package. The Docker harness (``benchmarks/secbench-js/harness``)
installs the published vulnerable version and, with ``PATCHED_SRC``, overlays the
worktree's patched ``src/`` on ``node_modules/<package>`` (``src/`` is the npm
tarball of that exact version, so only the patch differs). A correct fix makes the
exploit fail. CodeQL saying FIXED while the exploit still works is an
**incomplete fix**, reported by this check.

Functional oracle (D9 tiers, pre-registered in ``benchmarks/oracles/``):

- **T1** ``functional_check`` — the package's own test suite (``run_suite.sh``).
- **T2** ``differential_check`` — a pre-registered driver
  (``benchmarks/oracles/t2/<case>.js``) calls the vulnerable entry point with
  benign inputs on the original and the patched package and compares what is
  observable (return values, intercepted commands as argv, HTTP responses)
  (``run_diff.sh`` + ``diff_runner.js``).

Exit codes of the harness: 0 exploited, 1 not exploited, 3 install failed,
4 overlay failed. 3 and 4 are infrastructure errors (raised, not a patch outcome).

Usage (run the exploit on any tree, e.g. the unpatched checkout = base validation):
    python scripts/ai_agent/oracle_secbench.py exploit --tree . --case prototype-pollution/set-value_3.0.0
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from regression import CheckResult

CASES = "benchmarks/secbench-js/cases"
REGISTRY = Path("benchmarks/oracles/secbench-functional.json")
IMAGE = "tfm/secbench-harness"
TIMEOUT = 600
_TAIL = 600   # characters of harness output kept in a failure detail


def case_id(path: str) -> str | None:
    """``code-injection/pixl-class_1.0.0`` for a file inside that case, else None."""
    parts = path.replace("\\", "/").split("/")
    if path.startswith(CASES + "/") and len(parts) > 5:
        return f"{parts[3]}/{parts[4]}"
    return None


def load_case(tree: Path, cid: str) -> dict:
    return json.loads((tree / CASES / cid / "case.json").read_text(encoding="utf-8"))


def run_exploit(tree: Path, cid: str) -> tuple[int, str, float]:
    """Run the case's exploit with ``tree``'s ``src/`` overlaid; (exit code, output, s)."""
    case = load_case(tree, cid)
    cls, name = cid.split("/")
    src = (tree / CASES / cid / "src").resolve()
    start = time.monotonic()
    res = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{src}:/patched:ro", "-e", "PATCHED_SRC=/patched",
         IMAGE, "run_case", cls, name, case["package"], case["vulnerable_version"]],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=TIMEOUT)
    return res.returncode, res.stdout + res.stderr, round(time.monotonic() - start, 1)


def exploit_check(tree: Path, cid: str) -> CheckResult:
    code, out, seconds = run_exploit(tree, cid)
    if code == 0:
        return CheckResult("secbench-exploit", False,
                           "the official SecBench.js exploit still succeeds against the patched "
                           "package, so the vulnerability is still exploitable", seconds)
    if code == 1:
        return CheckResult("secbench-exploit", True, "the exploit no longer succeeds", seconds)
    raise RuntimeError(f"secbench harness error (exit {code}) for {cid}: {out[-_TAIL:]}")


# ------------------------------------------------------------------ functional (T1)

def load_registry(repo_root: Path) -> dict:
    return json.loads((repo_root / REGISTRY).read_text(encoding="utf-8"))["cases"]


def _git(args: list[str], cwd: Path) -> None:
    res = subprocess.run(["git", "-c", "core.autocrlf=false", *args], cwd=cwd,
                         capture_output=True, text=True, timeout=300)
    if res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {res.stderr.strip()[-300:]}")


def _rmtree(path: Path) -> None:
    """rmtree that also removes read-only files (git objects on Windows)."""
    import os
    import shutil
    import stat

    def force(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)

    if path.exists():
        shutil.rmtree(path, onexc=force)


def fetch_repo_tests(repo_root: Path, cid: str, tests: dict) -> Path:
    """Upstream test files at the pinned commit, cached outside the repository.

    Only the listed ``paths`` are exported (no ``.git``). ``core.autocrlf=false``
    keeps fixtures byte-identical on Windows.
    """
    from worktree import default_root

    out = (default_root(repo_root) / "_oracle_cache" / "tests" / cid.replace("/", "__")
           / tests["commit"][:12])
    files = out / "files"
    if files.is_dir():
        return files
    import shutil
    _rmtree(out)
    repo = out / "repo"
    repo.mkdir(parents=True)
    _git(["init", "-q"], repo)
    _git(["fetch", "-q", "--depth", "1", tests["repo"], tests["commit"]], repo)
    _git(["checkout", "-q", "FETCH_HEAD", "--", *tests["paths"]], repo)
    files.mkdir()
    for rel in tests["paths"]:
        src = repo / rel
        (files / rel).parent.mkdir(parents=True, exist_ok=True)
        (shutil.copytree if src.is_dir() else shutil.copy2)(src, files / rel)
    _rmtree(repo)
    return files


def _volume(cid: str, spec: dict) -> str:
    """Named Docker volume caching the suite's node_modules for one case/spec."""
    import hashlib
    key = json.dumps([cid, spec.get("tests"), spec.get("extra_dev", "")], sort_keys=True)
    return "tfm-t1-" + hashlib.sha1(key.encode()).hexdigest()[:12]


def run_suite(tree: Path, cid: str, spec: dict, repo_root: Path) -> tuple[int, str, float]:
    """Run the case's own test suite on ``tree``'s ``src/``; (exit code, output, s)."""
    src = (tree / CASES / cid / "src").resolve()
    cmd = ["docker", "run", "--rm", "-v", f"{src}:/pkg:ro",
           "-v", f"{_volume(cid, spec)}:/work/node_modules"]
    if isinstance(spec.get("tests"), dict):
        cmd += ["-v", f"{fetch_repo_tests(repo_root, cid, spec['tests'])}:/tests:ro"]
    if spec.get("extra_dev"):
        cmd += ["-e", f"EXTRA_DEV={spec['extra_dev']}"]
    cmd += [IMAGE, "run_suite", spec["command"]]
    start = time.monotonic()
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=TIMEOUT)
    return res.returncode, res.stdout + res.stderr, round(time.monotonic() - start, 1)


def functional_check(tree: Path, cid: str, spec: dict, repo_root: Path) -> CheckResult:
    code, out, seconds = run_suite(tree, cid, spec, repo_root)
    if code == 3:
        raise RuntimeError(f"T1 dependencies could not be installed for {cid}: {out[-_TAIL:]}")
    if code == 0:
        return CheckResult("secbench-t1-suite", True,
                           f"the package's own test suite passes ({spec['command']})", seconds)
    lines = [l for l in out.splitlines() if l.strip()]
    return CheckResult("secbench-t1-suite", False,
                       f"the package's own test suite ({spec['command']}), which passed before "
                       f"the patch, now fails. Last output lines: " + " | ".join(lines[-12:])[-_TAIL:],
                       seconds)


# --------------------------------------------------------------- functional (T2)

T2_DRIVERS = Path("benchmarks/oracles/t2")


def driver_name(cid: str) -> str:
    return cid.replace("/", "__") + ".js"


def run_diff(tree: Path, cid: str, repo_root: Path) -> tuple[int, str, float]:
    """Compare the pre-registered benign inputs on the original vs ``tree``'s ``src/``."""
    case = load_case(tree, cid)
    src = (tree / CASES / cid / "src").resolve()
    drivers = (repo_root / T2_DRIVERS).resolve()
    start = time.monotonic()
    res = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{src}:/pkg:ro", "-v", f"{drivers}:/t2:ro",
         "-v", "tfm-npm-cache:/root/.npm",
         IMAGE, "run_diff", case["package"], case["vulnerable_version"], driver_name(cid)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=TIMEOUT)
    return res.returncode, res.stdout + res.stderr, round(time.monotonic() - start, 1)


def differential_check(tree: Path, cid: str, repo_root: Path) -> CheckResult:
    code, out, seconds = run_diff(tree, cid, repo_root)
    if code not in (0, 1):
        raise RuntimeError(f"T2 oracle error (exit {code}) for {cid}: {out[-_TAIL:]}")
    if code == 0:
        return CheckResult("secbench-t2-differential", True,
                           "same behaviour as the original on every pre-registered benign input",
                           seconds)
    diffs = [l for l in out.splitlines() if l.startswith(("DIFF", "  original:", "  patched:"))]
    return CheckResult("secbench-t2-differential", False,
                       "the patched package behaves differently from the original on benign "
                       "(non-malicious) inputs, so legitimate functionality changed: "
                       + " | ".join(diffs)[-_TAIL:], seconds)


def checks(repo_root: Path):
    """The D9 checks for SecBench.js findings, in the form ``verify_patch`` expects."""
    registry = load_registry(repo_root) if (repo_root / REGISTRY).is_file() else {}

    def exploit(finding, tree: Path):
        cid = case_id(finding.file)
        return exploit_check(tree, cid) if cid else None

    def functional(finding, tree: Path):
        cid = case_id(finding.file)
        spec = registry.get(cid) if cid else None
        if spec is None:
            return None
        if spec["tier"] == "T1":
            return functional_check(tree, cid, spec, repo_root)
        return differential_check(tree, cid, repo_root)

    return [exploit, functional]


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("exploit", help="run the case's exploit against a tree's src/")
    ex.add_argument("--tree", type=Path, default=Path("."))
    ex.add_argument("--case", required=True, help="e.g. prototype-pollution/set-value_3.0.0")
    su = sub.add_parser("suite", help="run a case's T1 test suite (registry spec, or a probe)")
    su.add_argument("--tree", type=Path, default=Path("."))
    su.add_argument("--repo-root", type=Path, default=Path("."))
    su.add_argument("--case", required=True)
    su.add_argument("--command", help="probe: test command instead of the registered one")
    su.add_argument("--repo", help="probe: upstream repo URL for the test files")
    su.add_argument("--commit", help="probe: commit of the version")
    su.add_argument("--paths", help="probe: comma-separated test paths to take from the repo")
    su.add_argument("--extra-dev", default="", help="probe: extra npm packages")
    di = sub.add_parser("diff", help="run a case's T2 differential driver on a tree")
    di.add_argument("--tree", type=Path, default=Path("."))
    di.add_argument("--repo-root", type=Path, default=Path("."))
    di.add_argument("--case", required=True)
    args = parser.parse_args()

    if args.cmd == "diff":
        code, out, seconds = run_diff(args.tree.resolve(), args.case, args.repo_root.resolve())
        print(out.rstrip())
        print(f"\nEXIT {code}  ({seconds}s)")
        raise SystemExit(code)

    if args.cmd == "exploit":
        r = exploit_check(args.tree.resolve(), args.case)
        print(f"{r.name}: {'OK' if r.ok else 'FAIL'} — {r.detail} ({r.seconds}s)")
        raise SystemExit(0 if r.ok else 1)

    repo_root = args.repo_root.resolve()
    if args.command:
        spec = {"tier": "T1", "command": args.command, "extra_dev": args.extra_dev,
                "tests": ({"repo": args.repo, "commit": args.commit, "paths": args.paths.split(",")}
                          if args.repo else "tarball")}
    else:
        spec = load_registry(repo_root)[args.case]
    code, out, seconds = run_suite(args.tree.resolve(), args.case, spec, repo_root)
    print("\n".join(out.splitlines()[-40:]))
    print(f"\nEXIT {code}  ({seconds}s)")
    raise SystemExit(code)


if __name__ == "__main__":
    main()
