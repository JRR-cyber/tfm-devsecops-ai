"""Run the executable evidence behind every triage label and check it holds.

Criteria: docs/benchmark/triage-labels.md. Each spec in
benchmarks/triage/evidence/specs.json names a finding, its label and the
exploit that backs it:

    TP  the exploit succeeds against the code as is.
    FP  the exploit fails against the code as is AND succeeds once the cited
        guards are removed (ablation: a list of exact old -> new edits applied
        to a temporary copy; the benchmark itself is never modified). Every
        guard on the path must be cited, or the ablated run still fails.

The FP set draws from Juice Shop and from the flagged fixed versions of
SecBench.js cases (docs/benchmark/decisions.md, D5).

Juice Shop exploits (``juice-shop/*.py``, ``exploit(base_url) -> (ok, detail)``)
run over HTTP against the container image the pipeline builds
(``docker build -t tfm/juice-shop:ci src/app/juice-shop``) with every
challenge enabled. An FP's ablation edits the compiled file inside the image
(``build/...js``), or a dependency under ``node_modules/``, mounted read-only
over the original.

SecBench.js exploits (``secbench-js/*.test.js``, Jest, pass = exploit
succeeded) run in the harness (``benchmarks/secbench-js/harness``,
``run_evidence``); their ablation edits a file of the installed package.

Usage:
    python scripts/benchmarks/triage_evidence.py [<spec id> ...]
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "benchmarks" / "triage" / "evidence"
JUICE_IMAGE = "tfm/juice-shop:ci"
HARNESS_IMAGE = "tfm/secbench-harness"
# Every challenge enabled: in containers safetyMode "auto" disables the risky
# ones, and some routes then sanitize their input (triage-labels.md, section 5).
JUICE_CONFIG = json.dumps({"challenges": {"safetyMode": "disabled"}})
STARTUP_TIMEOUT = 180


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", check=check)


def ablate(text: str, edit: dict) -> str:
    if text.count(edit["old"]) != 1:
        raise RuntimeError(f"ablation does not apply to {edit['file']}: 'old' must occur exactly once")
    return text.replace(edit["old"], edit["new"])


def run_secbench(spec: dict, ablation: list[dict] | None, tmp: Path) -> tuple[bool, str]:
    args = ["run", "--rm", "-v", f"{EVIDENCE}:/evidence:ro"]
    command = ["run_evidence", spec["package"], spec["version"], f"/evidence/{spec['exploit']}"]
    if ablation:
        (tmp / "ablation.json").write_text(json.dumps(ablation), encoding="utf-8")
        args += ["-v", f"{tmp}:/ablation:ro"]
        command.append("/ablation/ablation.json")
    res = docker(*args, HARNESS_IMAGE, *command, check=False)
    if res.returncode not in (0, 1):
        raise RuntimeError(f"run_evidence exited {res.returncode}:\n{(res.stdout + res.stderr)[-2000:]}")
    return res.returncode == 0, "jest passed" if res.returncode == 0 else "jest failed"


def run(spec: dict, ablation: list[dict] | None) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        if spec["source"] == "secbench-js":
            return run_secbench(spec, ablation, tmp)
        mounts = []
        if ablation:
            container = docker("create", JUICE_IMAGE).stdout.strip()
            try:
                for i, file in enumerate(dict.fromkeys(edit["file"] for edit in ablation)):
                    patched = tmp / f"ablated-{i}.js"
                    docker("cp", f"{container}:/juice-shop/{file}", str(patched))
                    text = patched.read_text(encoding="utf-8")
                    for edit in (e for e in ablation if e["file"] == file):
                        text = ablate(text, edit)
                    patched.write_text(text, encoding="utf-8")
                    mounts += ["-v", f"{patched}:/juice-shop/{file}:ro"]
            finally:
                docker("rm", container)

        container = docker("run", "-d", "-p", "127.0.0.1::3000", "-e", f"NODE_CONFIG={JUICE_CONFIG}",
                           *mounts, JUICE_IMAGE).stdout.strip()
        try:
            port = docker("port", container, "3000").stdout.split(":")[-1].strip()
            base = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + STARTUP_TIMEOUT
            while True:
                try:
                    urllib.request.urlopen(f"{base}/rest/admin/application-version", timeout=5)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError("Juice Shop did not start:\n" + docker("logs", container, check=False).stderr[-2000:])
                    time.sleep(2)
            module_spec = importlib.util.spec_from_file_location("exploit", EVIDENCE / spec["exploit"])
            module = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(module)
            ok, detail = module.exploit(base)
            # Effects visible only in the app's log (e.g. log injection) are checked
            # against the container's stdout: the exploit sends the payload, then
            # check_logs(logs) asserts the forged line landed (triage-labels.md s.6).
            if hasattr(module, "check_logs"):
                logs = docker("logs", container, check=False)
                ok_log, detail_log = module.check_logs(logs.stdout + logs.stderr)
                return ok and ok_log, f"{detail}; logs: {detail_log}"
            return ok, detail
        finally:
            docker("rm", "-f", container, check=False)


def main() -> None:
    specs = json.loads((EVIDENCE / "specs.json").read_text(encoding="utf-8"))
    if sys.argv[1:]:
        specs = [s for s in specs if s["id"] in sys.argv[1:]]
    failures = 0
    for spec in specs:
        start = time.monotonic()
        ok, detail = run(spec, ablation=None)
        if spec["label"] == "TP":
            holds, summary = ok, f"original: {'exploited' if ok else 'NOT exploited'} ({detail})"
        elif spec.get("evidence") == "GATE":
            # FP backed by a documented guard + one reproducible check: the exploit
            # function self-verifies (malicious input rejected, benign control works)
            # and returns True when the guard holds. No ablation (triage-labels.md s.6).
            holds, summary = ok, f"guard check: {'confirmed' if ok else 'FAILED'} ({detail})"
        else:
            ok_abl, detail_abl = run(spec, ablation=spec["ablation"])
            holds = not ok and ok_abl
            summary = (f"original: {'EXPLOITED' if ok else 'blocked'} ({detail}); "
                       f"ablated: {'exploited' if ok_abl else 'NOT exploited'} ({detail_abl})")
        failures += not holds
        print(f"{'OK  ' if holds else 'FAIL'} {spec['id']:<34} {spec['label']:<3} {summary} "
              f"[{time.monotonic() - start:.0f}s]", flush=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
