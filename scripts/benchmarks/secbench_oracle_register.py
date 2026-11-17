"""Validate and pre-register the SecBench.js functional oracle T1 (decision D9, Paso 4.8).

Input/output: ``benchmarks/oracles/secbench-functional.json``. Each case has a
hand-curated spec (where its tests come from and the command that runs them,
without linters or coverage gates). This script validates every ``T1`` spec
and writes the result back into the file:

1. **Base run** — the suite must pass on the unpatched package (Node 16 harness).
2. **Sensitivity control** — the suite must *fail* on a mutant of the package
   where ``throw new Error(...)`` is inserted right before the sink line (the
   vulnerable statement, ``benchmarks/dataset.csv``). A suite that still passes
   never reaches the vulnerable code, so it could not notice what a patch does
   there. If that insertion breaks the syntax (the sink line is inside a
   multi-line expression), the throw goes at the top of the file instead and
   the sensitivity is recorded as ``module-load`` (weaker: the module is loaded,
   not necessarily the vulnerable function run).

A spec that fails either check is demoted to ``T2`` with the reason. The file is
the pre-registration: it is committed before any Phase 5 patch exists.

Usage:
    python scripts/benchmarks/secbench_oracle_register.py [case-id-substring ...]
"""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts" / "ai_agent"))

import oracle_secbench as ob  # noqa: E402

REGISTRY = REPO / ob.REGISTRY
MARK = "throw new Error('tfm-oracle-sensitivity-control')"


def sinks() -> dict[str, tuple[str, int]]:
    """case id -> (sink file relative to the case's src/, sink line)."""
    out = {}
    for row in csv.DictReader(open(REPO / "benchmarks" / "dataset.csv", encoding="utf-8")):
        if row["source"] == "secbench-js":
            prefix = f"{ob.CASES}/{row['id']}/src/"
            out[row["id"]] = (row["file"].removeprefix(prefix), int(row["line"]))
    return out


def _syntax_ok(path: Path) -> bool:
    return subprocess.run(["node", "--check", str(path)], capture_output=True).returncode == 0


def mutant_tree(cid: str, sink_file: str, line: int, tmp: Path) -> tuple[Path, str]:
    """A tree with the case's package where the sink line is preceded by a throw."""
    case = tmp / ob.CASES / cid
    case.mkdir(parents=True)
    shutil.copy2(REPO / ob.CASES / cid / "case.json", case / "case.json")
    shutil.copytree(REPO / ob.CASES / cid / "src", case / "src")
    target = case / "src" / sink_file
    lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
    original = list(lines)
    lines.insert(line - 1, MARK + ";\n")
    target.write_text("".join(lines), encoding="utf-8")
    if _syntax_ok(target):
        return tmp, "sink-line"
    target.write_text(MARK + ";\n" + "".join(original), encoding="utf-8")
    return tmp, "module-load"


def validate(cid: str, spec: dict, sink: tuple[str, int]) -> dict:
    code, out, seconds = ob.run_suite(REPO, cid, spec, REPO)
    result = {"base_exit": code, "base_seconds": seconds}
    if code != 0:
        result["rejected"] = f"suite does not pass on the unpatched base (exit {code})"
        result["base_tail"] = " | ".join(l.strip() for l in out.splitlines()[-6:] if l.strip())[-400:]
        return result
    with tempfile.TemporaryDirectory() as tmp:
        tree, mode = mutant_tree(cid, sink[0], sink[1], Path(tmp))
        mcode, mout, _ = ob.run_suite(tree, cid, spec, REPO)
    result.update({"sensitivity": mode, "mutant_exit": mcode})
    if mcode == 0:
        result["rejected"] = ("suite still passes with a throw before the sink line: "
                              "it never reaches the vulnerable code")
    return result


def main() -> None:
    only = sys.argv[1:]
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    sink = sinks()
    for cid, spec in data["cases"].items():
        if only and not any(o in cid for o in only):
            continue
        if spec.get("tier") != "T1" and "t1_candidate" not in spec:
            continue
        candidate = spec.get("t1_candidate", spec)          # re-validate a demoted spec
        run_spec = {k: candidate[k] for k in ("tests", "command", "extra_dev") if k in candidate}
        v = validate(cid, run_spec, sink[cid])
        if "rejected" in v:
            data["cases"][cid] = {"tier": "T2", "reason": "T1 rejected: " + v["rejected"],
                                  "t1_candidate": {**run_spec, "validation": v},
                                  **{k: spec[k] for k in ("notes",) if k in spec}}
        else:
            data["cases"][cid] = {**{k: v2 for k, v2 in spec.items() if k != "t1_candidate"},
                                  **run_spec, "tier": "T1", "validation": v}
            data["cases"][cid].pop("reason", None)
        print(f"{cid:52s} {data['cases'][cid]['tier']}  {json.dumps(v)[:160]}", flush=True)
    data["validated"] = date.today().isoformat()
    REGISTRY.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
