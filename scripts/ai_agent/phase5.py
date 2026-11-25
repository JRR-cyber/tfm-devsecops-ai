"""Phase 5 experiment runner (D12): triage and remediation grids, 3 passes each.

Implements the protocol of ``docs/benchmark/decisions.md``, D12:

- **Triage**: 83 findings (the 53 rows of ``benchmarks/triage/labels.csv`` plus the
  30 SecBench.js remediation targets) x 3 strategies x 3 contexts = 747 calls per
  pass. Contexts: ``full`` (trace + RAG, the production agent), ``blind`` (RAG,
  no trace: the 5.3 control) and ``norag`` (trace, no RAG).
- **Remediation**: the 33 cases of ``benchmarks/remediation-targets.csv`` x 3
  strategies x trace yes/no, RAG always on (you cannot patch what you cannot
  see). Every case is repaired whatever the triage says (D11), with the reflexive
  loop of up to 3 attempts verified by CodeQL and the D9 oracles.
- **Passes**: ``--rep 1..3``. Each pass has its own log,
  ``experiments/phase5/<experiment>-p<rep>.jsonl``, and the pass is part of every
  log key.
- **Order**: randomised complete blocks. In each pass the units are shuffled, and
  each unit runs all its conditions, in shuffled order, before the next one starts
  (seed 20261125, per experiment and pass). An interrupted pass leaves complete
  within-subject blocks, and no condition is confounded with the time of day.
- **Input**: ``experiments/phase5/input/findings.sarif.gz``, the CI SARIF reduced to
  the findings of both experiments (``input`` subcommand). Every run checks it
  against its MANIFEST.
- **Freeze**: an official run needs the tag ``phase5-protocol``, and the agent code,
  the benchmark and the input must be unchanged since it; only new logs may be
  committed in between. ``--dev`` runs anything into ``results/dev/phase5/``.
- **Guards**: provider Together with gpt-oss-120b (D12). The run stops with exit 77
  if the API serves another model, 76 at the ``LLM_BUDGET_USD`` spend cap of the
  log, 75 on a provider quota, 1 on an infrastructure failure (Docker, CodeQL,
  network). Relaunching the same command resumes from the log.

The *finding* the model sees for a dataset row is the SARIF occurrence on the
row's line (``sarif_parser.pick_occurrence``), so every condition and pass gets
the same one.

Usage (Git Bash, repo root):
    python scripts/ai_agent/phase5.py input results/dev/ci/findings.sarif --ci-run 43938956025
    python scripts/ai_agent/phase5.py plan triage --rep 1
    LLM_PROVIDER=together LLM_BUDGET_USD=1 python scripts/ai_agent/phase5.py triage --rep 1
    LLM_PROVIDER=together LLM_BUDGET_USD=1 python scripts/ai_agent/phase5.py remediation --rep 1
    python scripts/ai_agent/phase5.py status
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import random
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from sarif_parser import FINGERPRINT_KEY, Finding, SourceReader, parse_sarif, pick_occurrence
from strategies import STRATEGIES

SEED = 20261125
PROVIDER = "together"                       # D12: the whole of Phase 5 on one provider
TAG = "phase5-protocol"
OUT = Path("experiments/phase5")
DEV_OUT = Path("results/dev/phase5")        # git-ignored, for smoke tests before the freeze
INPUT = OUT / "input" / "findings.sarif.gz"
MANIFEST = OUT / "input" / "MANIFEST.json"
LABELS = Path("benchmarks/triage/labels.csv")
TARGETS = Path("benchmarks/remediation-targets.csv")
FROZEN = ("scripts/ai_agent", "benchmarks", "experiments/phase5/input")
TRIAGE, REMEDIATION = "triage", "remediation"
EXPERIMENTS = (TRIAGE, REMEDIATION)
REPS = (1, 2, 3)
CONTEXTS = {"full": (True, True), "blind": (False, True), "norag": (True, False)}
EXIT_INFRA, EXIT_QUOTA, EXIT_BUDGET, EXIT_MODEL = 1, 75, 76, 77


@dataclass(frozen=True)
class Unit:
    """One dataset finding: what the model gets and what it is scored against."""

    id: str             # case id (targets) or bare fingerprint (labels.csv rows)
    fingerprint: str    # bare digest (label_key)
    line: int           # line of the row: picks the SARIF occurrence
    label: str          # ground truth: TP | FP | UNCERTAIN
    group: str          # unit of analysis (D12): vuln_group, or the case id
    source: str         # juice-shop | secbench-js


@dataclass(frozen=True)
class Condition:
    strategy: str
    context: str        # triage: full | blind | norag; remediation: trace | notrace
    with_trace: bool
    with_rag: bool

    @property
    def name(self) -> str:
        return f"{self.strategy}/{self.context}"


def conditions(experiment: str) -> list[Condition]:
    if experiment == TRIAGE:
        return [Condition(s, ctx, t, r) for s in STRATEGIES for ctx, (t, r) in CONTEXTS.items()]
    return [Condition(s, "trace" if t else "notrace", t, True)
            for s in STRATEGIES for t in (True, False)]


def _rows(repo_root: Path, rel: Path) -> list[dict]:
    with (repo_root / rel).open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def triage_pool(repo_root: Path) -> list[Unit]:
    """labels.csv rows plus the SecBench.js targets (TP with exploit) not already in it."""
    units = [Unit(r["fingerprint"], r["fingerprint"], int(r["line"]), r["label"].upper(),
                  r["vuln_group"], r["source"]) for r in _rows(repo_root, LABELS)]
    labelled = {u.fingerprint for u in units}
    units += [Unit(r["id"], r["fingerprint"], int(r["line"]), "TP", r["id"], r["source"])
              for r in _rows(repo_root, TARGETS) if r["fingerprint"] not in labelled]
    if len({u.fingerprint for u in units}) != len(units):
        raise SystemExit("triage pool: duplicated fingerprint")
    return sorted(units, key=lambda u: u.id)


def remediation_pool(repo_root: Path) -> list[Unit]:
    return sorted((Unit(r["id"], r["fingerprint"], int(r["line"]), "TP", r["id"], r["source"])
                   for r in _rows(repo_root, TARGETS)), key=lambda u: u.id)


def pool(experiment: str, repo_root: Path) -> list[Unit]:
    return triage_pool(repo_root) if experiment == TRIAGE else remediation_pool(repo_root)


def schedule(units: list[Unit], conds: list[Condition], experiment: str,
             rep: int) -> list[tuple[Unit, Condition]]:
    """Randomised complete blocks: shuffled units, each with all conditions shuffled."""
    rng = random.Random(f"{SEED}/{experiment}/p{rep}")   # str seed: sha512, platform-stable
    order = sorted(units, key=lambda u: u.id)
    rng.shuffle(order)
    plan = []
    for unit in order:
        conds_here = sorted(conds, key=lambda c: c.name)
        rng.shuffle(conds_here)
        plan += [(unit, c) for c in conds_here]
    return plan


def resolve(units: list[Unit], findings: list[Finding]) -> dict[str, Finding]:
    """unit id -> the SARIF finding the model sees; every unit must have a trace."""
    out, problems = {}, []
    for u in units:
        f = pick_occurrence(findings, u.fingerprint, u.line)
        if f is None:
            problems.append(f"{u.id}: not in the SARIF")
        elif not f.has_trace:
            problems.append(f"{u.id}: no taint trace")
        else:
            out[u.id] = f
    if problems:
        raise SystemExit("input SARIF does not cover the pool:\n  - " + "\n  - ".join(problems))
    return out


# --------------------------------------------------------------------------- input

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reduce_sarif(sarif: dict, keys: set[str]) -> dict:
    """Keep only the results whose digest is in ``keys`` (all their occurrences, in
    order) and the rules they use; drop the invocations and artifact tables, which
    the parser does not read."""
    runs = []
    for run in sarif.get("runs", []):
        results = [r for r in run.get("results", [])
                   if r.get("partialFingerprints", {}).get(FINGERPRINT_KEY, "").split(":")[0] in keys]
        if not results:
            continue
        used = {r.get("ruleId") or r.get("rule", {}).get("id") for r in results}
        tool = json.loads(json.dumps(run.get("tool", {})))
        for comp in [tool.get("driver", {})] + tool.get("extensions", []):
            if "rules" in comp:
                comp["rules"] = [x for x in comp["rules"] if x.get("id") in used]
        kept = {k: v for k, v in run.items() if k not in ("results", "tool", "invocations", "artifacts")}
        runs.append({**kept, "tool": tool, "results": results})
    return {k: v for k, v in sarif.items() if k != "runs"} | {"runs": runs}


def _same_findings(a: list[Finding], b: list[Finding], units: list[Unit],
                   reader: SourceReader) -> list[str]:
    """Units whose finding or rendered context differs between two SARIFs."""
    from trace_context import render_context

    bad = []
    for u in units:
        fa, fb = pick_occurrence(a, u.fingerprint, u.line), pick_occurrence(b, u.fingerprint, u.line)
        if fa is None or fb is None or fa.as_dict() != fb.as_dict():
            bad.append(u.id)
            continue
        for t, r in ((True, True), (False, True), (True, False), (False, False)):
            if render_context(fa, reader, t, r) != render_context(fb, reader, t, r):
                bad.append(u.id)
                break
    return bad


def make_input(full: Path, repo_root: Path, ci_run: str) -> None:
    raw = full.read_bytes()
    units = triage_pool(repo_root) + remediation_pool(repo_root)
    keys = {u.fingerprint for u in units}
    reduced = reduce_sarif(json.loads(raw.decode("utf-8")), keys)
    content = json.dumps(reduced, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    out = repo_root / INPUT
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(gzip.compress(content, mtime=0))        # mtime=0: reproducible bytes

    reader = SourceReader(repo_root)
    bad = _same_findings(parse_sarif(full, repo_root), parse_sarif(out, repo_root), units, reader)
    if bad:
        out.unlink()
        raise SystemExit(f"the reduced SARIF changes what the model sees for: {', '.join(bad)}")
    manifest = {
        "source": {"ci_run": ci_run, "artifact": "unified-findings", "file": "findings.sarif",
                   "sha256": _sha256(raw), "bytes": len(raw)},
        "file": INPUT.name, "content_sha256": _sha256(content), "bytes": out.stat().st_size,
        "results": sum(len(r["results"]) for r in reduced["runs"]),
        "triage_units": len(triage_pool(repo_root)),
        "remediation_units": len(remediation_pool(repo_root)),
        "check": "pick_occurrence + render_context identical to the full SARIF for every unit",
    }
    (repo_root / MANIFEST).write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    print(f"{INPUT}: {manifest['results']} results, {manifest['bytes']} bytes "
          f"(from {len(raw)}); identical context for {len(units)} units")


def check_input(repo_root: Path, path: Path) -> str:
    """Content hash of the input, checked against the MANIFEST when it is the frozen one."""
    raw = (repo_root / path).read_bytes()
    content = gzip.decompress(raw) if path.suffix == ".gz" else raw
    digest = _sha256(content)
    if path == INPUT:
        expected = json.loads((repo_root / MANIFEST).read_text(encoding="utf-8"))["content_sha256"]
        if digest != expected:
            raise SystemExit(f"{INPUT} does not match its MANIFEST (content_sha256)")
    return digest


# -------------------------------------------------------------------------- freeze

def _git(repo_root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo_root, text=True, capture_output=True)


def freeze_problems(repo_root: Path) -> tuple[list[str], str | None]:
    """(problems, protocol commit): the tag exists and nothing frozen changed since it."""
    tag = _git(repo_root, "rev-parse", "--verify", "--quiet", f"{TAG}^{{commit}}")
    if tag.returncode != 0:
        return [f"tag {TAG} does not exist: the protocol is not frozen yet (use --dev)"], None
    commit = tag.stdout.strip()
    problems = []
    if _git(repo_root, "diff", "--quiet", commit, "HEAD", "--", *FROZEN).returncode != 0:
        problems.append(f"{', '.join(FROZEN)} changed since {TAG}: an official run must use "
                        "the frozen code, benchmark and input (D12)")
    dirty = _git(repo_root, "status", "--porcelain", "--", *FROZEN).stdout.strip()
    if dirty:
        problems.append("uncommitted changes under " + ", ".join(FROZEN) + ":\n" + dirty)
    return problems, commit


# ----------------------------------------------------------------------------- run

class ModelChanged(Exception):
    pass


def _check_served(rec: dict, expected: str) -> None:
    served = rec.get("model_served")
    if served and served != expected:
        raise ModelChanged(f"the API served {served!r} instead of {expected!r} "
                           f"({rec['fingerprint'][:8]}, {rec['strategy']})")


def log_path(out: Path, experiment: str, rep: int) -> Path:
    return out / f"{experiment}-p{rep}.jsonl"


def _spent(log, provider) -> float:
    return sum(provider.cost(r.get("prompt_tokens") or 0, r.get("completion_tokens") or 0)
               for r in log.records() if r.get("provider", "groq") == provider.name)


def _done(log, experiment: str, unit_fp: str, cond: Condition, rep: int) -> bool:
    from results import REMEDIATION as REM, TRIAGE as TRI, RunKey, loop_outcome

    if experiment == TRIAGE:
        return log.done(RunKey(TRI, unit_fp, cond.strategy, cond.with_trace, cond.with_rag, 1, rep))
    attempts = [log.get(RunKey(REM, unit_fp, cond.strategy, cond.with_trace, cond.with_rag, n, rep))
                for n in (1, 2, 3)]
    attempts = [a for a in attempts if a]
    return bool(attempts) and loop_outcome(attempts)[0] != "INCOMPLETE"


def run(experiment: str, rep: int, repo_root: Path, *, dev: bool, sarif: Path,
        limit: int | None, codeql: str | None, no_oracles: bool) -> int:
    from groq_client import GroqClient, GroqQuotaExhausted, LLMBudgetExceeded, current_provider
    from results import ResultLog, environment
    from run_dataset import llm_problems

    problems = llm_problems()
    provider = current_provider() if not problems else None
    protocol = None
    if not dev:
        if provider is not None and provider.name != PROVIDER:
            problems.append(f"official runs use LLM_PROVIDER={PROVIDER} (D12), not {provider.name}")
        if sarif != INPUT:
            problems.append(f"official runs read the frozen input {INPUT}")
        if limit:
            problems.append("--limit is for --dev smoke tests only")
        frozen, protocol = freeze_problems(repo_root)
        problems += frozen
    input_sha = check_input(repo_root, sarif)
    units = pool(experiment, repo_root)
    findings = resolve(units, parse_sarif(repo_root / sarif, repo_root))
    plan = schedule(units, conditions(experiment), experiment, rep)
    if limit:
        keep = {u.id for u, _ in plan[:: len(conditions(experiment))][:limit]}
        plan = [(u, c) for u, c in plan if u.id in keep]

    cli = checks = None
    if experiment == REMEDIATION and not problems:
        from repair_loop import oracle_checks
        from run_dataset import load_cases, preflight
        cases = [c for c in load_cases(repo_root, list(findings.values()), None)]
        cli = preflight(repo_root, cases, not no_oracles, codeql)   # raises with its own list
        checks = None if no_oracles else oracle_checks(repo_root)
    if problems:
        raise SystemExit("preflight failed:\n  - " + "\n  - ".join(problems))

    out = DEV_OUT if dev else OUT
    path = log_path(repo_root / out, experiment, rep)
    from rescan import codeql_version
    env = environment(repo_root, codeql_version(cli) if cli else None, experiment=experiment, input_sha256=input_sha, protocol_commit=protocol,
                      dev=dev)
    log = ResultLog(path, env)
    if log.repaired:
        print(f"(repaired {log.repaired} truncated line(s) in {path})")
    if not dev:
        foreign = {r.get("protocol_commit") for r in log.records()} - {protocol}
        if foreign:
            raise SystemExit(f"{path} has rows from another protocol commit: {foreign}")
    client = GroqClient(spent=_spent(log, provider))
    if client.budget is not None:
        print(f"spend cap ${client.budget:.2f} ({provider.name}); already spent in this log "
              f"~${client.spent:.4f} at list price", flush=True)

    base = protocol or "HEAD"
    reader = SourceReader(repo_root)
    todo = [(u, c) for u, c in plan if not _done(log, experiment, u.fingerprint, c, rep)]
    print(f"{experiment} pass {rep}: {len(plan) - len(todo)}/{len(plan)} done, "
          f"{len(todo)} to go -> {path}", flush=True)
    start, code, note = time.monotonic(), 0, ""
    try:
        for i, (unit, cond) in enumerate(todo, 1):
            print(f"[{i}/{len(todo)}] {unit.id[:40]} {cond.name}", end=" ... ", flush=True)
            if experiment == TRIAGE:
                from triage_engine import triage_logged
                rec, _ = triage_logged(findings[unit.id], client, reader, log, cond.strategy,
                                       cond.with_trace, cond.with_rag, rep=rep)
                _check_served(rec, provider.model)
                print(rec["verdict"], flush=True)
            else:
                from repair_loop import repair
                loop = repair(findings[unit.id], client, repo_root, reader=reader,
                              strategy=cond.strategy, with_trace=cond.with_trace,
                              with_rag=cond.with_rag, base=base, log=log, cli=cli,
                              checks=checks, rep=rep)
                for a in loop.attempts:
                    _check_served(a.record, provider.model)
                print(f"{loop.outcome} in {loop.iterations}", flush=True)
    except GroqQuotaExhausted as err:
        code, note = EXIT_QUOTA, f"provider quota exhausted ({err}); relaunch later"
    except LLMBudgetExceeded as err:
        code, note = EXIT_BUDGET, f"spend cap reached ({err}); check the spend, raise it, relaunch"
    except ModelChanged as err:
        code, note = EXIT_MODEL, (f"STOP: {err}. D12: the affected experiment is repeated; "
                                  "do not relaunch before deciding")
    except KeyboardInterrupt:
        code, note = 130, "interrupted by hand; relaunch to resume"
    except Exception as err:                # infra: Docker, CodeQL, network (attempt not logged)
        code, note = EXIT_INFRA, f"infrastructure failure: {err}; relaunch to resume"
    left = sum(not _done(log, experiment, u.fingerprint, c, rep) for u, c in plan)
    print(f"\n{len(plan) - left}/{len(plan)} done in {time.monotonic() - start:.0f} s; "
          f"~${client.spent:.4f} spent in this log")
    if note:
        print(note)
    return code


# -------------------------------------------------------------------------- status

def status(repo_root: Path, out: Path) -> str:
    from results import ResultLog

    lines = ["| Log | Unidades × condiciones hechas | Llamadas | Tokens (in+out) | Coste lista | "
             "Modelo servido | Proveedor |", "|---|---|---|---|---|---|---|"]
    for experiment in EXPERIMENTS:
        units = pool(experiment, repo_root)
        conds = conditions(experiment)
        for rep in REPS:
            path = log_path(repo_root / out, experiment, rep)
            if not path.is_file():
                continue
            log = ResultLog(path)
            recs = log.records()
            done = sum(_done(log, experiment, u.fingerprint, c, rep) for u in units for c in conds)
            tin = sum(r.get("prompt_tokens") or 0 for r in recs)
            tout = sum(r.get("completion_tokens") or 0 for r in recs)
            served = Counter(r.get("model_served") for r in recs)
            prov = Counter(r.get("provider") for r in recs)
            lines.append(f"| {path.name} | {done}/{len(units) * len(conds)} | {len(recs)} | "
                         f"{tin}+{tout} | ${tin * 0.15e-6 + tout * 0.6e-6:.3f} | "
                         f"{', '.join(f'{k} ({v})' for k, v in served.items())} | "
                         f"{', '.join(f'{k} ({v})' for k, v in prov.items())} |")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("input", help="write the reduced, versioned input SARIF + MANIFEST")
    p.add_argument("sarif", type=Path, help="unified SARIF of the CI run (artifact unified-findings)")
    p.add_argument("--ci-run", required=True, help="GitHub Actions run id it comes from")
    p = sub.add_parser("plan", help="print the execution order of a pass")
    p.add_argument("experiment", choices=EXPERIMENTS)
    p.add_argument("--rep", type=int, choices=REPS, required=True)
    for name in EXPERIMENTS:
        p = sub.add_parser(name, help=f"run one pass of the {name} experiment")
        p.add_argument("--rep", type=int, choices=REPS, required=True)
        p.add_argument("--dev", action="store_true",
                       help=f"smoke test before the freeze: any provider/input, logs in {DEV_OUT}")
        p.add_argument("--sarif", type=Path, default=INPUT)
        p.add_argument("--limit", type=int, help="--dev only: first N units of the plan")
        if name == REMEDIATION:
            p.add_argument("--codeql", help="CodeQL CLI (default: $CODEQL_CLI or PATH)")
            p.add_argument("--no-oracles", action="store_true", help="--dev only: CodeQL alone")
    p = sub.add_parser("status", help="progress of every log")
    p.add_argument("--dev", action="store_true")
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()

    if args.cmd == "input":
        make_input(args.sarif, repo_root, args.ci_run)
    elif args.cmd == "plan":
        plan = schedule(pool(args.experiment, repo_root), conditions(args.experiment),
                        args.experiment, args.rep)
        for i, (u, c) in enumerate(plan, 1):
            print(f"{i}\t{u.id}\t{c.name}")
    elif args.cmd == "status":
        print(status(repo_root, DEV_OUT if args.dev else OUT))
    else:
        if getattr(args, "no_oracles", False) and not args.dev:
            raise SystemExit("--no-oracles is for --dev runs only (D9 oracles are part of D12)")
        sys.exit(run(args.cmd, args.rep, repo_root, dev=args.dev, sarif=args.sarif,
                     limit=args.limit, codeql=getattr(args, "codeql", None),
                     no_oracles=getattr(args, "no_oracles", False)))


if __name__ == "__main__":
    main()
