"""Provider pilot: does another provider serve gpt-oss-120b like Groq does?

Branch ``exp/proveedor-piloto``; criteria fixed beforehand in
``docs/benchmark/piloto-proveedor.md``. Compares the JSONL logs of
``run_dataset.py`` (same condition: 33 cases, one strategy/trace/RAG) between a
reference group A (Groq) and a candidate group B (the new provider), each with
two runs. The model is not deterministic, so "the same" means: **B differs from
A no more than each provider differs from itself**. A within-group agreement is
the noise floor; the cross-group agreement (mean of every A x B pair) must not
fall below it by more than the tolerance.

Criteria (thresholds below, identical to the document):

- C1 same input: per matched call (triage, and remediation attempt 1, whose
  prompt does not depend on earlier replies), the prompt-token difference B - A
  is constant (>= 95 % of the calls within +/-2 of the most common offset; the
  offset is the provider's chat template) and the served model is gpt-oss-120b.
- C2 triage: cross verdict agreement >= within-A agreement - 2 cases.
- C3 remediation: mean ACCEPTED of B within +/-3 of A, and cross per-case outcome
  agreement (ACCEPTED or not) >= within-A agreement - 3 cases.
- C4 format: mean format failures (triage reply without a valid JSON verdict;
  remediation NO_DIFF; any other reply cut by max_tokens) of B <= A + 2.
- C5 reasoning: median completion tokens per triage call of B within x0.5-x2 of A
  (reasoning tokens are part of the completion; a different effort level shows here).
- C6 operational (manual): no blocking failure, real cost from the provider's
  dashboard within the estimate, data policy acceptable.

Usage:
    python scripts/ai_agent/pilot_compare.py \
        --a groq-1=results/dev/pilot-groq-1.jsonl --a groq-2=results/dev/pilot-groq-2.jsonl \
        --b together-1=results/dev/pilot-together-1.jsonl --b together-2=results/dev/pilot-together-2.jsonl \
        [--out results/dev/pilot-report.md]
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import statistics
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from results import REMEDIATION, TRIAGE, loop_outcome, loops

C1_SHARE, C1_SLACK = 0.95, 2
C2_TOL = 2
C3_COUNT_TOL, C3_AGREE_TOL = 3, 3
C4_TOL = 2
C5_LOW, C5_HIGH = 0.5, 2.0

VERDICTS = ("TP", "FP", "UNCERTAIN")


@dataclass
class Run:
    label: str
    path: Path
    records: list[dict]
    triage: dict[str, dict] = field(default_factory=dict)        # fp -> record
    first_fix: dict[str, dict] = field(default_factory=dict)     # fp -> remediation attempt 1
    outcome: dict[str, str] = field(default_factory=dict)        # fp -> ACCEPTED|ESCALATED|...
    conditions: set = field(default_factory=set)

    @property
    def provider(self) -> str:
        names = {r.get("provider", "groq") for r in self.records}
        return ",".join(sorted(names))

    @property
    def effort(self) -> str:
        return ",".join(sorted({r.get("reasoning_effort", "provider-default") for r in self.records}))


def load(spec: str) -> Run:
    label, _, path = spec.partition("=")
    if not path:
        raise SystemExit(f"--a/--b expects label=path, got {spec!r}")
    p = Path(path)
    records = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
    run = Run(label, p, records)
    for r in records:
        run.conditions.add((r["strategy"], r["with_trace"], r["with_rag"]))
        if r["kind"] == TRIAGE:
            run.triage[r["fingerprint"]] = r
        elif r["kind"] == REMEDIATION and r.get("attempt") == 1:
            run.first_fix[r["fingerprint"]] = r
    for (fp, *_), attempts in loops(records).items():
        run.outcome[fp] = loop_outcome(attempts)[0]
    for fp in run.triage:                       # gated run: no loop when the triage said no
        run.outcome.setdefault(fp, "NOT_REPAIRED")
    return run


def format_failure(rec: dict) -> bool:
    """Triage reply without a parseable JSON verdict (parse_verdict fell back)."""
    m = re.search(r"\{.*\}", rec.get("raw") or "", re.DOTALL)
    if not m:
        return True
    try:
        return str(json.loads(m.group(0)).get("verdict", "")).upper().strip() not in VERDICTS
    except (ValueError, TypeError, AttributeError):
        return True


def truncated(run: Run) -> int:
    """Replies cut by max_tokens (finish_reason 'length'); logs before the pilot lack the field."""
    return sum(r.get("finish_reason") == "length" for r in run.records)


def failures(run: Run) -> int:
    """Format failures: triage without a JSON verdict, remediation without a diff, and
    any reply cut by max_tokens that was not already counted as one of those."""
    tri_bad = {fp for fp, r in run.triage.items() if format_failure(r)}
    rem_bad = [r for r in run.records if r["kind"] == REMEDIATION and r.get("status") == "NO_DIFF"]
    cut_other = [r for r in run.records if r.get("finish_reason") == "length"
                 and not (r["kind"] == TRIAGE and r["fingerprint"] in tri_bad)
                 and not (r["kind"] == REMEDIATION and r.get("status") == "NO_DIFF")]
    return len(tri_bad) + len(rem_bad) + len(cut_other)


def agreement(x: dict, y: dict, key=lambda v: v) -> tuple[int, int]:
    common = sorted(set(x) & set(y))
    return sum(key(x[k]) == key(y[k]) for k in common), len(common)


def verdicts(run: Run) -> dict:
    return {fp: r["verdict"] for fp, r in run.triage.items()}


def accepted(run: Run) -> dict:
    return {fp: o == "ACCEPTED" for fp, o in run.outcome.items()}


def mean_pairs(pairs) -> float | None:
    vals = [a for a, n in pairs if n]
    return statistics.mean(vals) if vals else None


def prompt_offsets(a: Run, b: Run) -> tuple[int | None, float, int]:
    """(most common offset, share within slack, matched calls) of B - A prompt tokens."""
    diffs = []
    for src_a, src_b in ((a.triage, b.triage), (a.first_fix, b.first_fix)):
        for fp in set(src_a) & set(src_b):
            diffs.append((src_b[fp].get("prompt_tokens") or 0) - (src_a[fp].get("prompt_tokens") or 0))
    if not diffs:
        return None, 0.0, 0
    offset = Counter(diffs).most_common(1)[0][0]
    share = sum(abs(d - offset) <= C1_SLACK for d in diffs) / len(diffs)
    return offset, share, len(diffs)


def median_completion(run: Run) -> float:
    vals = [r.get("completion_tokens") or 0 for r in run.triage.values()]
    return statistics.median(vals) if vals else 0.0


def cost(run: Run) -> float:
    from groq_client import PROVIDERS
    provider = PROVIDERS.get(run.provider, PROVIDERS["groq"])
    return sum(provider.cost(r.get("prompt_tokens") or 0, r.get("completion_tokens") or 0)
               for r in run.records)


def fmt(x, digits=1) -> str:
    return "—" if x is None else f"{x:.{digits}f}"


def case_names(repo_root: Path) -> dict[str, str]:
    """fingerprint -> case id, from the pre-registered targets (fingerprints not there keep theirs)."""
    import csv
    path = repo_root / "benchmarks" / "remediation-targets.csv"
    if not path.is_file():
        return {}
    return {r["fingerprint"]: r["id"] for r in csv.DictReader(path.open(encoding="utf-8"))}


def compare(A: list[Run], B: list[Run],
            names: dict[str, str] | None = None) -> tuple[str, dict[str, bool | None]]:
    names = names or {}
    conds = set().union(*(r.conditions for r in A + B))
    if len(conds) != 1:
        raise SystemExit(f"logs mix conditions {sorted(conds)}: compare one condition at a time")
    lines = ["# Piloto de proveedor: comparación", "",
             f"- Condición: estrategia `{next(iter(conds))[0]}`, traza {next(iter(conds))[1]}, "
             f"RAG {next(iter(conds))[2]}",
             f"- Grupo A (referencia): " + ", ".join(f"{r.label} ({r.provider}, effort {r.effort})" for r in A),
             f"- Grupo B (candidato): " + ", ".join(f"{r.label} ({r.provider}, effort {r.effort})" for r in B),
             "", "## Por ejecución", "",
             "| Ejecución | Triajes | Bucles | ACCEPTED | Fallos de formato | Cortadas por max_tokens | "
             "Mediana tokens salida (triaje) | Razonamiento informado | Caché informada | "
             "LLM s (mediana) | Coste estimado |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in A + B:
        calls = [x for x in r.records if x["kind"] in (TRIAGE, REMEDIATION) and "prompt_tokens" in x]
        reas = sum(x.get("reasoning_tokens") is not None for x in calls)
        cach = sum(x.get("cached_tokens") is not None for x in calls)
        secs = [x.get("llm_seconds") or 0 for x in calls]
        lines.append(f"| {r.label} | {len(r.triage)} | {len(loops(r.records))} | "
                     f"{sum(accepted(r).values())} | {failures(r)} | {truncated(r)} | "
                     f"{median_completion(r):.0f} | "
                     f"{reas}/{len(calls)} | {cach}/{len(calls)} | "
                     f"{statistics.median(secs) if secs else 0:.1f} | ${cost(r):.3f} |")

    verdict: dict[str, bool | None] = {}
    within = lambda runs, f: mean_pairs(agreement(f(x), f(y)) for x, y in itertools.combinations(runs, 2))
    cross = lambda f: mean_pairs(agreement(f(x), f(y)) for x, y in itertools.product(A, B))
    n_tri = max((len(r.triage) for r in A + B), default=0)

    # C1
    offs = [(x.label, y.label, *prompt_offsets(x, y)) for x, y in itertools.product(A, B)]
    served = {x.get("model_served") or "?" for r in A + B for x in r.records if "model_served" in x}
    c1 = bool(offs) and all(share >= C1_SHARE for *_, share, n in offs if n) and \
        all("gpt-oss-120b" in m for m in served)
    verdict["C1"] = c1
    lines += ["", "## Criterios", "",
              f"**C1 — misma entrada** ({'cumple' if c1 else 'NO cumple'}). Modelo servido: "
              f"{', '.join(sorted(served))}."]
    for la, lb, off, share, n in offs:
        lines.append(f"- {lb} − {la}: desfase más común {off} tokens; {share:.0%} de {n} llamadas "
                     f"a ±{C1_SLACK} (mínimo {C1_SHARE:.0%})")
    for grp in (A, B):
        for x, y in itertools.combinations(grp, 2):
            off, share, n = prompt_offsets(x, y)
            lines.append(f"- control dentro del grupo {y.label} − {x.label}: desfase {off}, "
                         f"{share:.0%} de {n}")

    # C2
    wa, wb, cr = within(A, verdicts), within(B, verdicts), cross(verdicts)
    c2 = None if wa is None or cr is None else cr >= wa - C2_TOL
    verdict["C2"] = c2
    lines += ["", f"**C2 — triaje** ({'cumple' if c2 else 'sin datos' if c2 is None else 'NO cumple'}). "
              f"Veredictos iguales (de {n_tri}): dentro de A {fmt(wa)}, dentro de B {fmt(wb)}, "
              f"entre A y B {fmt(cr)} (mínimo: dentro de A − {C2_TOL})."]

    # C3
    acc_a = statistics.mean(sum(accepted(r).values()) for r in A) if A else None
    acc_b = statistics.mean(sum(accepted(r).values()) for r in B) if B else None
    wa3, wb3, cr3 = within(A, accepted), within(B, accepted), cross(accepted)
    c3 = None if None in (acc_a, acc_b, wa3, cr3) else (
        abs(acc_b - acc_a) <= C3_COUNT_TOL and cr3 >= wa3 - C3_AGREE_TOL)
    verdict["C3"] = c3
    lines += ["", f"**C3 — remediación** ({'cumple' if c3 else 'sin datos' if c3 is None else 'NO cumple'}). "
              f"ACCEPTED medio: A {fmt(acc_a)}, B {fmt(acc_b)} (máx. ±{C3_COUNT_TOL}). "
              f"Resultado igual por caso: dentro de A {fmt(wa3)}, dentro de B {fmt(wb3)}, "
              f"entre A y B {fmt(cr3)} (mínimo: dentro de A − {C3_AGREE_TOL})."]

    # C4
    fa = statistics.mean(failures(r) for r in A) if A else None
    fb = statistics.mean(failures(r) for r in B) if B else None
    c4 = None if None in (fa, fb) else fb <= fa + C4_TOL
    verdict["C4"] = c4
    lines += ["", f"**C4 — formato** ({'cumple' if c4 else 'sin datos' if c4 is None else 'NO cumple'}). "
              f"Fallos medios: A {fmt(fa)}, B {fmt(fb)} (máx. A + {C4_TOL})."]

    # C5
    ma = statistics.mean(median_completion(r) for r in A) if A else 0
    mb = statistics.mean(median_completion(r) for r in B) if B else 0
    ratio = mb / ma if ma else None
    c5 = None if ratio is None else C5_LOW <= ratio <= C5_HIGH
    verdict["C5"] = c5
    lines += ["", f"**C5 — razonamiento** ({'cumple' if c5 else 'sin datos' if c5 is None else 'NO cumple'}). "
              f"Mediana de tokens de salida por triaje: A {ma:.0f}, B {mb:.0f}; razón B/A {fmt(ratio, 2)} "
              f"(rango {C5_LOW}–{C5_HIGH})."]

    verdict["C6"] = None
    lines += ["", "**C6 — operativo** (manual): fallos que bloquearon el lote, coste real del panel "
              "del proveedor frente al estimado de la tabla, política de datos."]

    # disagreements, for reading the cases behind the numbers
    fps = sorted(set().union(*(r.outcome.keys() for r in A + B)), key=lambda fp: names.get(fp, fp))
    rows = []
    for fp in fps:
        v = [verdicts(r).get(fp, "—") for r in A + B]
        o = [r.outcome.get(fp, "—") for r in A + B]
        if len(set(v)) > 1 or len(set(o)) > 1:
            rows.append(f"| `{names.get(fp, fp[:12])}` | "
                        + " | ".join(f"{a} / {b}" for a, b in zip(v, o)) + " |")
    lines += ["", "## Casos con alguna diferencia (veredicto / resultado)", ""]
    if rows:
        lines += ["| Caso | " + " | ".join(r.label for r in A + B) + " |",
                  "|---|" + "---|" * len(A + B)] + rows
    else:
        lines.append("Ninguno.")
    auto = [k for k in ("C1", "C2", "C3", "C4", "C5")]
    ok = all(verdict[k] for k in auto)
    lines += ["", "## Resultado", "",
              ("C1–C5 se cumplen: queda revisar C6 a mano." if ok else
               "No se cumplen: " + ", ".join(k for k in auto if not verdict[k]) + ".")]
    return "\n".join(lines) + "\n", verdict


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--a", action="append", required=True, help="reference run label=log.jsonl")
    parser.add_argument("--b", action="append", required=True, help="candidate run label=log.jsonl")
    parser.add_argument("--out", type=Path, help="write the markdown report here")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    args = parser.parse_args()
    md, verdict = compare([load(s) for s in args.a], [load(s) for s in args.b],
                          case_names(args.repo_root))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(md, encoding="utf-8")
        print(f"report: {args.out}")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(md)
    sys.exit(0 if all(verdict[k] for k in ("C1", "C2", "C3", "C4", "C5")) else 1)


if __name__ == "__main__":
    main()
