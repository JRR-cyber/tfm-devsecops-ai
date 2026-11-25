"""Phase 5 analysis (D12): research questions PI1-PI5, descriptives, sensitivity.

Pre-registered with the protocol (D12) and tested on simulated data before the
first real call (``selftest``). It reads the logs written by ``phase5.py`` and
writes a markdown report. Nothing here is tuned to the real results: the tests,
the unit of analysis, the corrections and the sensitivity analyses are fixed.

**Unit scores.** Triage: each vulnerability (``vuln_group``; 69 TP + FP groups)
scores the share of its rows x passes the agent gets right ("right" = says TP iff
the label is TP; an UNCERTAIN answer counts as "not TP", as in production).
Remediation: each case scores the share of passes whose loop is ACCEPTED.

**Research questions** (alpha = 0.05, Holm within each question):

- PI1 does the taint trace improve the triage?  full vs blind, Wilcoxon per strategy.
- PI2 which strategy triages best?  Friedman (full context); if significant,
  pairwise Wilcoxon.
- PI3 which strategy remediates best?  Friedman (with trace); if significant,
  pairwise Wilcoxon.
- PI4 does the trace improve the remediation?  trace vs no trace, Wilcoxon per strategy.
- PI5 does the RAG improve the triage?  full vs norag, Wilcoxon per strategy.

Wilcoxon signed-rank: zeros dropped (Wilcoxon's method), **exact** two-sided p from
the sign-flip distribution of the tied ranks. Friedman: tie-corrected statistic,
chi-square p (df = 2). Effect sizes: Kendall's W, matched-pairs rank-biserial r,
mean difference with a 95 % percentile bootstrap CI over units (10 000 resamples).

**Secondary**: the same triage tests on the FP groups (FPR component) and on the TP
groups (TPR component). **Sensitivity**: pass 1 alone and binary (Cochran's Q,
exact McNemar; triage groups by the production rule "any row TP"); triage per row
(83) instead of per group; UNCERTAIN groups counted as TP and as FP (PI1).
**Exploratory**: memorisation control (blind-context accuracy, Juice Shop vs
SecBench.js, Mann-Whitney with a permutation p).

Usage:
    python scripts/ai_agent/phase5_analysis.py analyze [--dir experiments/phase5] [--out .../analysis.md]
    python scripts/ai_agent/phase5_analysis.py simulate --scenario null|effect --out results/dev/phase5-sim
    python scripts/ai_agent/phase5_analysis.py selftest
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, median

from phase5 import (CONTEXTS, EXPERIMENTS, REMEDIATION, REPS, SEED, TARGETS, TRIAGE,
                    remediation_pool, triage_pool)
from strategies import STRATEGIES

ALPHA = 0.05
BOOT = 10_000
EXPLOIT = {"secbench-exploit", "juice-shop-exploit"}
FUNCTIONAL = {"secbench-t1-suite", "secbench-t2-differential", "juice-shop-functional"}
CTX_OF = {flags: name for name, flags in CONTEXTS.items()}     # (trace, rag) -> context


# =========================================================================== statistics

def average_ranks(values: list[float]) -> list[float]:
    """1-based ranks, ties get the average of the positions they span."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for t in range(i, j + 1):
            ranks[order[t]] = (i + j) / 2 + 1
        i = j + 1
    return ranks


def _tie_sizes(values: list[float]) -> list[int]:
    return [n for n in Counter(values).values() if n > 1]


def chi2_sf(x: float, df: int) -> float:
    """Upper tail of chi-square for an even df (closed form); df = 2 here."""
    if df % 2:
        raise ValueError("only even degrees of freedom are needed (k = 3 conditions)")
    if x <= 0:
        return 1.0
    half = x / 2
    return min(1.0, math.exp(-half) * sum(half ** i / math.factorial(i) for i in range(df // 2)))


@dataclass
class Wilcoxon:
    n: int                 # units with a non-zero difference
    t_plus: float
    t_minus: float
    p: float
    r: float               # matched-pairs rank-biserial
    diff: float            # mean(a) - mean(b), zeros included
    ci: tuple[float, float]


def wilcoxon(a: list[float], b: list[float], ci: bool = True) -> Wilcoxon:
    """Paired signed-rank test, exact p under random sign flips of the tied ranks."""
    d = [x - y for x, y in zip(a, b)]
    nz = [x for x in d if abs(x) > 1e-12]
    diff = mean(d) if d else 0.0
    ci = bootstrap_ci(d) if ci else (float("nan"), float("nan"))
    if not nz:
        return Wilcoxon(0, 0.0, 0.0, 1.0, 0.0, diff, ci)
    ranks2 = [round(2 * r) for r in average_ranks([abs(x) for x in nz])]   # half-ranks -> ints
    t_plus2 = sum(r for r, x in zip(ranks2, nz) if x > 0)
    total2 = sum(ranks2)
    dist = [1.0] + [0.0] * total2            # P(sum of a random subset of ranks2 = s)
    for r in ranks2:
        shifted = [0.0] * r + dist[:-r]
        dist = [0.5 * (u + v) for u, v in zip(dist, shifted)]
    centre = total2 / 2
    dev = abs(t_plus2 - centre)
    p = sum(prob for s, prob in enumerate(dist) if abs(s - centre) >= dev - 1e-9)
    t_plus, t_minus = t_plus2 / 2, (total2 - t_plus2) / 2
    return Wilcoxon(len(nz), t_plus, t_minus, min(1.0, p), (t_plus - t_minus) / (total2 / 2),
                    diff, ci)


@dataclass
class Friedman:
    n: int
    q: float
    p: float
    w: float               # Kendall's W
    mean_ranks: list[float]


def friedman(blocks: list[tuple[float, ...]]) -> Friedman:
    n, k = len(blocks), len(blocks[0]) if blocks else 0
    if n == 0:
        return Friedman(0, 0.0, 1.0, 0.0, [])
    totals, ties = [0.0] * k, 0
    for b in blocks:
        for j, r in enumerate(average_ranks(list(b))):
            totals[j] += r
        ties += sum(t ** 3 - t for t in _tie_sizes(list(b)))
    num = 12 / (n * k * (k + 1)) * sum(t * t for t in totals) - 3 * n * (k + 1)
    den = 1 - ties / (n * k * (k * k - 1))
    q = num / den if den > 1e-12 else 0.0
    return Friedman(n, q, chi2_sf(q, k - 1), q / (n * (k - 1)), [t / n for t in totals])


def cochran_q(blocks: list[tuple[int, ...]]) -> tuple[float, float]:
    """(Q, p) for k related binary samples."""
    if not blocks:
        return 0.0, 1.0
    k = len(blocks[0])
    cols = [sum(b[j] for b in blocks) for j in range(k)]
    rows = [sum(b) for b in blocks]
    total = sum(rows)
    den = k * total - sum(r * r for r in rows)
    if den == 0:
        return 0.0, 1.0
    q = (k - 1) * (k * sum(c * c for c in cols) - total * total) / den
    return q, chi2_sf(q, k - 1)


def mcnemar_exact(a: list[int], b: list[int]) -> tuple[int, int, float]:
    """(a-only, b-only, two-sided exact p)."""
    n10 = sum(1 for x, y in zip(a, b) if x and not y)
    n01 = sum(1 for x, y in zip(a, b) if y and not x)
    n = n10 + n01
    if n == 0:
        return n10, n01, 1.0
    tail = sum(math.comb(n, i) for i in range(min(n10, n01) + 1)) / 2 ** n
    return n10, n01, min(1.0, 2 * tail)


def holm(ps: list[float]) -> list[float]:
    order = sorted(range(len(ps)), key=lambda i: ps[i])
    adj, running = [0.0] * len(ps), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(ps) - rank) * ps[i]))
        adj[i] = running
    return adj


def bootstrap_ci(d: list[float], reps: int = BOOT) -> tuple[float, float]:
    if not d:
        return (0.0, 0.0)
    rng = random.Random(SEED)
    n = len(d)
    means = sorted(sum(d[rng.randrange(n)] for _ in range(n)) / n for _ in range(reps))
    return means[int(0.025 * reps)], means[int(0.975 * reps) - 1]


def mann_whitney(x: list[float], y: list[float], reps: int = 20_000) -> tuple[float, float]:
    """(U of x, two-sided permutation p) — exploratory comparison of independent groups."""
    if not x or not y:
        return 0.0, 1.0
    ranks = average_ranks(x + y)
    nx = len(x)

    def u_of(rs: list[float]) -> float:
        return sum(rs[:nx]) - nx * (nx + 1) / 2
    u = u_of(ranks)
    centre = nx * len(y) / 2
    rng, hits, pool_ = random.Random(SEED), 0, ranks[:]
    for _ in range(reps):
        rng.shuffle(pool_)
        hits += abs(u_of(pool_) - centre) >= abs(u - centre) - 1e-9
    return u, (hits + 1) / (reps + 1)


def fleiss_kappa(ratings: list[list[str]], categories: tuple[str, ...]) -> float:
    """Agreement of the passes on each subject; NaN when every answer is the same."""
    subjects = [r for r in ratings if len(r) >= 2]
    if not subjects:
        return float("nan")
    n = len(subjects[0])
    subjects = [r for r in subjects if len(r) == n]
    counts = [[r.count(c) for c in categories] for r in subjects]
    p_i = [(sum(x * x for x in row) - n) / (n * (n - 1)) for row in counts]
    p_j = [sum(row[j] for row in counts) / (len(counts) * n) for j in range(len(categories))]
    p_e = sum(p * p for p in p_j)
    return float("nan") if p_e >= 1 else (mean(p_i) - p_e) / (1 - p_e)


# ================================================================================ data

def load(directory: Path) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {e: [] for e in EXPERIMENTS}
    for experiment in EXPERIMENTS:
        for rep in REPS:
            path = directory / f"{experiment}-p{rep}.jsonl"
            if path.is_file():
                for line in path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        out[experiment].append(json.loads(line))
    return out


def correct(verdict: str, label: str) -> int:
    return int((verdict == "TP") == (label == "TP"))


class Data:
    """Logs joined with the ground truth."""

    def __init__(self, logs: dict[str, list[dict]], repo_root: Path):
        self.units = triage_pool(repo_root)
        self.cases = remediation_pool(repo_root)
        self.verdict: dict[tuple, str] = {}             # (fp, strategy, ctx, rep) -> verdict
        for r in logs[TRIAGE]:
            ctx = CTX_OF[(bool(r["with_trace"]), bool(r["with_rag"]))]
            self.verdict[(r["fingerprint"], r["strategy"], ctx, r.get("rep", 1))] = r["verdict"]
        self.attempts: dict[tuple, list[dict]] = defaultdict(list)   # (fp, strategy, trace, rep)
        for r in logs[REMEDIATION]:
            self.attempts[(r["fingerprint"], r["strategy"], bool(r["with_trace"]),
                           r.get("rep", 1))].append(r)
        for v in self.attempts.values():
            v.sort(key=lambda a: a["attempt"])
        self.reps = sorted({k[3] for k in self.verdict} | {k[3] for k in self.attempts})
        self.groups: dict[str, list] = defaultdict(list)
        for u in self.units:
            self.groups[u.group].append(u)
        self.logs = logs

    # ---- triage
    def group_label(self, g: str) -> str:
        return self.groups[g][0].label

    def triage_score(self, rows: list, strategy: str, ctx: str, reps: list[int],
                     label: str | None = None) -> float | None:
        vals = [correct(self.verdict[(u.fingerprint, strategy, ctx, r)], label or u.label)
                for u in rows for r in reps if (u.fingerprint, strategy, ctx, r) in self.verdict]
        expected = len(rows) * len(reps)
        return mean(vals) if vals and len(vals) == expected else None

    def group_called_tp(self, g: str, strategy: str, ctx: str, rep: int) -> int | None:
        """Production rule: the group goes to remediation if any of its rows is TP."""
        vs = [self.verdict.get((u.fingerprint, strategy, ctx, rep)) for u in self.groups[g]]
        return None if None in vs else int(any(v == "TP" for v in vs))

    def triage_blocks(self, cells: list[tuple[str, str]], labels: set[str],
                      reps: list[int] | None = None, per_row: bool = False,
                      relabel: str | None = None) -> list[tuple[float, ...]]:
        reps = reps or self.reps
        units = ([[u] for u in self.units] if per_row else list(self.groups.values()))
        blocks = []
        for rows in units:
            label = rows[0].label
            if label == "UNCERTAIN" and relabel:
                label = relabel
            elif label not in labels:
                continue
            if label not in labels:
                continue
            scores = [self.triage_score(rows, s, c, reps, label) for s, c in cells]
            if None not in scores:
                blocks.append(tuple(scores))
        return blocks

    # ---- remediation
    def loop_accepted(self, fp: str, strategy: str, trace: bool, rep: int) -> int | None:
        attempts = self.attempts.get((fp, strategy, trace, rep))
        if not attempts:
            return None
        if any(a.get("accepted") for a in attempts):
            return 1
        last = attempts[-1]
        return 0 if last["attempt"] >= last.get("max_attempts", 3) else None   # incomplete

    def remediation_blocks(self, conds: list[tuple[str, bool]], reps: list[int] | None = None,
                           cases: list | None = None) -> list[tuple[float, ...]]:
        reps = reps or self.reps
        blocks = []
        for c in cases or self.cases:
            row = []
            for s, t in conds:
                vals = [self.loop_accepted(c.fingerprint, s, t, r) for r in reps]
                row.append(None if None in vals else mean(vals))
            if None not in row:
                blocks.append(tuple(row))
        return blocks


# ============================================================================= report

def _f(x: float | None, nd: int = 3) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "—"
    return f"{x:.{nd}f}".replace(".", ",")


def _p(p: float) -> str:
    return "<0,001" if p < 0.001 else f"{p:.3f}".replace(".", ",")


def _pairs_table(title: str, comparisons: list[tuple[str, list[tuple[float, ...]]]]) -> list[str]:
    """Wilcoxon per comparison (block columns 0 vs 1), Holm across the comparisons."""
    tests = [(name, wilcoxon([b[0] for b in blocks], [b[1] for b in blocks]), len(blocks))
             for name, blocks in comparisons]
    adj = holm([t.p for _, t, _ in tests])
    lines = [title, "", "| Comparación | n | Media A | Media B | Dif. [IC 95 %] | T+ / T− | r | p | p Holm | ¿Diferencia? |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for (name, t, n), pa in zip(tests, adj):
        blocks = dict(comparisons)[name]
        ma = mean(b[0] for b in blocks) if blocks else None
        mb = mean(b[1] for b in blocks) if blocks else None
        lines.append(f"| {name} | {n} | {_f(ma)} | {_f(mb)} | {_f(t.diff)} [{_f(t.ci[0])}; {_f(t.ci[1])}] | "
                     f"{_f(t.t_plus, 1)} / {_f(t.t_minus, 1)} | {_f(t.r, 2)} | {_p(t.p)} | {_p(pa)} | "
                     f"{'sí' if pa < ALPHA else 'no'} |")
    return lines + [""]


def _friedman_section(title: str, names: list[str], blocks: list[tuple[float, ...]]) -> list[str]:
    fr = friedman(blocks)
    lines = [title, "", f"Friedman: n = {fr.n}, χ² = {_f(fr.q, 2)}, p = {_p(fr.p)}, W de Kendall = {_f(fr.w)}.",
             "", "| Estrategia | Media | Rango medio |", "|---|---|---|"]
    for j, name in enumerate(names):
        lines.append(f"| {name} | {_f(mean(b[j] for b in blocks) if blocks else None)} | "
                     f"{_f(fr.mean_ranks[j] if fr.mean_ranks else None, 2)} |")
    lines.append("")
    if fr.p < ALPHA:
        pairs = [(f"{names[i]} vs {names[j]}", [(b[i], b[j]) for b in blocks])
                 for i in range(len(names)) for j in range(i + 1, len(names))]
        lines += _pairs_table("Comparaciones dos a dos (Wilcoxon, Holm):", pairs)
    else:
        lines += ["Friedman no significativo: sin comparaciones dos a dos (D12).", ""]
    return lines


def triage_questions(d: Data, labels: set[str], **kw) -> list[str]:
    lines = []
    lines += _pairs_table("**PI1. ¿La traza mejora el triaje?** (completo vs ciego)",
                          [(f"{s}: completo vs ciego", d.triage_blocks([(s, "full"), (s, "blind")], labels, **kw))
                           for s in STRATEGIES])
    lines += _friedman_section("**PI2. ¿Qué estrategia triaja mejor?** (contexto completo)", list(STRATEGIES),
                               d.triage_blocks([(s, "full") for s in STRATEGIES], labels, **kw))
    lines += _pairs_table("**PI5. ¿El RAG mejora el triaje?** (completo vs sin RAG)",
                          [(f"{s}: completo vs sin RAG", d.triage_blocks([(s, "full"), (s, "norag")], labels, **kw))
                           for s in STRATEGIES])
    return lines


def remediation_questions(d: Data, reps: list[int] | None = None) -> list[str]:
    lines = _friedman_section("**PI3. ¿Qué estrategia remedia mejor?** (con traza)", list(STRATEGIES),
                              d.remediation_blocks([(s, True) for s in STRATEGIES], reps))
    lines += _pairs_table("**PI4. ¿La traza mejora la remediación?** (con vs sin traza)",
                          [(f"{s}: con vs sin traza", d.remediation_blocks([(s, True), (s, False)], reps))
                           for s in STRATEGIES])
    return lines


def sensitivity_binary(d: Data) -> list[str]:
    """Pass 1 only, binary outcomes: Cochran's Q and exact McNemar."""
    rep = d.reps[0] if d.reps else 1
    lines = [f"**Pasada {rep} sola, binaria** (triaje por la regla de producción).", "",
             "| Pregunta | Comparación | n | Resultado | p (Holm dentro de la pregunta) |", "|---|---|---|---|---|"]
    groups = [g for g in d.groups if d.group_label(g) in ("TP", "FP")]

    def tri(g, s, c):
        called = d.group_called_tp(g, s, c, rep)
        return None if called is None else int(called == (d.group_label(g) == "TP"))

    for q, ctx_b in (("PI1", "ciego"), ("PI5", "sin RAG")):
        rows = []
        for s in STRATEGIES:
            other = "blind" if q == "PI1" else "norag"
            pairs = [(tri(g, s, "full"), tri(g, s, other)) for g in groups]
            pairs = [p for p in pairs if None not in p]
            n10, n01, p = mcnemar_exact([a for a, _ in pairs], [b for _, b in pairs])
            rows.append((f"{s}: completo vs {ctx_b}", len(pairs), f"solo A {n10}, solo B {n01}", p))
        for (name, n, res, _), pa in zip(rows, holm([r[3] for r in rows])):
            lines.append(f"| {q} | {name} | {n} | {res} | {_p(pa)} |")
    blocks = [tuple(tri(g, s, "full") for s in STRATEGIES) for g in groups]
    blocks = [b for b in blocks if None not in b]
    q, p = cochran_q(blocks)
    lines.append(f"| PI2 | Q de Cochran, 3 estrategias | {len(blocks)} | Q = {_f(q, 2)} | {_p(p)} |")
    rb = [tuple(d.loop_accepted(c.fingerprint, s, True, rep) for s in STRATEGIES) for c in d.cases]
    rb = [b for b in rb if None not in b]
    q, p = cochran_q(rb)
    lines.append(f"| PI3 | Q de Cochran, 3 estrategias | {len(rb)} | Q = {_f(q, 2)} | {_p(p)} |")
    rows = []
    for s in STRATEGIES:
        pairs = [(d.loop_accepted(c.fingerprint, s, True, rep), d.loop_accepted(c.fingerprint, s, False, rep))
                 for c in d.cases]
        pairs = [x for x in pairs if None not in x]
        n10, n01, p = mcnemar_exact([a for a, _ in pairs], [b for _, b in pairs])
        rows.append((f"{s}: con vs sin traza", len(pairs), f"solo A {n10}, solo B {n01}", p))
    for (name, n, res, _), pa in zip(rows, holm([r[3] for r in rows])):
        lines.append(f"| PI4 | {name} | {n} | {res} | {_p(pa)} |")
    return lines + [""]


def triage_descriptives(d: Data) -> list[str]:
    lines = ["| Celda | Acierto (TP+FP) | FPR producción | TPR producción | Respuestas UNCERTAIN | κ de Fleiss entre pasadas |",
             "|---|---|---|---|---|---|"]
    fp_groups = [g for g in d.groups if d.group_label(g) == "FP"]
    tp_groups = [g for g in d.groups if d.group_label(g) == "TP"]
    for s in STRATEGIES:
        for ctx in CONTEXTS:
            acc = [b[0] for b in d.triage_blocks([(s, ctx)], {"TP", "FP"})]
            fpr = [mean(x) for x in ([d.group_called_tp(g, s, ctx, r) for g in fp_groups] for r in d.reps)
                   if None not in x]
            tpr = [mean(x) for x in ([d.group_called_tp(g, s, ctx, r) for g in tp_groups] for r in d.reps)
                   if None not in x]
            answers = [d.verdict.get((u.fingerprint, s, ctx, r)) for u in d.units for r in d.reps]
            answers = [a for a in answers if a]
            ratings = [[d.verdict[(u.fingerprint, s, ctx, r)] for r in d.reps
                        if (u.fingerprint, s, ctx, r) in d.verdict] for u in d.units]
            lines.append(f"| {s}/{ctx} | {_f(mean(acc) if acc else None)} | {_f(mean(fpr) if fpr else None)} | "
                         f"{_f(mean(tpr) if tpr else None)} | "
                         f"{sum(a == 'UNCERTAIN' for a in answers)}/{len(answers)} | "
                         f"{_f(fleiss_kappa(ratings, ('TP', 'FP', 'UNCERTAIN')), 2)} |")
    return lines + ["", f"FPR sobre {len(fp_groups)} grupos FP y TPR sobre {len(tp_groups)} grupos TP, "
                        "media de las pasadas; acierto = puntuación media por grupo.", ""]


def _case_sets(repo_root: Path, d: Data) -> dict[str, set[str]]:
    with (repo_root / TARGETS).open(encoding="utf-8") as fh:
        targets = {r["id"]: r for r in csv.DictReader(fh)}
    with (repo_root / "benchmarks/nvd-cvss.csv").open(encoding="utf-8") as fh:
        nvd = {r["id"]: r for r in csv.DictReader(fh)}
    tiers = json.loads((repo_root / "benchmarks/oracles/secbench-functional.json")
                       .read_text(encoding="utf-8"))["cases"]
    ids = {c.id for c in d.cases}
    return {
        "todos (33)": ids,
        "CodeQL ≥ 7": {i for i in ids if targets[i]["auto_remediable"] == "True"},
        "NVD v3 ≥ 7": {i for i in ids if nvd.get(i, {}).get("nvd_v3") not in (None, "")
                       and float(nvd[i]["nvd_v3"]) >= 7},
        "Juice Shop": {i for i in ids if targets[i]["source"] == "juice-shop"},
        "T1": {i for i in ids if tiers.get(i, {}).get("tier") == "T1"},
        "T2": {i for i in ids if tiers.get(i, {}).get("tier") == "T2"},
    }


def remediation_descriptives(d: Data, repo_root: Path) -> list[str]:
    conds = [(s, t) for s in STRATEGIES for t in (True, False)]
    sets = _case_sets(repo_root, d)
    cname = {(s, t): f"{s}/{'traza' if t else 'sin traza'}" for s, t in conds}
    lines = ["**RSR por condición** (ACCEPTED / casos, media de las pasadas; entre paréntesis, cada pasada).", "",
             "| Condición | " + " | ".join(f"{k} (n={len(v)})" for k, v in sets.items()) + " |",
             "|---|" + "---|" * len(sets)]
    for s, t in conds:
        cells = []
        for ids in sets.values():
            per = []
            for r in d.reps:
                vals = [d.loop_accepted(c.fingerprint, s, t, r) for c in d.cases if c.id in ids]
                if vals and None not in vals:
                    per.append(mean(vals))
            cells.append(f"{_f(mean(per)) if per else '—'} ({', '.join(_f(x, 2) for x in per)})")
        lines.append(f"| {cname[(s, t)]} | " + " | ".join(cells) + " |")

    lines += ["", "**Convergencia, regresión, desacuerdo CodeQL–exploit, RSR de punta a punta y coste.**", "",
              "| Condición | Aceptado en el intento 1 / 2 / 3 | Regresión en FIXED | FIXED con exploit vivo | "
              "NOT_FIXED con exploit bloqueado | RSR punta a punta | Tokens por bucle (mediana) | "
              "LLM s / rescan s / oráculos s por bucle (mediana) |", "|---|---|---|---|---|---|---|---|"]
    for s, t in conds:
        at, fixed, regress, alive, blocked, e2e, toks, secs = Counter(), 0, 0, 0, 0, [], [], []
        for c in d.cases:
            for r in d.reps:
                atts = d.attempts.get((c.fingerprint, s, t, r), [])
                if not atts:
                    continue
                acc = next((a["attempt"] for a in atts if a.get("accepted")), None)
                if acc:
                    at[acc] += 1
                for a in atts:
                    checks = {k["name"]: k["ok"] for k in a.get("checks") or []}
                    exploit_ok = [ok for n, ok in checks.items() if n in EXPLOIT]
                    if a.get("status") == "FIXED":
                        fixed += 1
                        regress += bool(a.get("new")) or any(not ok for n, ok in checks.items()
                                                             if n in FUNCTIONAL)
                        alive += any(not ok for ok in exploit_ok)
                    elif a.get("status") == "NOT_FIXED":
                        blocked += bool(exploit_ok) and all(exploit_ok)
                verdict = d.verdict.get((c.fingerprint, s, "full" if t else "blind", r))
                if verdict is not None:
                    e2e.append(int(bool(acc) and verdict == "TP"))
                toks.append(sum((a.get("prompt_tokens") or 0) + (a.get("completion_tokens") or 0) for a in atts))
                secs.append((sum(a.get("llm_seconds") or 0 for a in atts),
                             sum(sum((a.get("rescan_seconds") or {}).values()) for a in atts),
                             sum(k.get("seconds") or 0 for a in atts for k in a.get("checks") or [])))
        lines.append(f"| {cname[(s, t)]} | {at[1]} / {at[2]} / {at[3]} | {regress}/{fixed} | {alive}/{fixed} | "
                     f"{blocked} | {_f(mean(e2e)) if e2e else '—'} | {median(toks) if toks else '—'} | "
                     + (" / ".join(f"{median(x[i] for x in secs):.0f}" for i in range(3)) if secs else "—")
                     + " |")
    return lines + ["", "Regresión: hallazgo NEW o fallo funcional (T1, T2, Juice Shop) en un intento que CodeQL da por FIXED. "
                        "Punta a punta: aceptado y el triaje de la misma estrategia, contexto (completo si hay traza, "
                        "ciego si no) y pasada dijo TP.", ""]


def memorisation(d: Data) -> list[str]:
    by_src: dict[str, list[float]] = defaultdict(list)
    gaps: dict[str, list[float]] = defaultdict(list)
    for g, rows in d.groups.items():
        if rows[0].label not in ("TP", "FP"):
            continue
        blind = [d.triage_score(rows, s, "blind", d.reps) for s in STRATEGIES]
        full = [d.triage_score(rows, s, "full", d.reps) for s in STRATEGIES]
        if None in blind or None in full:
            continue
        by_src[rows[0].source].append(mean(blind))
        gaps[rows[0].source].append(mean(full) - mean(blind))
    js, sb = by_src.get("juice-shop", []), by_src.get("secbench-js", [])
    u, p = mann_whitney(js, sb)
    return ["| Fuente | Grupos | Acierto ciego (media) | Completo − ciego (media) |", "|---|---|---|---|",
            *(f"| {src} | {len(v)} | {_f(mean(v))} | {_f(mean(gaps[src]))} |" for src, v in sorted(by_src.items())),
            "", f"Mann-Whitney (acierto ciego, Juice Shop vs SecBench.js): U = {u:g}, p = {_p(p)} (permutación). "
                "Exploratorio: un acierto ciego mayor en Juice Shop, conocido públicamente, sería compatible con "
                "memorización.", ""]


def provenance(d: Data) -> list[str]:
    lines = []
    for experiment, recs in d.logs.items():
        if not recs:
            lines.append(f"- {experiment}: sin datos")
            continue
        def c(field):
            return ", ".join(f"{k} ({v})" for k, v in Counter(r.get(field) for r in recs).items())
        lines.append(f"- {experiment}: {len(recs)} llamadas; pasadas {sorted({r.get('rep', 1) for r in recs})}; "
                     f"proveedor {c('provider')}; modelo servido {c('model_served')}; "
                     f"protocolo {c('protocol_commit')}; dev {c('dev')}")
        if any(r.get("dev") for r in recs):
            lines.append("  - **AVISO: hay filas de ejecuciones --dev; no son datos de la Fase 5.**")
    return lines


def report(d: Data, repo_root: Path, source: str) -> str:
    lines = ["# Fase 5 — análisis (D12)", "", f"Datos: `{source}`. Pasadas presentes: {d.reps}.", ""]
    lines += provenance(d) + [""]
    lines += ["## Preguntas de investigación", "",
              "Unidad: vulnerabilidad (triaje, grupos TP + FP) o caso (remediación); puntuación = proporción de "
              "aciertos en filas × pasadas. α = 0,05; Holm dentro de cada pregunta.", ""]
    lines += triage_questions(d, {"TP", "FP"})
    lines += remediation_questions(d)
    lines += ["## Componentes del triaje (secundario)", "", "### FPR: solo grupos FP", ""]
    lines += triage_questions(d, {"FP"})
    lines += ["### TPR: solo grupos TP", ""]
    lines += triage_questions(d, {"TP"})
    lines += ["## Sensibilidad", ""]
    lines += sensitivity_binary(d)
    lines += ["### Triaje por fila (75 filas TP + FP) en lugar de por grupo", ""]
    lines += triage_questions(d, {"TP", "FP"}, per_row=True)
    for relabel in ("TP", "FP"):
        lines += [f"### Grupos UNCERTAIN contados como {relabel} (PI1)", ""]
        lines += _pairs_table("", [(f"{s}: completo vs ciego",
                                    d.triage_blocks([(s, "full"), (s, "blind")], {"TP", "FP"}, relabel=relabel))
                                   for s in STRATEGIES])
    lines += ["## Descriptivos del triaje", ""] + triage_descriptives(d)
    lines += ["## Descriptivos de la remediación", ""] + remediation_descriptives(d, repo_root)
    lines += ["## Control de memorización (exploratorio)", ""] + memorisation(d)
    return "\n".join(lines)


# ========================================================================== simulation

def simulate(repo_root: Path, out: Path, scenario: str, seed: int, reps=REPS) -> None:
    """Synthetic logs with a known truth: ``null`` (no condition matters) or
    ``effect`` (the trace raises triage accuracy and remediation success)."""
    rng = random.Random(seed)
    out.mkdir(parents=True, exist_ok=True)
    units, cases = triage_pool(repo_root), remediation_pool(repo_root)
    skill = {u.fingerprint: rng.uniform(0.35, 0.95) for u in units}     # per-unit difficulty
    fix = {c.fingerprint: rng.uniform(0.2, 0.9) for c in cases}
    base = {"provider": "sim", "model_served": "sim", "protocol_commit": "sim", "dev": False,
            "prompt_tokens": 1500, "completion_tokens": 400, "llm_seconds": 3.0}
    for rep in reps:
        rows = []
        for u in units:
            for s in STRATEGIES:
                for ctx, (t, rg) in CONTEXTS.items():
                    p = skill[u.fingerprint]
                    if scenario == "effect" and t:
                        p = min(0.99, p + 0.25)
                    right = rng.random() < p
                    truth_tp = u.label == "TP"
                    says_tp = truth_tp if right else not truth_tp
                    if u.label == "UNCERTAIN":
                        says_tp = rng.random() < 0.5
                    v = "TP" if says_tp else rng.choice(("FP", "FP", "UNCERTAIN"))
                    rows.append({"kind": TRIAGE, "fingerprint": u.fingerprint, "strategy": s,
                                 "with_trace": t, "with_rag": rg, "attempt": 1, "rep": rep,
                                 "verdict": v, **base})
        (out / f"{TRIAGE}-p{rep}.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n",
                                                   encoding="utf-8")
        rows = []
        for c in cases:
            for s in STRATEGIES:
                for t in (True, False):
                    p = fix[c.fingerprint] + (0.3 if scenario == "effect" and t else 0)
                    for n in (1, 2, 3):
                        ok = rng.random() < min(0.95, p)
                        rows.append({"kind": REMEDIATION, "fingerprint": c.fingerprint, "strategy": s,
                                     "with_trace": t, "with_rag": True, "attempt": n, "rep": rep,
                                     "max_attempts": 3, "accepted": ok,
                                     "status": "FIXED" if ok or rng.random() < 0.5 else "NOT_FIXED",
                                     "checks": [{"name": "secbench-exploit", "ok": ok, "seconds": 3.0}],
                                     "new": [], "rescan_seconds": {"post": 40.0}, **base})
                        if ok:
                            break
        (out / f"{REMEDIATION}-p{rep}.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n",
                                                        encoding="utf-8")


def selftest(repo_root: Path) -> None:
    """Statistics against hand-checkable cases, then type-I error and power on simulations."""
    import itertools
    import tempfile

    checks = 0

    def ok(name: str, cond: bool) -> None:
        nonlocal checks
        if not cond:
            raise SystemExit(f"SELFTEST FAILED: {name}")
        checks += 1
        print(f"ok  {name}")

    # Wilcoxon exact p equals brute-force enumeration of all sign flips (with ties and zeros)
    a, b = [1, 2, 3, 4, 5, 6, 7, 1], [0, 0, 1, 1, 2, 9, 7, 3]
    w = wilcoxon(a, b)
    d = [x - y for x, y in zip(a, b) if x != y]
    ranks = average_ranks([abs(x) for x in d])
    obs = sum(r for r, x in zip(ranks, d) if x > 0)
    centre = sum(ranks) / 2
    brute = sum(abs(sum(r for r, s in zip(ranks, signs) if s) - centre) >= abs(obs - centre) - 1e-9
                for signs in itertools.product((0, 1), repeat=len(d))) / 2 ** len(d)
    ok("Wilcoxon exact p = brute force", abs(w.p - brute) < 1e-12 and w.n == 7)
    ok("Wilcoxon all-equal pairs -> p = 1", wilcoxon([1, 1], [1, 1]).p == 1.0)
    ok("Wilcoxon 6 positive diffs -> p = 2/64", abs(wilcoxon([2] * 6, [1] * 6).p - 2 / 64) < 1e-12)
    # Friedman: no ties, worked by hand (n = 4, k = 3, ranks all 1-2-3 -> Q = 8)
    fr = friedman([(1, 2, 3)] * 4)
    ok("Friedman Q = 8, W = 1 for identical orderings", abs(fr.q - 8) < 1e-9 and abs(fr.w - 1) < 1e-9)
    ok("chi2 sf df=2 at 5.991 ~ 0.05", abs(chi2_sf(5.991, 2) - 0.05) < 1e-3)
    ok("Friedman all tied -> p = 1", friedman([(1, 1, 1)] * 5).p == 1.0)
    q, p = cochran_q([(1, 0, 0)] * 6 + [(1, 1, 1)] * 4)
    ok("Cochran Q = 12 for one column always better", abs(q - 12) < 1e-9)
    ok("McNemar exact 0 vs 6 -> p = 2/64", abs(mcnemar_exact([1] * 6, [0] * 6)[2] - 2 / 64) < 1e-12)
    ok("Holm adjusts [0.01, 0.04, 0.03] -> [0.03, 0.06, 0.06]",
       [round(x, 9) for x in holm([0.01, 0.04, 0.03])] == [0.03, 0.06, 0.06])
    ok("Fleiss kappa = 1 for perfect agreement",
       abs(fleiss_kappa([["TP"] * 3, ["FP"] * 3, ["TP"] * 3], ("TP", "FP", "UNCERTAIN")) - 1) < 1e-12)
    ok("average ranks with ties", average_ranks([10, 20, 20, 30]) == [1, 2.5, 2.5, 4])

    # simulations: type-I error under the null, power under a real effect
    rounds = 40
    with tempfile.TemporaryDirectory() as tmp:
        hits = {"null": [0, 0], "effect": [0, 0]}
        for scenario in hits:
            for i in range(rounds):
                path = Path(tmp) / f"{scenario}-{i}"
                simulate(repo_root, path, scenario, seed=1000 + i)
                dd = Data(load(path), repo_root)
                blocks = dd.triage_blocks([("zero-shot", "full"), ("zero-shot", "blind")], {"TP", "FP"})
                hits[scenario][0] += wilcoxon([x for x, _ in blocks], [y for _, y in blocks],
                                              ci=False).p < ALPHA
                rb = dd.remediation_blocks([("zero-shot", True), ("zero-shot", False)])
                hits[scenario][1] += wilcoxon([x for x, _ in rb], [y for _, y in rb], ci=False).p < ALPHA
        print(f"    null: PI1 rejected {hits['null'][0]}/{rounds}, PI4 {hits['null'][1]}/{rounds}; "
              f"effect: PI1 {hits['effect'][0]}/{rounds}, PI4 {hits['effect'][1]}/{rounds}")
        ok("type-I error of PI1 under the null <= 12.5 % (alpha 5 %, 40 rounds)", hits["null"][0] <= 5)
        ok("type-I error of PI4 under the null <= 12.5 %", hits["null"][1] <= 5)
        ok("power of PI1 for a +0.25 trace effect >= 90 %", hits["effect"][0] >= 36)
        ok("power of PI4 for a +0.30 trace effect >= 80 %", hits["effect"][1] >= 32)
        # the whole report builds on simulated data, with all sections
        path = Path(tmp) / "report"
        simulate(repo_root, path, "effect", seed=7)
        text = report(Data(load(path), repo_root), repo_root, str(path))
        ok("report has PI1-PI5, sensitivity and memorisation",
           all(s in text for s in ("PI1.", "PI2.", "PI3.", "PI4.", "PI5.", "Sensibilidad", "memorización")))
        ok("report flags no dev rows", "AVISO" not in text)
        dd = Data(load(path), repo_root)
        ok("69 TP+FP groups, 33 cases",
           len(dd.triage_blocks([("cot", "full")], {"TP", "FP"})) == 69 and
           len(dd.remediation_blocks([("cot", True)])) == 33)
    print(f"{checks} checks passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("analyze", help="write the analysis report from the logs")
    p.add_argument("--dir", type=Path, default=Path("experiments/phase5"))
    p.add_argument("--out", type=Path, help="markdown report (default: <dir>/analysis.md)")
    p = sub.add_parser("simulate", help="write synthetic logs with a known truth")
    p.add_argument("--scenario", choices=("null", "effect"), required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seed", type=int, default=SEED)
    sub.add_parser("selftest", help="check the statistics and the analysis on simulated data")
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    if args.cmd == "analyze":
        out = args.out or args.dir / "analysis.md"
        out.write_text(report(Data(load(args.dir), repo_root), repo_root, str(args.dir)) + "\n",
                       encoding="utf-8")
        print(f"report: {out}")
    elif args.cmd == "simulate":
        simulate(repo_root, args.out, args.scenario, args.seed)
        print(f"simulated logs ({args.scenario}): {args.out}")
    else:
        selftest(repo_root)


if __name__ == "__main__":
    main()
