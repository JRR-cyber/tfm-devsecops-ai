"""Run the whole agent over the remediation dataset (Paso 4.10; reused by Phase 5).

For every case of ``benchmarks/remediation-targets.csv`` (one pre-registered
finding per case), under one experimental condition (strategy x trace x RAG):

    triage (logged)  ->  if TP: reflexive loop (CodeQL + D9 oracles, up to 3
    attempts)  ->  publication decision (PR ai-fixed [+ ai-needs-review] or
    issue ai-escalated)

Publication is **always a dry-run** here: the decision and its text go to the
report, nothing is pushed and no PR or issue is opened (the dataset is the
benchmark; demos use ``triage_engine.py --open --draft`` on one finding).

Scope: by default all 33 cases are repaired when the triage says TP. ``--policy``
applies the pipeline's CVSS >= 7 filter (3.3): cases below it are triaged and
reported only, as in production. ``--repair-all`` skips the triage gate (the loop
also runs on cases the triage missed), for remediation metrics independent of the
triage.

Resumable and quota-aware (Groq free plan, 200K tokens/day): every attempt is in
the JSONL log (4.5) as soon as it finishes, and relaunching the same command skips
what is done. When Groq says the quota is spent (``GroqQuotaExhausted``) the run
writes the report so far, prints when to resume and exits with code 75. Any other
failure (CodeQL, Docker) stops the run the same way, without logging the attempt.

Preflight (before any token is spent): the provider's API key (``LLM_PROVIDER``,
default Groq), CodeQL CLI, Docker and the SecBench harness image, the Juice Shop
build the oracle links in, and every target fingerprint present in the SARIF.

Paid provider: ``LLM_BUDGET_USD`` is required. It caps the list-price spend of the
whole log (a relaunch counts what the log already spent); when reached, the run
stops before the next call, writes the report and exits with code 76.

Usage (Git Bash, from the repo root; needs GROQ_API_KEY, CODEQL_CLI, Docker):
    python scripts/ai_agent/run_dataset.py <unified findings.sarif> \
        [--strategy zero-shot] [--no-trace] [--no-rag] [--policy] [--repair-all] \
        [--only id,id] [--log results/dev/rehearsal-4.10.jsonl]
    python scripts/ai_agent/run_dataset.py <sarif> --report-only     # rebuild the report, no calls
"""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from sarif_parser import Finding, SourceReader, parse_sarif
from strategies import STRATEGIES, ZERO_SHOT

TARGETS = Path("benchmarks/remediation-targets.csv")
JUICE_SHOP_BUILD = ("src/app/juice-shop/node_modules", "src/app/juice-shop/build",
                    "src/app/juice-shop/frontend/dist")
EXIT_RESUME_LATER = 75                     # EX_TEMPFAIL: relaunch the same command later
EXIT_BUDGET = 76                           # spend cap reached: check the spend first


@dataclass
class Case:
    id: str
    source: str
    fingerprint: str
    cvss: float | None
    auto_remediable: bool
    finding: Finding | None = None


@dataclass
class Row:
    case: Case
    triage: dict | None = None
    outcome: str = "PENDING"               # ACCEPTED | ESCALATED | NOT_TP | POLICY | PENDING
    attempts: list[dict] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    body: str = ""


def load_cases(repo_root: Path, findings: list[Finding], only: set[str] | None) -> list[Case]:
    by_key = {f.label_key: f for f in findings}
    cases = []
    for r in csv.DictReader((repo_root / TARGETS).open(encoding="utf-8")):
        if only and r["id"] not in only:
            continue
        cases.append(Case(r["id"], r["source"], r["fingerprint"],
                          float(r["cvss"]) if r["cvss"] not in ("", "None") else None,
                          r["auto_remediable"] == "True", by_key.get(r["fingerprint"])))
    if only and len(cases) != len(only):
        raise SystemExit(f"unknown case id(s): {sorted(only - {c.id for c in cases})}")
    return cases


def preflight(repo_root: Path, cases: list[Case], oracles: bool, codeql: str | None) -> str:
    """Fail before spending tokens; returns the CodeQL CLI path."""
    import os

    from rescan import find_codeql

    problems = []
    missing = [c.id for c in cases if c.finding is None]
    if missing:
        problems.append(f"targets not in this SARIF (wrong artifact?): {', '.join(missing)}")
    from groq_client import (BUDGET_ENV, budget_setting, current_provider, max_tokens_setting,
                             reasoning_effort)
    try:
        provider = current_provider()
        reasoning_effort()
        max_tokens_setting()
        if not os.environ.get(provider.key_env):
            problems.append(f"{provider.key_env} is not set in this terminal "
                            f"(provider {provider.name})")
        if provider.name != "groq" and budget_setting() is None:
            problems.append(f"{BUDGET_ENV} is not set: a paid provider ({provider.name}) needs "
                            "a spend cap in USD for this run, e.g. export LLM_BUDGET_USD=1")
    except ValueError as err:
        problems.append(str(err))
    try:
        cli = find_codeql(codeql)
    except Exception as err:               # noqa: BLE001 - reported with the rest
        problems.append(f"CodeQL CLI: {err}")
        cli = None
    if oracles:
        if not shutil.which("docker"):
            problems.append("docker not found")
        elif subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
            problems.append("Docker is not running (start Docker Desktop)")
        else:
            from oracle_secbench import IMAGE
            if any(c.source == "secbench-js" for c in cases) and subprocess.run(
                    ["docker", "image", "inspect", IMAGE], capture_output=True).returncode != 0:
                problems.append(f"harness image {IMAGE} missing "
                                "(docker build -t tfm/secbench-harness benchmarks/secbench-js/harness)")
        if any(c.source == "juice-shop" for c in cases):
            absent = [p for p in JUICE_SHOP_BUILD if not (repo_root / p).is_dir()]
            if absent:
                problems.append("Juice Shop oracle needs a built checkout (npm install in "
                                f"src/app/juice-shop): missing {', '.join(absent)}")
    if problems:
        raise SystemExit("preflight failed:\n  - " + "\n  - ".join(problems))
    return cli


def attempt_trail(attempts: list[dict], plain: bool = False) -> str:
    """'NOT_FIXED ✗ → FIXED ✗(juice-shop-functional) → FIXED ✓'.

    ``plain`` uses ASCII only, for the console (a redirected Windows console is cp1252).
    """
    ok, ko, arrow = ("ok", "x", " -> ") if plain else ("✓", "✗", " → ")
    parts = []
    for a in attempts:
        failed = [c["name"] for c in a.get("checks") or [] if not c["ok"]]
        mark = ok if a.get("accepted") else ko + (f"({', '.join(failed)})" if failed else "")
        parts.append(f"{a.get('status')} {mark}")
    return arrow.join(parts)


def _cost(records: list[dict]) -> tuple[int, int, float, float]:
    tin = sum(r.get("prompt_tokens") or 0 for r in records)
    tout = sum(r.get("completion_tokens") or 0 for r in records)
    llm = sum(r.get("llm_seconds") or 0 for r in records)
    rescan = sum(sum((r.get("rescan_seconds") or {}).values()) for r in records)
    return tin, tout, llm, rescan


def report(rows: list[Row], args, log_path: Path, note: str = "") -> str:
    from results import PRICE_INPUT_PER_M, PRICE_OUTPUT_PER_M

    cond = (f"estrategia `{args.strategy}`, traza {'sí' if not args.no_trace else 'no'}, "
            f"RAG {'sí' if not args.no_rag else 'no'}, "
            f"{'filtro CVSS ≥ 7' if args.policy else 'todos los casos'}"
            f"{', sin puerta de triaje' if args.repair_all else ''}")
    served = sorted({f"{rec.get('provider', 'groq')} (reasoning_effort "
                     f"{rec.get('reasoning_effort', 'provider-default')})"
                     for r in rows for rec in ([r.triage] if r.triage else []) + r.attempts})
    lines = [f"# Ensayo sobre el dataset de remediación", "",
             f"- Condición: {cond}", f"- Proveedor: {', '.join(served) or '—'}",
             f"- Log: `{log_path}`",
             f"- Generado: {time.strftime('%Y-%m-%d %H:%M')}"]
    if note:
        lines += ["", f"> {note}"]
    lines += ["", "| Caso | CVSS | Triaje | Resultado | Intentos | Etiquetas | Tokens (in+out) | LLM s | Rescan s |",
              "|---|---|---|---|---|---|---|---|---|"]
    totals = [0, 0, 0.0, 0.0]
    for r in rows:
        recs = ([r.triage] if r.triage else []) + r.attempts
        tin, tout, llm, rescan = _cost(recs)
        for i, v in enumerate((tin, tout, llm, rescan)):
            totals[i] += v
        tri = f"{r.triage['verdict']} {r.triage.get('confidence')}" if r.triage else "—"
        lines.append(f"| {r.case.id} | {r.case.cvss} | {tri} | {r.outcome} | "
                     f"{attempt_trail(r.attempts) or '—'} | {', '.join(r.labels) or '—'} | "
                     f"{tin}+{tout} | {llm:.0f} | {rescan:.0f} |")
    from collections import Counter
    counts = Counter(r.outcome for r in rows)
    accepted_at = Counter(len(r.attempts) for r in rows if r.outcome == "ACCEPTED")
    cost = totals[0] / 1e6 * PRICE_INPUT_PER_M + totals[1] / 1e6 * PRICE_OUTPUT_PER_M
    attempts = [a for r in rows for a in r.attempts]
    applied = [a for a in attempts if "[mode=" in (a.get("apply_detail") or "")]
    tolerant = Counter(m for a in applied
                       for m in a["apply_detail"].split("[mode=")[1].rstrip("]").split(",")
                       if m != "exact")
    lines += ["", "## Totales", "",
              f"- Intentos: {len(attempts)}; diff no aplicable {sum(a.get('status') == 'APPLY_FAILED' for a in attempts)}; "
              f"aplicados con tolerancia (hunks): " +
              (", ".join(f"{k} {v}" for k, v in sorted(tolerant.items())) or "ninguno"),
              "- Resultados: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())),
              "- Aceptados en el intento: " + (", ".join(f"#{k}: {v}" for k, v in
                                                       sorted(accepted_at.items())) or "—"),
              f"- Tokens: {totals[0]} in + {totals[1]} out (~${cost:.4f} a precio de lista)",
              f"- Tiempo: LLM {totals[2]:.0f} s, rescans {totals[3]:.0f} s", ""]
    detail = [r for r in rows if r.body]
    if detail:
        lines += ["## Publicación que se habría hecho (dry-run)", ""]
        for r in detail:
            lines += [f"<details><summary>{r.case.id} — {r.outcome}, {', '.join(r.labels)}"
                      "</summary>", "", r.body, "", "</details>", ""]
    return "\n".join(lines)


def run_case(case: Case, args, client, reader, log, repo_root: Path, cli, checks) -> Row:
    from publish import decide
    from repair_loop import repair
    from triage_engine import triage_logged

    row = Row(case)
    with_trace, with_rag = not args.no_trace, not args.no_rag
    row.triage, _ = triage_logged(case.finding, client, reader, log, args.strategy,
                                  with_trace, with_rag)
    if args.policy and not case.auto_remediable:
        row.outcome = "POLICY"             # reported only (CVSS < 7)
        return row
    if row.triage["verdict"] != "TP" and not args.repair_all:
        row.outcome = "NOT_TP"             # the pipeline would report, not patch
        return row
    loop = repair(case.finding, client, repo_root, reader=reader, strategy=args.strategy,
                  with_trace=with_trace, with_rag=with_rag, log=log, cli=cli, checks=checks)
    row.outcome = loop.outcome
    row.attempts = [a.record for a in loop.attempts]
    d = decide(case.finding, loop, repo_root, verdict=row.triage["verdict"])
    row.labels, row.caveats, row.body = d.labels, d.caveats, d.body
    return row


class _LogOnly:
    """--report-only: every answer must come from the log."""

    def complete(self, system, user):
        raise _NotLogged


class _NotLogged(Exception):
    pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sarif", type=Path, help="unified SARIF of the CI pipeline")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--strategy", default=ZERO_SHOT, choices=STRATEGIES)
    parser.add_argument("--no-trace", action="store_true")
    parser.add_argument("--no-rag", action="store_true")
    parser.add_argument("--policy", action="store_true",
                        help="apply the CVSS>=7 filter: cases below it are triaged only")
    parser.add_argument("--repair-all", action="store_true",
                        help="run the loop even when the triage does not say TP")
    parser.add_argument("--only", help="comma-separated case ids (default: all)")
    parser.add_argument("--no-oracles", action="store_true", help="CodeQL only (skip D9 oracles)")
    parser.add_argument("--codeql", help="path to the CodeQL CLI (default: $CODEQL_CLI or PATH)")
    parser.add_argument("--log", type=Path, default=Path("results/dev/rehearsal-4.10.jsonl"))
    parser.add_argument("--report", type=Path, help="markdown report (default: <log>.md)")
    parser.add_argument("--report-only", action="store_true",
                        help="rebuild the report from the log; no LLM call, no rescan")
    args = parser.parse_args()

    from groq_client import (GroqClient, GroqQuotaExhausted, LLMBudgetExceeded,
                             current_provider, format_wait)
    from repair_loop import oracle_checks
    from rescan import codeql_version
    from results import ResultLog, environment

    repo_root = args.repo_root.resolve()
    report_path = args.report or args.log.with_suffix(".md")
    only = set(args.only.split(",")) if args.only else None
    cases = load_cases(repo_root, parse_sarif(args.sarif, repo_root), only)
    reader = SourceReader(repo_root)

    if args.report_only:
        log = ResultLog(args.log)
        rows = []
        for case in cases:
            try:
                rows.append(run_case(case, args, _LogOnly(), reader, log, repo_root, None, None))
            except _NotLogged:              # unfinished case: show what the log has
                from results import REMEDIATION, TRIAGE, RunKey
                cond = (args.strategy, not args.no_trace, not args.no_rag)
                tri = log.get(RunKey(TRIAGE, case.fingerprint, *cond))
                done = sorted((r for r in log.records() if r["kind"] == REMEDIATION
                               and r["fingerprint"] == case.fingerprint
                               and (r["strategy"], r["with_trace"], r["with_rag"]) == cond),
                              key=lambda r: r["attempt"])
                rows.append(Row(case, triage=tri, attempts=done))
        report_path.write_text(report(rows, args, args.log), encoding="utf-8")
        print(f"report: {report_path}")
        return

    cli = preflight(repo_root, cases, not args.no_oracles, args.codeql)
    log = ResultLog(args.log, environment(repo_root, codeql_version(cli)))
    # the spend cap covers the whole log: a relaunch starts from what it already spent
    provider = current_provider()
    spent = sum(provider.cost(r.get("prompt_tokens") or 0, r.get("completion_tokens") or 0)
                for r in log.records() if r.get("provider", "groq") == provider.name)
    client = GroqClient(spent=spent)
    if getattr(client, "budget", None) is not None:
        print(f"spend cap ${client.budget:.2f} ({provider.name}); already spent in this log "
              f"~${spent:.4f} at list price", flush=True)
    checks = None if args.no_oracles else oracle_checks(repo_root)
    rows: list[Row] = []
    note, code = "", 0
    start = time.monotonic()
    try:
        for i, case in enumerate(cases, 1):
            print(f"[{i}/{len(cases)}] {case.id} (CVSS {case.cvss}) ...", flush=True)
            row = run_case(case, args, client, reader, log, repo_root, cli, checks)
            rows.append(row)
            tri = row.triage["verdict"] if row.triage else "?"
            print(f"    triage {tri} -> {row.outcome}"
                  + (f" [{attempt_trail(row.attempts, plain=True)}]" if row.attempts else "")
                  + (f" {row.labels}" if row.labels else ""), flush=True)
    except GroqQuotaExhausted as err:
        wait = f"en ~{format_wait(err.wait_seconds)}" if err.wait_seconds else "más tarde"
        note = (f"Interrumpido en {cases[len(rows)].id}: cuota de "
                f"{current_provider().name.capitalize()} agotada. "
                f"Relanzar el mismo comando {wait}; el log evita repetir lo hecho.")
        code = EXIT_RESUME_LATER
    except LLMBudgetExceeded as err:
        note = (f"Interrumpido en {cases[len(rows)].id}: tope de gasto alcanzado ({err}). "
                "Revisar el gasto antes de subir LLM_BUDGET_USD y relanzar.")
        code = EXIT_BUDGET
    except KeyboardInterrupt:
        note, code = f"Interrumpido a mano en {cases[len(rows)].id}.", 130
    except Exception as err:               # infra: CodeQL, Docker... (attempt not logged)
        note = f"Interrumpido en {cases[len(rows)].id} por un fallo de infraestructura: {err}"
        code = 1
    rows += [Row(c) for c in cases[len(rows):]]
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report(rows, args, args.log, note), encoding="utf-8")
    done = sum(r.outcome != "PENDING" for r in rows)
    print(f"\n{done}/{len(rows)} cases done in {time.monotonic() - start:.0f} s; "
          f"report: {report_path}")
    if note:
        print(note)
    sys.exit(code)


if __name__ == "__main__":
    main()
