"""Labelling and escalation of the reflexive loop's outcome (Paso 4.9).

Turns a ``repair_loop.LoopResult`` into what a human reviewer receives:

| Loop outcome                       | Published as | Labels                          |
|------------------------------------|--------------|---------------------------------|
| ACCEPTED, full evidence            | pull request | ``ai-fixed``                    |
| ACCEPTED, with caveats             | pull request | ``ai-fixed`` + ``ai-needs-review`` |
| ESCALATED (3 rejected attempts)    | issue        | ``ai-escalated``                |

A pull request is opened **only for a verified patch** (the attempt the loop
accepted). An escalated finding has no verified patch, so no code is pushed: the
issue carries every attempt (diff, verification result, feedback) for the human
who takes over. Every PR still needs human approval (assistive posture); the
labels only say how much the automatic verification already covers.

Caveats (deterministic rules, listed in the PR body, add ``ai-needs-review``):

- no functional oracle or no dynamic exploit oracle covered the finding (e.g. a
  candidate outside the 33-case dataset: CodeQL is the only evidence);
- the functional oracle is the weaker kind: differential T2, or a T1 suite whose
  sensitivity was only shown at module load (``benchmarks/oracles``);
- the patch also changed other findings (DISAPPEARED or RELOCATED besides the
  target): effects beyond the fix.

Dry-run by default: ``publish`` returns the text it would publish. ``open_=True``
pushes / calls ``gh`` (outward-facing: only with explicit approval).
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from sarif_parser import Finding

AI_FIXED, AI_NEEDS_REVIEW, AI_ESCALATED = "ai-fixed", "ai-needs-review", "ai-escalated"
LABELS = {
    AI_FIXED: ("0e8a16", "Fix del agente verificado automáticamente (CodeQL + oráculos D9). "
                         "Requiere aprobación humana."),
    AI_NEEDS_REVIEW: ("fbca04", "Fix verificado con evidencia más débil o efectos colaterales: "
                                "revisar con especial atención."),
    AI_ESCALATED: ("d93f0b", "El agente no logró un fix verificado en 3 intentos: escalado a "
                             "una persona."),
}
FUNCTIONAL = ("juice-shop-functional", "secbench-t1-suite", "secbench-t2-differential")
EXPLOIT = ("juice-shop-exploit", "secbench-exploit")
_REGISTRY = Path("benchmarks/oracles/secbench-functional.json")


@dataclass
class Decision:
    kind: str                         # pr | issue
    labels: list[str]
    title: str
    body: str
    diff: str | None = None           # the accepted patch (pr only)
    caveats: list[str] = field(default_factory=list)


def _where(f: dict) -> str:
    return f"`{f['rule']}` en `{f['file']}:{f['line']}`"


def caveats(finding: Finding, record: dict, repo_root: Path) -> list[str]:
    """Reasons an accepted patch deserves extra attention (empty = full evidence)."""
    out = []
    names = {c["name"] for c in record.get("checks") or []}
    if not names & set(FUNCTIONAL):
        out.append("Ningún oráculo funcional cubre este hallazgo: no hay evidencia automática "
                   "de que el parche conserve la funcionalidad.")
    if not names & set(EXPLOIT):
        out.append("Ningún exploit cubre este hallazgo: la eliminación de la vulnerabilidad solo "
                   "la confirma el rescan de CodeQL.")
    if "secbench-t2-differential" in names:
        out.append("El oráculo funcional es diferencial (T2): compara con la versión original "
                   "sobre entradas benignas, más débil que una suite de tests.")
    if "secbench-t1-suite" in names:
        from oracle_secbench import case_id
        registry = repo_root / _REGISTRY
        spec = (json.loads(registry.read_text(encoding="utf-8"))["cases"].get(case_id(finding.file) or "")
                if registry.is_file() else None)
        if spec and spec.get("validation", {}).get("sensitivity") == "module-load":
            out.append("La suite del paquete solo demostró llegar al módulo vulnerable, no a la "
                       "línea del sink (sensibilidad module-load).")
    if record.get("disappeared"):
        out.append(f"El parche también hizo desaparecer {len(record['disappeared'])} hallazgo(s) "
                   "distintos del objetivo: " + "; ".join(_where(f) for f in record["disappeared"]) + ".")
    others = [m for m in record.get("moved") or [] if m["pre"]["fingerprint"] != finding.label_key]
    if others:
        out.append(f"El parche modificó la línea marcada de otros {len(others)} hallazgo(s) "
                   "(reubicados, siguen presentes): " + "; ".join(_where(m["pre"]) for m in others) + ".")
    return out


def _header(finding: Finding, verdict: str | None) -> list[str]:
    cwes = ", ".join(finding.cwes) if finding.cwes else "n/a"
    lines = [f"- **Regla**: `{finding.rule_id}` ({cwes})",
             f"- **Ubicación**: `{finding.file}:{finding.start_line}`",
             f"- **Fingerprint**: `{finding.label_key}`"]
    if finding.security_severity is not None:
        lines.append(f"- **CVSS**: {finding.security_severity}")
    if verdict:
        lines.append(f"- **Triaje del agente**: {verdict}")
    return lines


def _verification_table(record: dict) -> list[str]:
    rows = ["| Verificación | Resultado |", "|---|---|",
            f"| CodeQL (rescan, fingerprints) | {record.get('status')}, "
            f"{len(record.get('new') or [])} nuevos, {record.get('persisting')} sin cambios |"]
    for c in record.get("checks") or []:
        rows.append(f"| `{c['name']}` | {'✅' if c['ok'] else '❌'} {c['detail'][:200]} |")
    return rows


def _history(attempts) -> list[str]:
    lines = []
    for a in attempts:
        status = a.record.get("status")
        verdict = "aceptado" if a.accepted else "rechazado"
        lines.append(f"### Intento {a.number}: {status}, {verdict}")
        if a.feedback:
            lines.append(f"> {a.feedback}")
        if a.patch_diff:
            lines += ["<details><summary>diff</summary>", "", "```diff", a.patch_diff.strip(),
                      "```", "</details>"]
        lines.append("")
    return lines


def decide(finding: Finding, loop, repo_root: Path, verdict: str | None = None) -> Decision:
    """What to publish for a finding after the reflexive loop."""
    from repair_loop import ACCEPTED

    head = _header(finding, verdict)
    n = loop.iterations
    if loop.outcome == ACCEPTED:
        accepted = next(a for a in loop.attempts if a.accepted)
        notes = caveats(finding, accepted.record, repo_root)
        labels = [AI_FIXED] + ([AI_NEEDS_REVIEW] if notes else [])
        body = ["## Remediación asistida por IA (revisión humana obligatoria)", "", *head,
                f"- **Intentos**: {accepted.number} de {accepted.record.get('max_attempts', 3)}", "",
                "## Verificación automática", "", *_verification_table(accepted.record), ""]
        if notes:
            body += ["## Por qué revisar con especial atención", "", *[f"- {c}" for c in notes], ""]
        if n > 1:
            body += ["## Intentos anteriores", "", *_history(loop.attempts[:-1]), ""]
        body += ["## Parche", "", "```diff", accepted.patch_diff.strip(), "```", "",
                 "Parche propuesto por el agente (modelo único, ver `scripts/ai_agent/README.md`).",
                 "**No fusionar en `main`**: rama de artefacto experimental sobre código del",
                 "benchmark, intencionadamente vulnerable. Requiere aprobación humana."]
        return Decision("pr", labels, f"fix(ai): {finding.rule_id} en {finding.file}",
                        "\n".join(body), accepted.patch_diff, notes)

    body = ["## Remediación escalada: el agente no logró un parche verificado", "", *head, "",
            f"El bucle reflexivo agotó sus {n} intentos sin un parche que superase la "
            "verificación automática (CodeQL + oráculos de D9). No se ha subido código: "
            "cada intento y el motivo de su rechazo quedan abajo para quien retome el caso.", "",
            *_history(loop.attempts)]
    return Decision("issue", [AI_ESCALATED],
                    f"[ai-escalated] {finding.rule_id} en {finding.file}:{finding.start_line}",
                    "\n".join(body))


def ensure_labels(repo_root: Path, apply: bool = False) -> list[str]:
    """Create/update the three labels (idempotent: ``gh label create --force``)."""
    cmds = [["gh", "label", "create", name, "--color", color, "--description", desc, "--force"]
            for name, (color, desc) in LABELS.items()]
    if apply:
        for cmd in cmds:
            res = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"{' '.join(cmd[:4])}: {res.stderr.strip()}")
    return [" ".join(c[:4]) for c in cmds]


def publish(decision: Decision, finding: Finding, repo_root: Path, base: str = "main",
            commit: bool = False, open_: bool = False) -> str:
    """Dry-run (default) or publish the decision; returns a report."""
    if decision.kind == "pr":
        from remediation_pr import prepare_pr
        return prepare_pr(finding, decision.diff, repo_root, commit=commit or open_, open_pr=open_,
                          base=base, body=decision.body, labels=decision.labels,
                          title=decision.title)
    if not open_:
        return "\n".join([f"(dry-run) gh issue create --label {','.join(decision.labels)}",
                          f"title: {decision.title}", "", decision.body])
    res = subprocess.run(["gh", "issue", "create", "--title", decision.title, "--body-file", "-",
                          *[x for l in decision.labels for x in ("--label", l)]],
                         cwd=repo_root, input=decision.body, capture_output=True, text=True)
    return res.stdout.strip() or res.stderr.strip()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    lb = sub.add_parser("labels", help="create/update the ai-* labels on the GitHub repo")
    lb.add_argument("--repo-root", type=Path, default=Path("."))
    lb.add_argument("--apply", action="store_true", help="really call gh (default: print)")
    args = parser.parse_args()
    done = ensure_labels(args.repo_root, apply=args.apply)
    print(("created/updated:\n  " if args.apply else "(dry-run) would run:\n  ") + "\n  ".join(done))


if __name__ == "__main__":
    main()
