"""Assign a CVSS-comparable score to every finding and apply the >=7 filter (Paso 3.3).

The roadmap only auto-remediates findings with CVSS >= 7.0; the rest are
reported. To apply one threshold across tools that disagree on how they express
severity, this module turns each finding into a single number on the CVSS 0-10
scale:

- **CodeQL / Trivy**: already carry a numeric ``security-severity`` (CVSS),
  parsed in 3.2 (``Finding.security_severity``) — used as-is.
- **Semgrep**: emits no number, only a level (ERROR/WARNING/INFO, surfaced as
  SARIF error/warning/note). It is mapped to the representative value of the
  matching CVSS v3.1 qualitative band (see ``SEMGREP_LEVEL_CVSS``). Only the
  >= 7 boundary matters for the filter, and only ``error`` crosses it.
- **TruffleHog**: a hard-coded secret (CWE-798) is treated as Critical.

This is *policy*, not a SARIF fact, so it lives here and not in the parser. The
mapping and its rationale are documented in ``scripts/ai_agent/README.md``
(section "Mapeo de severidad"). The module classifies by severity only; whether a
high finding is actually auto-remediated (e.g. only CodeQL findings with a taint
trace, per D8/3.4) is decided when this is composed with the later steps.
"""

from __future__ import annotations

from dataclasses import dataclass

from sarif_parser import Finding

# CVSS v3.1 qualitative severity rating scale:
#   None 0.0 | Low 0.1-3.9 | Medium 4.0-6.9 | High 7.0-8.9 | Critical 9.0-10.0
AUTO_REMEDIATION_THRESHOLD = 7.0

# Semgrep SARIF level (ERROR/WARNING/INFO) -> representative value of its CVSS
# band. ERROR is treated as High (it is the level Semgrep uses for the security
# rules meant to be fixed), so it is the only level that reaches the threshold.
SEMGREP_LEVEL_CVSS = {
    "error": 8.0,     # High
    "warning": 5.0,   # Medium
    "note": 2.0,      # Low
}

# A verified hard-coded credential (CWE-798) is a Critical finding.
TRUFFLEHOG_CVSS = 9.0


def band(score: float | None) -> str:
    """CVSS v3.1 qualitative label for a score."""
    if score is None:
        return "unknown"
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


@dataclass
class Score:
    """The severity decision for one finding, with its provenance (for audit)."""

    cvss: float | None
    band: str
    source: str              # tool | semgrep-level-map | trufflehog-constant | none
    auto_remediable: bool    # cvss is not None and cvss >= threshold


def score(finding: Finding) -> Score:
    """Resolve a finding's CVSS-comparable score and whether it clears the filter."""
    if finding.security_severity is not None:
        cvss, source = finding.security_severity, "tool"
    elif finding.job == "semgrep":
        cvss = SEMGREP_LEVEL_CVSS.get((finding.level or "").lower())
        source = "semgrep-level-map" if cvss is not None else "none"
    elif finding.job == "trufflehog":
        cvss, source = TRUFFLEHOG_CVSS, "trufflehog-constant"
    else:
        cvss, source = None, "none"
    return Score(
        cvss=cvss,
        band=band(cvss),
        source=source,
        auto_remediable=cvss is not None and cvss >= AUTO_REMEDIATION_THRESHOLD,
    )


def high_severity(findings: list[Finding]) -> list[Finding]:
    """Findings that clear the CVSS >= 7.0 filter (severity only, no trace gate)."""
    return [f for f in findings if score(f).auto_remediable]


def _summary(findings: list[Finding]) -> str:
    from collections import Counter
    rows: dict[str, Counter] = {}
    for f in findings:
        s = score(f)
        r = rows.setdefault(f.job, Counter())
        r["total"] += 1
        r[s.band] += 1
        if s.auto_remediable:
            r["high+"] += 1
        if s.auto_remediable and f.has_trace:
            r["high+trace"] += 1
    out = ["| Job | Total | critical | high | medium | low | unknown | CVSS>=7 | CVSS>=7 y con traza |",
           "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    tot = Counter()
    for job in sorted(rows):
        r = rows[job]
        tot.update(r)
        out.append(f"| {job} | {r['total']} | {r['critical']} | {r['high']} | {r['medium']} "
                   f"| {r['low']} | {r['unknown']} | {r['high+']} | {r['high+trace']} |")
    out.append(f"| **total** | **{tot['total']}** | {tot['critical']} | {tot['high']} | {tot['medium']} "
               f"| {tot['low']} | {tot['unknown']} | **{tot['high+']}** | **{tot['high+trace']}** |")
    return "\n".join(out)


def main() -> None:
    import argparse
    from pathlib import Path
    from sarif_parser import parse_sarif

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sarif", type=Path, help="unified/findings.sarif")
    args = parser.parse_args()
    findings = parse_sarif(args.sarif)
    print(_summary(findings))


if __name__ == "__main__":
    main()
