"""Match scanner findings (SARIF) against the known sink of every case.

    C7  detection: at least one scanner reports a finding in the case's sink
        file within SINK_WINDOW lines of the sink, from a rule tagged with a
        CWE of the case's vulnerability class. Without such a finding there
        is nothing for the pipeline to triage or remediate.

The CWE check matters: a rule firing next to the sink for an unrelated reason
(e.g. "HTTP server without TLS" beside a path traversal) is a coincidence,
not a detection. Those are reported as ``<tool>_near_sink_unrelated``.
Findings elsewhere in the package are counted too (``other_findings``): they
are the noise the triage stage has to filter.

    C8  trace: at least one finding counted for C7 carries a taint trace
        (SARIF ``codeFlows``) with two or more steps, i.e. source and sink
        are distinct. The hybrid triage (Fase 3) feeds that trace to the LLM;
        a finding without it gives the LLM nothing beyond the sink line.
        ``<tool>_trace_steps`` is the longest such trace (0 = none).

SARIF locations must be relative to the repository root or to its
``benchmarks/secbench-js/`` folder (e.g. ``cases/redos/ms_0.7.0/src/...``).
For the pipeline's unified log, ``<sarif>#<job>`` keeps only the runs of
that job (``unified/findings.sarif#codeql``).

Usage:
    python scripts/benchmarks/secbench_detect.py <cases_dir> <out_csv> <tool>=<sarif>[#<job>] [...]
"""

import csv
import json
import re
import sys
from pathlib import Path

SINK_WINDOW = 10
CASES_PREFIX = "benchmarks/secbench-js/"
CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

# CWEs accepted as a detection of each vulnerability class (the class CWE
# plus its closest parents/variants used by scanner rule sets).
CLASS_CWES = {
    "code-injection": {"94", "95", "96"},
    "command-injection": {"77", "78", "88"},
    "path-traversal": {"22", "23", "35", "73"},
    "prototype-pollution": {"1321", "915", "471"},
    "redos": {"1333", "185", "400", "730"},
}


def rule_cwes(run: dict) -> dict[str, set[str]]:
    """CWE numbers per rule id, from the tags/properties of the SARIF rules.

    CodeQL declares its rules in ``tool.extensions`` (the query packs), not in
    the driver, and zero-pads the CWE (``external/cwe/cwe-079``).
    """
    tool = run.get("tool", {})
    components = [tool.get("driver", {})] + tool.get("extensions", [])
    cwes = {}
    for rule in (r for c in components for r in c.get("rules", [])):
        props = json.dumps(rule.get("properties", {}))
        cwes[rule.get("id", "")] = {str(int(n)) for n in CWE_RE.findall(props)}
    return cwes


def trace_steps(result: dict) -> int:
    """Steps of the longest threadFlow of a result (0 without codeFlows)."""
    return max((len(tf.get("locations", []))
                for cf in result.get("codeFlows", []) for tf in cf.get("threadFlows", [])), default=0)


def load_findings(spec: str) -> list[tuple[str, int, str, set[str], int]]:
    """(uri, line, rule_id, cwes, trace_steps) for every result in a SARIF file."""
    path, _, job = spec.partition("#")
    sarif = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = []
    for run in sarif.get("runs", []):
        if job and run.get("automationDetails", {}).get("id", "").rstrip("/") != job:
            continue
        cwes = rule_cwes(run)
        for result in run.get("results", []):
            for loc in result.get("locations", [])[:1]:
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", 0)
                uri = uri.removeprefix("file://").lstrip("/").removeprefix(CASES_PREFIX)
                rule = result.get("ruleId", "")
                findings.append((uri, line, rule, cwes.get(rule, set()), trace_steps(result)))
    return findings


def main() -> None:
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    cases_dir, out_csv = Path(sys.argv[1]), Path(sys.argv[2])
    tools = dict(arg.split("=", 1) for arg in sys.argv[3:])
    findings = {tool: load_findings(spec) for tool, spec in tools.items()}

    rows = []
    for manifest_path in sorted(cases_dir.rglob("case.json")):
        case = json.loads(manifest_path.read_text(encoding="utf-8"))
        prefix = f"cases/{case['case_id']}/"
        sink_file = f"cases/{case['case_id']}/{case['sink']['file']}" if case["sink"]["file"] else None
        sink_line = case["sink"]["line"]

        row = {"case_id": case["case_id"], "vuln_class": case["vuln_class"],
               "sink": f"{case['sink']['file']}:{sink_line}"}
        detected_any = traced_any = False
        accepted = CLASS_CWES[case["vuln_class"]]
        for tool, results in findings.items():
            in_case = [f for f in results if f[0].startswith(prefix)]
            near = [f for f in in_case
                    if f[0] == sink_file and abs(f[1] - sink_line) <= SINK_WINDOW]
            at_sink = [f for f in near if f[3] & accepted]
            unrelated = [f for f in near if not f[3] & accepted]
            row[f"{tool}_at_sink"] = bool(at_sink)
            row[f"{tool}_sink_rules"] = ";".join(sorted({f[2] for f in at_sink}))
            row[f"{tool}_near_sink_unrelated"] = ";".join(sorted({f[2] for f in unrelated}))
            row[f"{tool}_other_findings"] = len(in_case) - len(at_sink)
            row[f"{tool}_trace_steps"] = max((f[4] for f in at_sink), default=0)
            detected_any |= bool(at_sink)
            traced_any |= row[f"{tool}_trace_steps"] >= 2
        row["c7_detected"] = detected_any
        row["c8_trace"] = traced_any
        rows.append(row)

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    print(f"{'class':<22}{'cases':>6}" + "".join(f"{t:>10}" for t in tools) + f"{'C7':>6}{'C8':>6}")
    groups = sorted({r["vuln_class"] for r in rows}) + ["TOTAL"]
    for group in groups:
        s = rows if group == "TOTAL" else [r for r in rows if r["vuln_class"] == group]
        per_tool = "".join(f"{sum(r[f'{t}_at_sink'] for r in s):>10}" for t in tools)
        print(f"{group:<22}{len(s):>6}{per_tool}{sum(r['c7_detected'] for r in s):>6}"
              f"{sum(r['c8_trace'] for r in s):>6}")


if __name__ == "__main__":
    main()
