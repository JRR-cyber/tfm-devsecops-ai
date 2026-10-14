"""Match scanner findings (SARIF) against the Juice Shop inventory (C7, C8).

Same criteria as secbench_detect.py, adapted to Juice Shop:

    C7  detection: a finding within LINE_WINDOW lines of one of the
        vulnerability's marked lines (``vuln-code-snippet vuln-line
        <challenge>`` comments in the source), from a rule tagged with the
        inventory's CWE. Juice Shop marks the exact vulnerable lines, so the
        window is tighter than SecBench.js's sink window.
    C8  trace: one of those findings carries a taint trace with two or more
        steps.

Only rows with status ``candidate`` are evaluated.

Usage:
    python scripts/benchmarks/juiceshop_detect.py <inventory_csv> <out_csv> <tool>=<sarif>[#<job>] [...]
"""

import csv
import sys
from pathlib import Path

from secbench_detect import load_findings

APP_ROOT = Path("src/app/juice-shop")
LINE_WINDOW = 3
MARKER = "vuln-code-snippet vuln-line"


def vuln_lines(path: Path, challenges: set[str]) -> list[int]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [n for n, line in enumerate(lines, 1)
            if MARKER in line and challenges & set(line.split(MARKER, 1)[1].split())]


def main() -> None:
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    inventory, out_csv = Path(sys.argv[1]), Path(sys.argv[2])
    tools = dict(arg.split("=", 1) for arg in sys.argv[3:])
    findings = {tool: load_findings(spec) for tool, spec in tools.items()}

    with inventory.open(encoding="utf-8") as fh:
        candidates = [r for r in csv.DictReader(fh) if r["status"] == "candidate"]

    rows = []
    for item in candidates:
        uri = (APP_ROOT / item["file"]).as_posix()
        marked = vuln_lines(APP_ROOT / item["file"], set(item["challenges"].split(";")))
        cwe = item["cwe"].removeprefix("CWE-")
        row = {"vuln_id": item["vuln_id"], "cwe": item["cwe"], "file": item["file"],
               "vuln_lines": ";".join(map(str, marked))}
        detected_any = traced_any = False
        for tool, results in findings.items():
            near = [f for f in results
                    if f[0] == uri and any(abs(f[1] - n) <= LINE_WINDOW for n in marked)]
            hits = [f for f in near if cwe in f[3]]
            row[f"{tool}_detected"] = bool(hits)
            row[f"{tool}_rules"] = ";".join(sorted({f[2] for f in hits}))
            row[f"{tool}_near_unrelated"] = ";".join(sorted({f[2] for f in near if f not in hits}))
            row[f"{tool}_trace_steps"] = max((f[4] for f in hits), default=0)
            detected_any |= bool(hits)
            traced_any |= row[f"{tool}_trace_steps"] >= 2
        row["c7_detected"] = detected_any
        row["c8_trace"] = traced_any
        rows.append(row)

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    for row in rows:
        print(f"{row['vuln_id']:<7}{row['cwe']:<9}{'C7' if row['c7_detected'] else '  '} "
              f"{'C8' if row['c8_trace'] else '  '} {row['file']}")
    print(f"TOTAL candidates={len(rows)} C7={sum(r['c7_detected'] for r in rows)} "
          f"C8={sum(r['c8_trace'] for r in rows)}")


if __name__ == "__main__":
    main()
