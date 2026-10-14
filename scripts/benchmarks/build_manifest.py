"""Build the dataset manifests from the per-case data and the detection results.

Outputs:
    benchmarks/secbench-js/manifest.json  every vendored SecBench.js case
        (CVE, CWE, package, versions, sink, exploit command) with its C7/C8
        result. The roadmap's Paso 1.3 asks for this manifest.
    benchmarks/dataset.csv  the final evaluation set (Fase 5): the cases of
        both sources that pass C8, one row per vulnerability.

Usage:
    python scripts/benchmarks/build_manifest.py [benchmarks_dir]
"""

import csv
import json
import sys
from pathlib import Path

HARNESS_IMAGE = "tfm/secbench-harness"
JUICE_SHOP_ROOT = "src/app/juice-shop"


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def main() -> None:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("benchmarks")
    secbench = root / "secbench-js"
    detection = {r["case_id"]: r for r in read_csv(secbench / "detection.csv")}

    cases, dataset = [], []
    for path in sorted((secbench / "cases").rglob("case.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        det = detection[case["case_id"]]
        vuln_class, name = case["case_id"].split("/", 1)
        sink_file = f"benchmarks/secbench-js/cases/{case['case_id']}/{case['sink']['file']}"
        cases.append({
            "case_id": case["case_id"],
            "vuln_class": vuln_class,
            "cwe": case["cwe"],
            "cve": case["cve"],
            "package": case["package"],
            "vulnerable_version": case["vulnerable_version"],
            "fixed_version": case["fixed_version"],
            "sink": {"file": sink_file, "line": case["sink"]["line"]},
            "exploit_command": ["docker", "run", "--rm", HARNESS_IMAGE, "run_case", vuln_class, name,
                                case["package"], case["vulnerable_version"]],
            "c7_detected": det["c7_detected"] == "True",
            "c8_trace": det["c8_trace"] == "True",
        })
        if det["c8_trace"] == "True":
            dataset.append({"id": case["case_id"], "source": "secbench-js", "vuln_class": vuln_class,
                            "cwe": case["cwe"], "cve": case["cve"], "file": sink_file,
                            "line": case["sink"]["line"]})

    inventory = {r["vuln_id"]: r for r in read_csv(root / "juice-shop" / "inventory.csv")}
    for det in read_csv(root / "juice-shop" / "detection.csv"):
        if det["c8_trace"] != "True":
            continue
        item = inventory[det["vuln_id"]]
        dataset.append({"id": det["vuln_id"], "source": "juice-shop", "vuln_class": item["vuln_class"],
                        "cwe": item["cwe"], "cve": "", "file": f"{JUICE_SHOP_ROOT}/{item['file']}",
                        "line": det["vuln_lines"].split(";")[0]})

    manifest = {"source": "SecBench.js", "harness": "benchmarks/secbench-js/harness", "cases": cases}
    (secbench / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
                                            newline="\n")
    with (root / "dataset.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(dataset[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(dataset)
    print(f"manifest: {len(cases)} cases; dataset: {len(dataset)} vulnerabilities")


if __name__ == "__main__":
    main()
