"""Catalog every SecBench.js case and apply the static selection criteria.

SecBench.js (Bhuiyan et al., ICSE 2023) ships one folder per vulnerable npm
package version, containing a Jest exploit test and a package.json with the
case metadata. This script reads those folders and writes a CSV catalog with
the static criteria evaluated per case:

    C1  the case has a CVE identifier (traceability to a public advisory);
    C2  a reference fix exists (upstream fix commit or published fixed version);
    C3  the sink lives in the package's own code and the case uses one package.
 Dynamic criteria (exploit
reproduction, scanner detection) are applied later by other scripts.

Usage:
    python scripts/benchmarks/secbench_catalog.py <secbench_dir> <out_csv>
"""

import csv
import json
import re
import sys
from pathlib import Path

# SecBench.js folder -> vulnerability class and CWE used in this project.
CLASSES = {
    "code-injection": ("code-injection", "CWE-94"),
    "command-injection": ("command-injection", "CWE-78"),
    "path-traversal": ("path-traversal", "CWE-22"),
    "prototype-pollution": ("prototype-pollution", "CWE-1321"),
    "redos": ("redos", "CWE-1333"),
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
GITHUB_COMMIT_RE = re.compile(
    r"https://github\.com/([^/\s]+)/([^/\s]+)/(?:pull/\d+/)?commits?/([0-9a-f]{7,40})"
)
SINK_RE = re.compile(r"^(?P<file>[^:\s]+):(?P<line>\d+)(?::\d+)?$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+")

FIELDS = [
    "case_id", "vuln_class", "cwe", "package", "version", "cve",
    "fixed_version", "fix_repo", "fix_commit", "sink_file", "sink_line",
    "test_file", "c1_has_cve", "c2_has_fix_reference", "c3_sink_in_package",
    "static_eligible",
]


def load_metadata(path: Path) -> dict:
    # Some upstream files contain raw newlines inside strings (e.g. fixCommit),
    # which strict JSON rejects.
    return json.loads(path.read_text(encoding="utf-8"), strict=False)


def parse_case(class_dir: str, case_dir: Path) -> dict | None:
    meta_path = case_dir / "package.json"
    tests = sorted(case_dir.glob("*.test.js"))
    if not meta_path.is_file() or not tests:
        return None
    meta = load_metadata(meta_path)
    vuln_class, cwe = CLASSES[class_dir]

    deps = meta.get("dependencies") or {}
    package, version = next(iter(deps.items()), ("", ""))

    cve_match = CVE_RE.search(str(meta.get("id", "")))
    fix_match = GITHUB_COMMIT_RE.search(str(meta.get("fixCommit", "")))
    # Upstream writes "n/a", ">=1.2.3" or "1.2.3"; keep only a concrete version.
    fixed_version = str(meta.get("fixedVersion", "")).strip().lstrip(">=^~ ")
    if not VERSION_RE.match(fixed_version):
        fixed_version = ""

    # Upstream uses both "sink" and "sinkLocation" for the same field.
    sink = str(meta.get("sink") or meta.get("sinkLocation") or "").strip()
    sink_match = SINK_RE.match(sink)
    sink_file = sink_match["file"] if sink_match else ""

    c1 = bool(cve_match)
    # A reference fix (upstream commit, or a published fixed version whose
    # code can be diffed against the vulnerable one) is the ground truth
    # against which the LLM patch is compared.
    c2 = bool(fix_match) or bool(fixed_version)
    # The vulnerable code must live in the package itself (not in one of its
    # dependencies) and the case must exercise exactly one package, so that
    # the scan target and the patch scope are a single, well-defined codebase.
    c3 = bool(sink_file) and "node_modules" not in sink_file and len(deps) == 1

    return {
        "case_id": f"{class_dir}/{case_dir.name}",
        "vuln_class": vuln_class,
        "cwe": cwe,
        "package": package,
        "version": version,
        "cve": cve_match.group(0) if cve_match else "",
        "fixed_version": fixed_version,
        "fix_repo": f"{fix_match[1]}/{fix_match[2]}" if fix_match else "",
        "fix_commit": fix_match[3] if fix_match else "",
        "sink_file": sink_file,
        "sink_line": sink_match["line"] if sink_match else "",
        "test_file": tests[0].name,
        "c1_has_cve": c1,
        "c2_has_fix_reference": c2,
        "c3_sink_in_package": c3,
        "static_eligible": c1 and c2 and c3,
    }


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    root, out_csv = Path(sys.argv[1]), Path(sys.argv[2])

    rows = []
    for class_dir in CLASSES:
        for case_dir in sorted(p for p in (root / class_dir).iterdir() if p.is_dir()):
            row = parse_case(class_dir, case_dir)
            if row:
                rows.append(row)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    print(f"{'class':<22}{'total':>7}{'C1':>6}{'C1+C2':>7}{'C1-C3':>7}")
    for vuln_class, _ in CLASSES.values():
        subset = [r for r in rows if r["vuln_class"] == vuln_class]
        c1 = [r for r in subset if r["c1_has_cve"]]
        c12 = [r for r in c1 if r["c2_has_fix_reference"]]
        c123 = [r for r in c12 if r["c3_sink_in_package"]]
        print(f"{vuln_class:<22}{len(subset):>7}{len(c1):>6}{len(c12):>7}{len(c123):>7}")
    print(f"{'TOTAL':<22}{len(rows):>7}"
          f"{sum(r['c1_has_cve'] for r in rows):>6}"
          f"{sum(r['c1_has_cve'] and r['c2_has_fix_reference'] for r in rows):>7}"
          f"{sum(r['static_eligible'] for r in rows):>7}")


if __name__ == "__main__":
    main()
