"""Apply the dynamic selection criteria to the candidate cases.

    C4  consistency: the case's package is one of the npm packages that OSV
        lists for the case's CVE (follows GHSA aliases). Catches mislabeled
        upstream cases.
    C5  reproduction: the exploit succeeds against the vulnerable version.
    C6  oracle validity: the exploit fails against the fixed version, so the
        exploit test really discriminates vulnerable from fixed code.

A case is verified when C4, C5 and C6 hold. C6 needs a published fixed
version; cases that only have a fix commit are reported but not verified.

Requires Docker and the harness image:
    docker build -t tfm/secbench-harness benchmarks/secbench-js/harness

Usage:
    python scripts/benchmarks/secbench_verify.py <candidates_csv> <out_csv> [workers]
    python scripts/benchmarks/secbench_verify.py --recheck-osv <verification_csv>
"""

import csv
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

IMAGE = "tfm/secbench-harness"
OSV_URL = "https://api.osv.dev/v1/vulns/{}"
GHSA_RE = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")
RUN_TIMEOUT_S = 300

EXIT_LABELS = {0: "exploited", 1: "not_exploited", 3: "install_failed"}


def osv(vuln_id: str) -> dict:
    with urllib.request.urlopen(OSV_URL.format(vuln_id), timeout=30) as resp:
        return json.load(resp)


def npm_packages_for(cve: str) -> set[str]:
    """npm package names OSV associates with a CVE, directly or via GHSA."""
    names: set[str] = set()
    try:
        record = osv(cve)
    except urllib.error.HTTPError as err:
        # Many CVEs are only stored under their GHSA id; OSV then answers 404
        # and names the aliases in the error message.
        body = err.read().decode("utf-8", errors="replace")
        record = {"aliases": GHSA_RE.findall(body)}
    except OSError:
        return names
    records = [record] if "affected" in record else []
    for alias in record.get("aliases", []):
        if alias.startswith("GHSA-"):
            try:
                records.append(osv(alias))
            except OSError:
                pass
    for rec in records:
        for affected in rec.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("ecosystem") == "npm":
                names.add(pkg["name"])
    return names


def run_exploit(row: dict, version: str) -> str:
    vuln_class, case = row["case_id"].split("/", 1)
    name = f"secbench-{uuid.uuid4().hex[:12]}"
    cmd = ["docker", "run", "--rm", "--name", name, IMAGE, "run_case",
           vuln_class, case, row["package"], version]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=RUN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        # Docker leaves the container running after the client is killed.
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        return "timeout"
    return EXIT_LABELS.get(proc.returncode, f"error_{proc.returncode}")


def verify(row: dict) -> dict:
    osv_pkgs = npm_packages_for(row["cve"])
    c4 = row["package"] in osv_pkgs

    vulnerable = run_exploit(row, row["version"])
    fixed = run_exploit(row, row["fixed_version"]) if row["fixed_version"] else "no_fixed_version"

    c5 = vulnerable == "exploited"
    c6 = fixed == "not_exploited"
    result = {
        "case_id": row["case_id"],
        "vuln_class": row["vuln_class"],
        "package": row["package"],
        "version": row["version"],
        "fixed_version": row["fixed_version"],
        "cve": row["cve"],
        "osv_npm_packages": ";".join(sorted(osv_pkgs)),
        "vulnerable_run": vulnerable,
        "fixed_run": fixed,
        "c4_consistent": c4,
        "c5_reproduces": c5,
        "c6_fix_blocks_exploit": c6,
        "verified": c4 and c5 and c6,
    }
    print(f"{row['case_id']:<50} C4={c4!s:<5} vuln={vulnerable:<15} fixed={fixed}",
          flush=True)
    return result


def main() -> None:
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)

    if sys.argv[1] == "--recheck-osv":
        out_csv = Path(sys.argv[2])
        with out_csv.open(encoding="utf-8") as fh:
            results = [recheck_osv(r) for r in csv.DictReader(fh)]
    else:
        candidates, out_csv = Path(sys.argv[1]), Path(sys.argv[2])
        workers = int(sys.argv[3]) if len(sys.argv) > 3 else 4
        with candidates.open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(verify, rows))

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(results[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(results)
    print_summary(results)


def recheck_osv(row: dict) -> dict:
    """Recompute C4 on an existing result row without re-running exploits."""
    osv_pkgs = npm_packages_for(row["cve"])
    row["osv_npm_packages"] = ";".join(sorted(osv_pkgs))
    row["c4_consistent"] = row["package"] in osv_pkgs
    row["c5_reproduces"] = row["c5_reproduces"] in (True, "True")
    row["c6_fix_blocks_exploit"] = row["c6_fix_blocks_exploit"] in (True, "True")
    row["verified"] = row["c4_consistent"] and row["c5_reproduces"] and row["c6_fix_blocks_exploit"]
    return row


def print_summary(results: list[dict]) -> None:
    criteria = ["c4_consistent", "c5_reproduces", "c6_fix_blocks_exploit", "verified"]
    print(f"\n{'class':<22}{'cand':>6}{'C4':>5}{'C5':>5}{'C6':>5}{'ok':>5}")
    groups = sorted({r["vuln_class"] for r in results}) + ["TOTAL"]
    for group in groups:
        s = results if group == "TOTAL" else [r for r in results if r["vuln_class"] == group]
        counts = "".join(f"{sum(bool(r[c]) for r in s):>5}" for c in criteria)
        print(f"{group:<22}{len(s):>6}{counts}")


if __name__ == "__main__":
    main()
