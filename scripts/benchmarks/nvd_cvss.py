"""NVD CVSS of each SecBench.js case's CVE, next to CodeQL's per-rule severity (D11).

CodeQL's ``security-severity`` is one number per *rule*; the CVSS that NVD gives a
CVE is assessed per *vulnerability*. This script records both for the dataset so
the gap that motivates D11 is reproducible: it reads the CVE of every case
(``benchmarks/dataset.csv``), fetches its record from the NVD API 2.0 (public, no
key; ~6 s between requests to stay within the anonymous rate limit) and writes
``benchmarks/nvd-cvss.csv`` with the NVD primary CVSS v3.x and v2 base scores and
the CodeQL severity of the case's target finding
(``benchmarks/remediation-targets.csv``).

Only CVE ids are sent. Juice Shop cases have no CVE and are skipped.

Usage:
    python scripts/benchmarks/nvd_cvss.py [--cache DIR]
"""

from __future__ import annotations

import argparse
import csv
import json
import time
import urllib.request
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DATASET = REPO / "benchmarks" / "dataset.csv"
TARGETS = REPO / "benchmarks" / "remediation-targets.csv"
OUT = REPO / "benchmarks" / "nvd-cvss.csv"
API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
FIELDS = ["id", "cve", "codeql_severity", "nvd_v3", "nvd_v3_severity", "nvd_v2", "fetched"]


def fetch(cve: str, cache: Path | None) -> dict:
    cached = cache / f"{cve}.json" if cache else None
    if cached and cached.is_file() and cached.stat().st_size:
        return json.loads(cached.read_text(encoding="utf-8"))
    req = urllib.request.Request(API + cve, headers={"User-Agent": "tfm-research-client"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    if cached:
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_text(json.dumps(data), encoding="utf-8")
    time.sleep(6.5)
    return data


def primary(metrics: dict, *keys: str) -> dict | None:
    """The NVD 'Primary' cvssData of the first metric family present."""
    for key in keys:
        entries = metrics.get(key) or []
        for e in entries:
            if e.get("type") == "Primary":
                return e["cvssData"]
        if entries:
            return entries[0]["cvssData"]
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--cache", type=Path, help="directory for raw NVD responses")
    args = parser.parse_args()
    codeql = {r["id"]: r["cvss"] for r in csv.DictReader(TARGETS.open(encoding="utf-8"))}
    rows = []
    for case in csv.DictReader(DATASET.open(encoding="utf-8")):
        if not case["cve"]:
            continue
        metrics = fetch(case["cve"], args.cache)["vulnerabilities"][0]["cve"].get("metrics", {})
        v3 = primary(metrics, "cvssMetricV31", "cvssMetricV30")
        v2 = primary(metrics, "cvssMetricV2")
        rows.append({"id": case["id"], "cve": case["cve"], "codeql_severity": codeql[case["id"]],
                     "nvd_v3": v3["baseScore"] if v3 else "",
                     "nvd_v3_severity": v3.get("baseSeverity", "") if v3 else "",
                     "nvd_v2": v2["baseScore"] if v2 else "", "fetched": date.today().isoformat()})
    with OUT.open("w", encoding="utf-8", newline="\n") as fh:
        w = csv.DictWriter(fh, FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    both = [r for r in rows if r["nvd_v3"] != ""]
    agree = sum((float(r["codeql_severity"]) >= 7) == (r["nvd_v3"] >= 7) for r in both)
    print(f"{len(rows)} CVEs -> {OUT.relative_to(REPO)}; CodeQL and NVD v3 agree on >=7 "
          f"for {agree}/{len(both)}")


if __name__ == "__main__":
    main()
