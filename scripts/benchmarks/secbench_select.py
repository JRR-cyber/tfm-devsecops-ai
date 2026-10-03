"""Draw a stratified, seeded sample of candidate cases from the catalog.

Only statically eligible cases (C1-C3, see secbench_catalog.py) are drawn.
The sample is stratified by vulnerability class so that every class is
represented even though the catalog is dominated by prototype pollution.
A fixed seed makes the draw reproducible.

Usage:
    python scripts/benchmarks/secbench_select.py <catalog_csv> <out_csv> [per_class] [seed]
"""

import csv
import random
import sys
from pathlib import Path

DEFAULT_PER_CLASS = 10
DEFAULT_SEED = 20260930


def main() -> None:
    if len(sys.argv) not in (3, 4, 5):
        sys.exit(__doc__)
    catalog, out_csv = Path(sys.argv[1]), Path(sys.argv[2])
    per_class = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PER_CLASS
    seed = int(sys.argv[4]) if len(sys.argv) > 4 else DEFAULT_SEED

    with catalog.open(encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r["static_eligible"] == "True"]

    rng = random.Random(seed)
    selected = []
    for vuln_class in sorted({r["vuln_class"] for r in rows}):
        pool = sorted((r for r in rows if r["vuln_class"] == vuln_class),
                      key=lambda r: r["case_id"])
        # One case per package, so a single library can't dominate a class.
        seen, unique = set(), []
        for r in rng.sample(pool, len(pool)):
            if r["package"] not in seen:
                seen.add(r["package"])
                unique.append(r)
        picked = sorted(unique[:per_class], key=lambda r: r["case_id"])
        selected.extend(picked)
        print(f"{vuln_class:<22} eligible={len(pool):>3} "
              f"packages={len(unique):>3} selected={len(picked):>3}")

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(selected[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(selected)
    print(f"TOTAL selected={len(selected)} (seed={seed})")


if __name__ == "__main__":
    main()
