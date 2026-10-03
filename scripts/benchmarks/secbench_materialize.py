"""Vendor the source of every verified SecBench.js case into the repository.

The pipeline scans and patches files in this repository, so each verified
case's vulnerable package is extracted here exactly as published on npm
(`npm pack`), together with a manifest describing the case. The package's
own license file travels with its source.

Usage:
    python scripts/benchmarks/secbench_materialize.py <verification_csv> <cases_dir>
"""

import csv
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

SECBENCH_REPO = "https://github.com/cristianstaicu/SecBench.js"
SECBENCH_COMMIT = "5d362353550a8baa42bba34edd26e5fb86d41b60"


def npm_pack(spec: str, dest: Path) -> Path:
    out = subprocess.run(["npm", "pack", spec, "--json", "--pack-destination", str(dest)],
                         capture_output=True, text=True, check=True, shell=sys.platform == "win32")
    return dest / json.loads(out.stdout)[0]["filename"]


def resolve_sink(src: Path, sink_file: str, sink_line: int) -> dict:
    """Locate the upstream sink in the npm source.

    Upstream sink paths are sometimes bare file names (``marked.js`` for
    ``lib/marked.js``) or were measured on the git sources, whose line
    numbers can differ from the published package. The file is resolved by
    name when unambiguous; ``line_verified`` says whether the line exists.
    """
    path = src / sink_file
    if not path.is_file():
        matches = [p for p in src.rglob(Path(sink_file).name) if p.is_file()]
        path = matches[0] if len(matches) == 1 else None
    if path is None:
        return {"file": None, "line": sink_line, "line_verified": False,
                "upstream": f"{sink_file}:{sink_line}"}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return {"file": path.relative_to(src.parent).as_posix(), "line": sink_line,
            "line_verified": 0 < sink_line <= len(lines) and bool(lines[sink_line - 1].strip()),
            "upstream": f"{sink_file}:{sink_line}"}


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    verification, cases_dir = Path(sys.argv[1]), Path(sys.argv[2])

    with verification.open(encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r["verified"] == "True"]
    catalog_path = verification.parent / "catalog.csv"
    with catalog_path.open(encoding="utf-8") as fh:
        catalog = {r["case_id"]: r for r in csv.DictReader(fh)}

    for row in rows:
        meta = catalog[row["case_id"]]
        target = cases_dir / row["case_id"]
        if target.exists():
            shutil.rmtree(target)
        with tempfile.TemporaryDirectory() as tmp:
            tarball = npm_pack(f"{row['package']}@{row['version']}", Path(tmp))
            with tarfile.open(tarball) as tar:
                tar.extractall(tmp, filter="data")
            # npm tarballs nest everything under a top-level "package/" dir.
            shutil.copytree(Path(tmp) / "package", target / "src")

        manifest = {
            "case_id": row["case_id"],
            "source": {"dataset": "SecBench.js", "repo": SECBENCH_REPO,
                       "commit": SECBENCH_COMMIT,
                       "exploit": f"{row['case_id']}/{meta['test_file']}"},
            "vuln_class": row["vuln_class"],
            "cwe": meta["cwe"],
            "cve": row["cve"],
            "package": row["package"],
            "vulnerable_version": row["version"],
            "fixed_version": row["fixed_version"],
            "fix_commit": (f"https://github.com/{meta['fix_repo']}/commit/{meta['fix_commit']}"
                           if meta["fix_commit"] else None),
            "sink": resolve_sink(target / "src", meta["sink_file"], int(meta["sink_line"])),
            "oracle": {"harness": "benchmarks/secbench-js/harness",
                       "command": ["run_case", *row["case_id"].split("/", 1), row["package"]],
                       "vulnerable_run": row["vulnerable_run"],
                       "fixed_run": row["fixed_run"]},
        }
        (target / "case.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        size_kb = sum(f.stat().st_size for f in (target / "src").rglob("*") if f.is_file()) // 1024
        sink = manifest["sink"]
        print(f"{row['case_id']:<50} {size_kb:>6} KB  sink={sink['file']}:{sink['line']}"
              f"{'' if sink['line_verified'] else '  (line not verified)'}")


if __name__ == "__main__":
    main()
