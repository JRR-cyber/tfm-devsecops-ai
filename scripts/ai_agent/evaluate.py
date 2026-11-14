"""Dev sanity probe: run the triage over the labelled set in several modes.

NOT the Phase 5 experiment. The prompts are not final (3.6 adds the zero/few/CoT
strategies), there is no statistical test and no fixed protocol here. This is a
development check: it runs the triage decision over the ground-truth triage set
(``benchmarks/triage/labels.csv``) in the chosen context modes and prints how
often the agent agrees with the label. Use it to catch wiring bugs and to get an
early feel for what the trace and the RAG add — not to report results.

It joins labels to findings by the bare fingerprint digest (``Finding.label_key``)
and, by default, keeps only CodeQL findings with a taint trace, since the
trace/no-trace comparison is only meaningful where a trace exists.

Usage (needs GROQ_API_KEY):
    GROQ_API_KEY=... python scripts/ai_agent/evaluate.py <unified.sarif> \
        --labels benchmarks/triage/labels.csv --repo-root . \
        [--modes notrace,trace,trace+rag] [--limit N] [--sleep 1.0] [--verbose]
"""

from __future__ import annotations

import argparse
import csv
import time
from collections import Counter
from pathlib import Path

from sarif_parser import parse_sarif, SourceReader
from triage import decide

MODE_FLAGS = {           # mode name -> (with_trace, with_rag)
    "notrace": (False, False),
    "trace": (True, False),
    "trace+rag": (True, True),
    "rag": (False, True),
}


def load_pairs(sarif: Path, labels_path: Path, repo_root: Path, only_traced: bool):
    """(finding, label) pairs, joined by bare fingerprint digest."""
    findings = parse_sarif(sarif, repo_root)
    by_key: dict[str, list] = {}
    for f in findings:
        by_key.setdefault(f.label_key, []).append(f)
    pairs = []
    for row in csv.DictReader(labels_path.open(encoding="utf-8")):
        matches = by_key.get(row["fingerprint"], [])
        if only_traced:
            matches = [f for f in matches if f.has_trace]
        if matches:
            pairs.append((matches[0], row["label"].upper()))
    return pairs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--labels", type=Path, default=Path("benchmarks/triage/labels.csv"))
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--modes", default="notrace,trace,trace+rag")
    parser.add_argument("--limit", type=int, default=0, help="cap findings (0 = all)")
    parser.add_argument("--sleep", type=float, default=2.0, help="pause between calls (rate limit)")
    parser.add_argument("--verbose", action="store_true", help="print every per-case verdict")
    args = parser.parse_args()

    from groq_client import GroqClient
    client = GroqClient()
    reader = SourceReader(args.repo_root)
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    pairs = load_pairs(args.sarif, args.labels, args.repo_root, only_traced=True)
    if args.limit:
        pairs = pairs[:args.limit]
    print(f"{len(pairs)} labelled CodeQL-with-trace findings; modes: {', '.join(modes)}\n")

    for mode in modes:
        with_trace, with_rag = MODE_FLAGS[mode]
        agree = 0
        confusion: Counter = Counter()   # (truth, verdict)
        errors = 0
        first_error = ""
        print(f"[{mode}] ", end="", flush=True)
        for finding, truth in pairs:
            try:
                v = decide(finding, client, reader, with_trace=with_trace, with_rag=with_rag).verdict
            except Exception as err:   # noqa: BLE001 - keep the batch going
                errors += 1
                first_error = first_error or str(err)
                print("!", end="", flush=True)
                continue
            confusion[(truth, v)] += 1
            if v == truth:
                agree += 1
            print("." if v == truth else "x", end="", flush=True)
            if args.verbose:
                mark = "ok " if v == truth else "XX "
                print(f"\n  {mark} truth={truth:9} verdict={v:9} {finding.rule_id} {finding.file}:{finding.start_line}",
                      end="", flush=True)
            time.sleep(args.sleep)
        print()

        done = len(pairs) - errors
        pct = f"{100 * agree / done:.0f}%" if done else "-"
        print(f"== {mode}: agreement {agree}/{done} ({pct})" + (f", {errors} errors" if errors else ""))
        if first_error:
            print(f"   first error: {first_error[:120]}")
        # FP recall: of the FP-labelled, how many the agent called FP (the RAG target)
        fp_total = sum(n for (t, _), n in confusion.items() if t == "FP")
        fp_hit = confusion[("FP", "FP")]
        tp_total = sum(n for (t, _), n in confusion.items() if t == "TP")
        tp_hit = confusion[("TP", "TP")]
        if fp_total:
            print(f"   FP correctly flagged: {fp_hit}/{fp_total}")
        if tp_total:
            print(f"   TP correctly flagged: {tp_hit}/{tp_total}")
        print()


if __name__ == "__main__":
    main()
