"""Cross-pass input check (D12 addendum 2026-11-26).

Compares prompt_tokens per call between pass 1 and pass n of the same experiment.
Pass: >= 95 % of comparable calls within +-2 of the modal offset, and modal offset == 0.
Triage: every call. Remediation: attempt 1 only.

usage: python scripts/phase5_review/cross_pass.py experiments/phase5/triage-p1.jsonl experiments/phase5/triage-p2.jsonl
"""
import collections as C
import json
import sys


def load(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        if r["kind"] == "remediation" and r.get("attempt") != 1:
            continue
        key = (r["fingerprint"], r["strategy"], r["with_trace"], r["with_rag"])
        out[key] = r
    return out


a, b = load(sys.argv[1]), load(sys.argv[2])
common = sorted(set(a) & set(b))
diffs = [b[k]["prompt_tokens"] - a[k]["prompt_tokens"] for k in common]
mode, _ = C.Counter(diffs).most_common(1)[0]
within = sum(abs(d - mode) <= 2 for d in diffs)
share = within / len(diffs)
print(f"comparable calls: {len(common)} (only in p1: {len(set(a) - set(b))}, only in pn: {len(set(b) - set(a))})")
print(f"offset distribution: {dict(C.Counter(diffs).most_common(6))}")
print(f"modal offset: {mode}; within +-2: {within}/{len(diffs)} = {share:.1%}")
served = C.Counter(r["model_served"] for r in b.values())
print(f"model_served (pn): {dict(served)}")
ok = share >= 0.95 and mode == 0
print("CROSS-PASS CHECK:", "PASS" if ok else "FAIL -> treat as model change (D12 point 1)")
sys.exit(0 if ok else 1)
