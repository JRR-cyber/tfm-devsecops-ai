"""Append-only, resumable results log (JSONL) for every agent attempt (Paso 4.5).

The reflexive loop (4.7) and the Phase 5 grid make hundreds of LLM calls and
rescans on a rate-limited API. A run can stop at any point (429 back-off giving
up, a crash, Ctrl+C, a power cut), so results are written **one JSON line per
attempt, as soon as it finishes**, and a relaunched run skips the attempts that
are already in the log instead of paying for them again.

Each line carries:

- the **key** that identifies the attempt — ``kind`` (triage | remediation),
  ``fingerprint`` (label_key), ``strategy``, ``with_trace``, ``with_rag``,
  ``attempt`` — used for resuming and never duplicated;
- the **outcome** — triage verdict, or patch status (FIXED / NOT_FIXED /
  APPLY_FAILED / NO_DIFF) with NEW / RELOCATED / PERSISTING counts from 4.3/4.4;
- the **cost** — prompt/completion tokens, LLM seconds, rescan seconds (overhead);
- the **provenance** — model reported by the API, CodeQL version, agent commit,
  base commit, timestamp, and the model's raw reply (audit; the API is not
  deterministic enough to re-derive it later, and the model may be retired).

Robustness: lines are written with a single ``write`` + ``flush`` + ``fsync``. A
line cut off by a crash (no trailing newline, invalid JSON) is detected on open,
truncated away and counted in ``repaired``, so the next append starts clean.

Usage:
    python scripts/ai_agent/results.py summary results/run.jsonl
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1
TRIAGE, REMEDIATION = "triage", "remediation"
NO_DIFF, APPLY_FAILED = "NO_DIFF", "APPLY_FAILED"

# Groq list price for openai/gpt-oss-120b (USD per million tokens), as published
# by price trackers on 2026-11-14. Used only for the summary's cost *estimate*.
PRICE_INPUT_PER_M = 0.15
PRICE_OUTPUT_PER_M = 0.60


@dataclass(frozen=True)
class RunKey:
    """Identity of one attempt; a log never holds two lines with the same key."""

    kind: str           # triage | remediation
    fingerprint: str    # label_key (bare digest) of the finding
    strategy: str       # zero-shot | few-shot | cot
    with_trace: bool
    with_rag: bool
    attempt: int = 1    # 1..3 for remediation (reflexive loop); 1 for triage

    @classmethod
    def from_record(cls, rec: dict) -> "RunKey":
        return cls(rec["kind"], rec["fingerprint"], rec["strategy"],
                   bool(rec["with_trace"]), bool(rec["with_rag"]), int(rec.get("attempt", 1)))


def environment(repo_root: Path | None = None, codeql_version: str | None = None) -> dict:
    """Provenance fields stamped on every line of a run."""
    from groq_client import MODEL

    commit = None
    if repo_root is not None:
        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_root,
                             text=True, capture_output=True)
        commit = res.stdout.strip() or None
    return {"model_requested": MODEL, "codeql_version": codeql_version,
            "agent_commit": commit, "python": platform.python_version()}


class ResultLog:
    """JSONL results file with resume support."""

    def __init__(self, path: Path, env: dict | None = None):
        self.path = Path(path)
        self.env = env or {}
        self.repaired = 0                    # truncated/corrupt lines dropped on open
        self._records: dict[RunKey, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        data = self.path.read_bytes()
        if data and not data.endswith(b"\n"):
            # A crash mid-write left a partial last line: cut it off so the next
            # append starts on a fresh line, and count it.
            cut = data.rfind(b"\n") + 1
            self.path.write_bytes(data[:cut])
            data = data[:cut]
            self.repaired += 1
        for line in data.decode("utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                self._records[RunKey.from_record(rec)] = rec
            except (ValueError, KeyError, TypeError):
                self.repaired += 1

    def done(self, key: RunKey) -> bool:
        return key in self._records

    def get(self, key: RunKey) -> dict | None:
        return self._records.get(key)

    def records(self) -> list[dict]:
        return list(self._records.values())

    def append(self, key: RunKey, outcome: dict) -> dict:
        """Write one attempt; refuses to overwrite an attempt already logged."""
        if key in self._records:
            raise ValueError(f"attempt already logged: {key}")
        rec = {"schema": SCHEMA_VERSION, **asdict(key), **outcome, **self.env,
               "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        self._records[key] = rec
        return rec


# ------------------------------------------------------------------ record builders

def _finding_fields(finding) -> dict:
    return {"rule": finding.rule_id, "file": finding.file, "line": finding.start_line,
            "cvss": finding.security_severity}


def _usage_fields(usage) -> dict:
    return {"prompt_tokens": usage.prompt_tokens, "completion_tokens": usage.completion_tokens,
            "llm_seconds": usage.seconds, "model_served": usage.model}


def triage_outcome(finding, verdict) -> dict:
    """Outcome fields of a triage attempt (``triage.TriageVerdict``)."""
    return {**_finding_fields(finding), "verdict": verdict.verdict,
            "confidence": verdict.confidence, "rationale": verdict.rationale,
            **_usage_fields(verdict.usage), "raw": verdict.raw}


def remediation_outcome(finding, patch, verification=None, base_sha: str | None = None) -> dict:
    """Outcome fields of a remediation attempt (``remediate.Patch`` + ``Verification``).

    ``verification`` is None when there was no diff to verify.
    """
    out = {**_finding_fields(finding), **_usage_fields(patch.usage), "base_sha": base_sha,
           "diff": patch.diff, "raw": patch.raw}
    if not patch.diff:
        return {**out, "status": NO_DIFF}
    if verification is None or not verification.applied:
        detail = verification.detail if verification else "not verified"
        return {**out, "status": APPLY_FAILED, "apply_detail": detail}
    c = verification.comparison
    cmp = c.as_dict()
    return {**out, "status": c.status, "relocated": c.relocated, "regression": c.regression,
            "new": cmp["new"], "moved": cmp["moved"], "persisting": cmp["persisting"],
            "disappeared": cmp["disappeared"], "apply_detail": verification.detail,
            "baseline_cached": verification.baseline_cached,
            "rescan_seconds": verification.seconds}


# ------------------------------------------------------------------------ summary

def summary(records: list[dict]) -> str:
    by_kind: dict[str, Counter] = defaultdict(Counter)
    tokens_in = tokens_out = 0
    llm_s = rescan_s = 0.0
    served = Counter()
    for r in records:
        outcome = r.get("verdict") if r["kind"] == TRIAGE else r.get("status")
        by_kind[(r["kind"], r["strategy"])][outcome] += 1
        tokens_in += r.get("prompt_tokens") or 0
        tokens_out += r.get("completion_tokens") or 0
        llm_s += r.get("llm_seconds") or 0
        rescan_s += sum((r.get("rescan_seconds") or {}).values())
        served[r.get("model_served") or "?"] += 1
    lines = [f"{len(records)} attempts"]
    for (kind, strategy), counts in sorted(by_kind.items()):
        lines.append(f"  {kind:<11} {strategy:<9} " +
                     ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda kv: str(kv[0]))))
    cost = tokens_in / 1e6 * PRICE_INPUT_PER_M + tokens_out / 1e6 * PRICE_OUTPUT_PER_M
    lines += [f"tokens: {tokens_in} in + {tokens_out} out  (~${cost:.2f} at list price)",
              f"time: LLM {llm_s:.0f}s, rescans {rescan_s:.0f}s",
              "model served: " + ", ".join(f"{m} ({n})" for m, n in served.items())]
    return "\n".join(lines)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("summary", help="counts, tokens, estimated cost and time of a log")
    s.add_argument("log", type=Path)
    args = parser.parse_args()

    log = ResultLog(args.log)
    if log.repaired:
        print(f"(repaired {log.repaired} truncated/corrupt line(s))")
    print(summary(log.records()))


if __name__ == "__main__":
    main()
