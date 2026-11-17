"""Minimal Groq chat client for the agent (Paso 3.1).

The thesis fixes a single model on Groq; the experiments compare *prompting
strategies* (zero-shot / few-shot / CoT), not models, so the model id is a
constant here on purpose, not a parameter. The roadmap's original model, Llama
3.3 70B, was retired by Groq on 2026-08-16, so the fixed model is now
``openai/gpt-oss-120b`` (open-weights, the most capable general model on Groq's
current line-up). See README "Decisión de modelo".

This talks to Groq's OpenAI-compatible endpoint over the standard library only
(no new dependency to pin), so the agent stays reproducible from a clean Python.
The key is read from the ``GROQ_API_KEY`` environment variable and never logged
or committed; in CI it comes from the repository secret of the same name.

Usage:
    GROQ_API_KEY=... python scripts/ai_agent/groq_client.py --selftest
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "openai/gpt-oss-120b"   # single fixed model (Llama 3.3 70B retired by Groq 2026-08-16)
DEFAULT_TEMPERATURE = 0.0           # deterministic by default, for reproducible triage
DEFAULT_TIMEOUT = 60
MAX_RETRIES = 5
# api.groq.com sits behind Cloudflare, which blocks urllib's default User-Agent
# with HTTP 403 "error code: 1010". A plain, non-default UA passes.
USER_AGENT = "Mozilla/5.0 (compatible; tfm-devsecops-ai/1.0)"


# A 429 that asks to wait longer than this is a spent quota (tokens or requests
# per day on the free plan), not a burst: waiting inside the call would block a
# batch run for hours, so the client stops and the run is resumed later from its
# log (results.py). Shorter 429s (per-minute limits) are waited out as before.
QUOTA_WAIT_LIMIT = 60
_DAILY = re.compile(r"per day|\((?:TPD|RPD)\)", re.I)
_TRY_AGAIN = re.compile(r"try again in\s*(?:(\d+)h)?\s*(?:(\d+)m(?!s))?\s*(?:([\d.]+)s)?", re.I)


class GroqError(RuntimeError):
    """A call to Groq failed (missing key, HTTP error, or malformed response)."""


class GroqQuotaExhausted(GroqError):
    """Groq's rate-limit quota is spent; retry after ``wait_seconds`` (None = unknown)."""

    def __init__(self, wait_seconds: float | None, detail: str):
        self.wait_seconds = wait_seconds
        when = f"in ~{format_wait(wait_seconds)}" if wait_seconds else "later"
        super().__init__(f"Groq quota exhausted: resume the run {when}. {detail}")


def format_wait(seconds: float) -> str:
    """Human-readable wait: '45 s', '12 min', '2 h 05 min'."""
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds} s"
    hours, minutes = divmod(-(-seconds // 60), 60)
    return f"{hours} h {minutes:02d} min" if hours else f"{minutes} min"


def wait_hint(headers, body: str) -> float | None:
    """Seconds Groq asks to wait: ``Retry-After`` header, else 'try again in 1h2m3.4s'."""
    try:
        return float(headers.get("Retry-After"))
    except (AttributeError, TypeError, ValueError):
        pass
    m = _TRY_AGAIN.search(body or "")
    if not m or not any(m.groups()):
        return None
    h, mins, s = m.groups()
    return int(h or 0) * 3600 + int(mins or 0) * 60 + float(s or 0)


def is_quota(wait: float | None, body: str) -> bool:
    """A 429 that will not clear within a short back-off."""
    return bool(_DAILY.search(body or "")) or (wait is not None and wait > QUOTA_WAIT_LIMIT)


@dataclass
class Completion:
    """One model reply, with the token accounting the experiments need."""

    text: str
    prompt_tokens: int
    completion_tokens: int
    model: str


@dataclass
class Usage:
    """Cost of one LLM call, kept with each decision/patch for the results log (4.5).

    ``seconds`` is wall time including retries/back-off (the overhead users feel);
    ``model`` is what the API reports it served, to detect silent model changes.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    model: str = ""
    seconds: float = 0.0


def timed_complete(client, system: str, user: str) -> tuple[Completion, Usage]:
    """``client.complete`` plus its Usage (tolerates test doubles without token fields)."""
    start = time.monotonic()
    reply = client.complete(system, user)
    usage = Usage(prompt_tokens=getattr(reply, "prompt_tokens", 0) or 0,
                  completion_tokens=getattr(reply, "completion_tokens", 0) or 0,
                  model=getattr(reply, "model", "") or "",
                  seconds=round(time.monotonic() - start, 2))
    return reply, usage


class GroqClient:
    """Thin wrapper around Groq's chat/completions endpoint."""

    def __init__(self, api_key: str | None = None, model: str = MODEL,
                 timeout: int = DEFAULT_TIMEOUT):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        if not self.api_key:
            raise GroqError("GROQ_API_KEY is not set (env var or constructor argument).")
        self.model = model
        self.timeout = timeout

    def complete(self, system: str, user: str,
                 temperature: float = DEFAULT_TEMPERATURE,
                 max_tokens: int | None = None) -> Completion:
        """Send a system+user prompt and return the reply.

        Retries transient failures (short 429 and 5xx) with back-off; raises
        GroqQuotaExhausted at once when the quota is spent (a daily limit, or a
        wait over QUOTA_WAIT_LIMIT), and GroqError on any other non-transient
        error or after the retries are exhausted.
        """
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        body = json.dumps(payload).encode("utf-8")

        last_error: Exception | None = None
        for attempt in range(MAX_RETRIES):
            request = urllib.request.Request(
                GROQ_ENDPOINT, data=body, method="POST",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    data = json.load(response)
                return self._parse(data)
            except urllib.error.HTTPError as err:
                last_error = err
                detail = err.read().decode("utf-8", "replace")[:500]
                wait = wait_hint(err.headers, detail) if err.code == 429 else None
                if err.code == 429 and is_quota(wait, detail):
                    raise GroqQuotaExhausted(wait, detail) from err
                if err.code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES - 1:
                    # A short 429 (per-minute limit) says how long to wait; honour
                    # it instead of a fixed back-off, so batch runs self-pace.
                    time.sleep(min(wait if wait is not None else 2 ** attempt, 30))
                    continue
                raise GroqError(f"Groq HTTP {err.code}: {detail}") from err
            except (urllib.error.URLError, TimeoutError) as err:
                last_error = err
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
        raise GroqError(f"Groq request failed after {MAX_RETRIES} attempts: {last_error}")

    def list_models(self) -> list[str]:
        """Model ids this key can access (GET /models), to resolve the right id."""
        request = urllib.request.Request(
            GROQ_ENDPOINT.replace("/chat/completions", "/models"),
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Accept": "application/json", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.load(response)
        except urllib.error.HTTPError as err:
            detail = err.read().decode("utf-8", "replace")[:500]
            raise GroqError(f"Groq HTTP {err.code}: {detail}") from err
        return sorted(m.get("id", "") for m in data.get("data", []))

    def _parse(self, data: dict) -> Completion:
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as err:
            raise GroqError(f"unexpected Groq response shape: {json.dumps(data)[:300]}") from err
        usage = data.get("usage", {})
        return Completion(
            text=text,
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            model=data.get("model", self.model),
        )


def _selftest() -> None:
    client = GroqClient()
    reply = client.complete(
        system="You are a terse assistant. Answer in one word.",
        user="Reply with the single word: OK",
    )
    print(f"model={reply.model} tokens={reply.prompt_tokens}+{reply.completion_tokens}")
    print(f"reply={reply.text.strip()!r}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--selftest", action="store_true",
                        help="send one tiny request to verify the key and connectivity")
    parser.add_argument("--models", action="store_true",
                        help="list the model ids this key can access")
    args = parser.parse_args()
    if args.models:
        for model_id in GroqClient().list_models():
            print(model_id)
    elif args.selftest:
        _selftest()
    else:
        parser.print_help()
