"""Minimal Groq chat client for the agent (Paso 3.1).

The thesis fixes a single model (Llama 3.3 70B on Groq); the experiments compare
*prompting strategies* (zero-shot / few-shot / CoT), not models, so the model id
is a constant here on purpose, not a parameter.

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
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "llama-3.3-70b-versatile"   # the single model fixed by the roadmap
DEFAULT_TEMPERATURE = 0.0           # deterministic by default, for reproducible triage
DEFAULT_TIMEOUT = 60
MAX_RETRIES = 3


class GroqError(RuntimeError):
    """A call to Groq failed (missing key, HTTP error, or malformed response)."""


@dataclass
class Completion:
    """One model reply, with the token accounting the experiments need."""

    text: str
    prompt_tokens: int
    completion_tokens: int
    model: str


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

        Retries transient failures (429 and 5xx) with exponential backoff; raises
        GroqError on a non-transient error or after the retries are exhausted.
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
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    data = json.load(response)
                return self._parse(data)
            except urllib.error.HTTPError as err:
                last_error = err
                if err.code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
                detail = err.read().decode("utf-8", "replace")[:500]
                raise GroqError(f"Groq HTTP {err.code}: {detail}") from err
            except (urllib.error.URLError, TimeoutError) as err:
                last_error = err
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
        raise GroqError(f"Groq request failed after {MAX_RETRIES} attempts: {last_error}")

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
    args = parser.parse_args()
    if args.selftest:
        _selftest()
    else:
        parser.print_help()
