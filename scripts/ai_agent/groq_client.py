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

Provider (pilot, branch ``exp/proveedor-piloto``): the Groq Developer plan is not
available, so the same open-weights model can be served by another
OpenAI-compatible provider, chosen with ``LLM_PROVIDER`` (default ``groq``; each
provider reads its own key variable, see ``PROVIDERS``). Without that variable the
client talks to Groq as before.

``reasoning_effort`` is sent explicitly (``LLM_REASONING_EFFORT``, default
``medium``; ``default`` omits it and leaves the provider's own default, as in the
4.10 rehearsals). gpt-oss reasons before it answers and each provider picks its
own default effort, so leaving it implicit would let the provider change how the
model reasons without any visible sign.

``max_tokens`` is sent explicitly too (``LLM_MAX_TOKENS``, default 16384): gpt-oss
spends its reasoning and its answer from the same budget, and the providers do not
document their default, so a low implicit cap could cut answers silently. Every
reply records its ``finish_reason`` ("length" = cut by that cap).

Spend cap (``LLM_BUDGET_USD``, required by ``run_dataset.py`` for paid providers):
the client adds up the list-price cost of the tokens it has used and refuses the
next call once the cap is reached (``LLMBudgetExceeded``), so a runaway loop cannot
spend more than the cap plus one call, whatever the provider's own billing does.

Usage:
    GROQ_API_KEY=... python scripts/ai_agent/groq_client.py --selftest
    LLM_PROVIDER=together TOGETHER_API_KEY=... python scripts/ai_agent/groq_client.py --probe-effort
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


@dataclass(frozen=True)
class Provider:
    """An OpenAI-compatible endpoint serving the fixed model."""

    name: str
    endpoint: str
    key_env: str
    model: str          # the provider's id for the same open-weights model
    price_in: float     # list price, USD per 1M input tokens
    price_out: float    # list price, USD per 1M output tokens (reasoning bills as output)

    def cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        return prompt_tokens / 1e6 * self.price_in + completion_tokens / 1e6 * self.price_out


# Endpoints, model ids and list prices from each provider's official pages (2026-11-23).
PROVIDERS = {
    "groq": Provider("groq", GROQ_ENDPOINT, "GROQ_API_KEY", MODEL, 0.15, 0.60),
    "together": Provider("together", "https://api.together.ai/v1/chat/completions",
                         "TOGETHER_API_KEY", "openai/gpt-oss-120b", 0.15, 0.60),
    "deepinfra": Provider("deepinfra", "https://api.deepinfra.com/v1/openai/chat/completions",
                          "DEEPINFRA_API_KEY", "openai/gpt-oss-120b", 0.037, 0.17),
}
PROVIDER_ENV = "LLM_PROVIDER"
EFFORT_ENV = "LLM_REASONING_EFFORT"
DEFAULT_EFFORT = "medium"
EFFORTS = ("low", "medium", "high")
MAX_TOKENS_ENV = "LLM_MAX_TOKENS"
DEFAULT_MAX_TOKENS = 16384      # 5x the largest reply of the 4.10 rehearsals (3072)
BUDGET_ENV = "LLM_BUDGET_USD"


def current_provider() -> Provider:
    """The provider selected by ``LLM_PROVIDER`` (default groq)."""
    name = (os.environ.get(PROVIDER_ENV) or "groq").strip().lower()
    if name not in PROVIDERS:
        raise ValueError(f"{PROVIDER_ENV}={name!r}: use one of {', '.join(PROVIDERS)}")
    return PROVIDERS[name]


def reasoning_effort() -> str | None:
    """The effort sent with every call; None = omit it (provider default)."""
    value = (os.environ.get(EFFORT_ENV) or DEFAULT_EFFORT).strip().lower()
    if value == "default":
        return None
    if value not in EFFORTS:
        raise ValueError(f"{EFFORT_ENV}={value!r}: use one of {', '.join(EFFORTS)} or 'default'")
    return value


def max_tokens_setting() -> int:
    """The completion cap sent with every call (``LLM_MAX_TOKENS``, default 16384)."""
    raw = (os.environ.get(MAX_TOKENS_ENV) or str(DEFAULT_MAX_TOKENS)).strip()
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if not 256 <= value <= 65536:
        raise ValueError(f"{MAX_TOKENS_ENV}={raw!r}: use an integer between 256 and 65536")
    return value


def budget_setting() -> float | None:
    """The spend cap in USD (``LLM_BUDGET_USD``); None when unset (no cap)."""
    raw = (os.environ.get(BUDGET_ENV) or "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        value = -1.0
    if not 0 < value <= 50:
        raise ValueError(f"{BUDGET_ENV}={raw!r}: use a number of USD between 0 and 50")
    return value


DEFAULT_TEMPERATURE = 0.0           # deterministic by default, for reproducible triage
# A slower provider can take minutes on a long reasoning reply; a timeout makes
# the client retry, and the abandoned request is most likely billed anyway.
DEFAULT_TIMEOUT = 180
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


class LLMBudgetExceeded(GroqError):
    """The spend cap (``LLM_BUDGET_USD``) is reached; no further call is sent."""

    def __init__(self, spent: float, budget: float):
        self.spent, self.budget = spent, budget
        super().__init__(f"spend cap reached: ~${spent:.4f} of ${budget:.2f} at list price "
                         f"({BUDGET_ENV}); no further call sent")


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
    cached_tokens: int | None = None      # prompt tokens served from the provider's cache
    reasoning_tokens: int | None = None   # part of completion_tokens spent reasoning
    finish_reason: str | None = None      # "stop", or "length" when max_tokens cut it


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
    cached_tokens: int | None = None      # None = the provider does not report it
    reasoning_tokens: int | None = None
    finish_reason: str | None = None


def timed_complete(client, system: str, user: str) -> tuple[Completion, Usage]:
    """``client.complete`` plus its Usage (tolerates test doubles without token fields)."""
    start = time.monotonic()
    reply = client.complete(system, user)
    usage = Usage(prompt_tokens=getattr(reply, "prompt_tokens", 0) or 0,
                  completion_tokens=getattr(reply, "completion_tokens", 0) or 0,
                  model=getattr(reply, "model", "") or "",
                  seconds=round(time.monotonic() - start, 2),
                  cached_tokens=getattr(reply, "cached_tokens", None),
                  reasoning_tokens=getattr(reply, "reasoning_tokens", None),
                  finish_reason=getattr(reply, "finish_reason", None))
    return reply, usage


_FROM_ENV = object()


class GroqClient:
    """Thin wrapper around an OpenAI-compatible chat/completions endpoint (Groq by default)."""

    def __init__(self, api_key: str | None = None, model: str | None = None,
                 timeout: int = DEFAULT_TIMEOUT, provider: Provider | None = None,
                 effort=_FROM_ENV, max_tokens=_FROM_ENV, budget=_FROM_ENV,
                 spent: float = 0.0):
        self.provider = provider or current_provider()
        self.api_key = api_key or os.environ.get(self.provider.key_env)
        if not self.api_key:
            raise GroqError(f"{self.provider.key_env} is not set (env var or constructor argument).")
        self.model = model or self.provider.model
        self.effort = reasoning_effort() if effort is _FROM_ENV else effort
        self.max_tokens = max_tokens_setting() if max_tokens is _FROM_ENV else max_tokens
        self.budget = budget_setting() if budget is _FROM_ENV else budget
        self.spent = spent          # USD at list price; start from the log when resuming
        self.timeout = timeout

    def complete(self, system: str, user: str,
                 temperature: float = DEFAULT_TEMPERATURE,
                 max_tokens: int | None = None) -> Completion:
        """Send a system+user prompt and return the reply.

        Retries transient failures (short 429 and 5xx) with back-off; raises
        GroqQuotaExhausted at once when the quota is spent (a daily limit, or a
        wait over QUOTA_WAIT_LIMIT), LLMBudgetExceeded before sending once the
        spend cap is reached, and GroqError on any other non-transient error or
        after the retries are exhausted.
        """
        if self.budget is not None and self.spent >= self.budget:
            raise LLMBudgetExceeded(self.spent, self.budget)
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        cap = max_tokens if max_tokens is not None else self.max_tokens
        if cap is not None:
            payload["max_tokens"] = cap
        if self.effort:
            payload["reasoning_effort"] = self.effort
        body = json.dumps(payload).encode("utf-8")
        name = self.provider.name

        last_error: Exception | None = None
        for attempt in range(MAX_RETRIES):
            request = urllib.request.Request(
                self.provider.endpoint, data=body, method="POST",
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
                reply = self._parse(data)
                self.spent += self.provider.cost(reply.prompt_tokens, reply.completion_tokens)
                return reply
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
                raise GroqError(f"{name} HTTP {err.code}: {detail}") from err
            except (urllib.error.URLError, TimeoutError) as err:
                last_error = err
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
        raise GroqError(f"{name} request failed after {MAX_RETRIES} attempts: {last_error}")

    def list_models(self) -> list[str]:
        """Model ids this key can access (GET /models), to resolve the right id."""
        request = urllib.request.Request(
            self.provider.endpoint.replace("/chat/completions", "/models"),
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Accept": "application/json", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.load(response)
        except urllib.error.HTTPError as err:
            detail = err.read().decode("utf-8", "replace")[:500]
            raise GroqError(f"{self.provider.name} HTTP {err.code}: {detail}") from err
        return sorted(m.get("id", "") for m in data.get("data", []))

    def _parse(self, data: dict) -> Completion:
        try:
            choice = data["choices"][0]
            text = choice["message"]["content"]
        except (KeyError, IndexError, TypeError) as err:
            raise GroqError(f"unexpected {self.provider.name} response shape: "
                            f"{json.dumps(data)[:300]}") from err
        usage = data.get("usage") or {}
        return Completion(
            text=text or "",      # None when every token went to reasoning
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            model=data.get("model") or self.model,
            cached_tokens=_detail(usage, "prompt_tokens_details", "cached_tokens"),
            reasoning_tokens=_detail(usage, "completion_tokens_details", "reasoning_tokens"),
            finish_reason=choice.get("finish_reason"),
        )


def _detail(usage: dict, group: str, name: str) -> int | None:
    """``usage[group][name]`` as an int, or None when the provider does not report it."""
    value = (usage.get(group) or {}).get(name)
    try:
        return None if value is None else int(value)
    except (TypeError, ValueError):
        return None


def _selftest() -> None:
    client = GroqClient()
    reply = client.complete(
        system="You are a terse assistant. Answer in one word.",
        user="Reply with the single word: OK",
    )
    print(f"provider={client.provider.name} effort={client.effort or 'provider default'} "
          f"max_tokens={client.max_tokens} model={reply.model} "
          f"tokens={reply.prompt_tokens}+{reply.completion_tokens} "
          f"(reasoning={reply.reasoning_tokens}, cached={reply.cached_tokens}) "
          f"finish={reply.finish_reason} cost~${client.spent:.5f}")
    print(f"reply={reply.text.strip()!r}")


# A small question that needs some reasoning, so the effort level shows in the
# number of reasoning tokens (a one-word reply would hide it).
_PROBE_SYSTEM = "You are a careful security reviewer. Answer with one word: SAFE or UNSAFE."
_PROBE_USER = (
    "Is this Node.js handler vulnerable to path traversal?\n\n"
    "app.get('/f', (req, res) => {\n"
    "  const name = String(req.query.name).replace(/\\.\\.\\//g, '')\n"
    "  res.sendFile(path.join(__dirname, 'public', name))\n"
    "})"
)


def _probe_effort(repeats: int) -> None:
    """Average completion/reasoning tokens with the effort omitted and at each level.

    Shows which level the provider uses when the parameter is omitted (the 4.10
    rehearsals omitted it) and whether the levels behave alike across providers.
    """
    provider = current_provider()
    print(f"provider={provider.name} model={provider.model} repeats={repeats}")
    print(f"{'effort':<12}{'completion':>11}{'reasoning':>11}  replies")
    spent = 0.0
    for effort in (None, *EFFORTS):
        client = GroqClient(provider=provider, effort=effort, spent=spent)
        comp, reas, replies = [], [], []
        for _ in range(repeats):
            reply = client.complete(_PROBE_SYSTEM, _PROBE_USER)
            comp.append(reply.completion_tokens)
            if reply.reasoning_tokens is not None:
                reas.append(reply.reasoning_tokens)
            replies.append(reply.text.strip()[:12])
        spent = client.spent
        mean = lambda xs: f"{sum(xs) / len(xs):.0f}" if xs else "n/a"
        print(f"{effort or '(omitted)':<12}{mean(comp):>11}{mean(reas):>11}  {', '.join(replies)}")
    print(f"cost of the probe: ~${spent:.4f} at list price")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--selftest", action="store_true",
                        help="send one tiny request to verify the key and connectivity")
    parser.add_argument("--models", action="store_true",
                        help="list the model ids this key can access")
    parser.add_argument("--probe-effort", action="store_true",
                        help="compare tokens with reasoning_effort omitted/low/medium/high")
    parser.add_argument("--repeats", type=int, default=3, help="calls per level for --probe-effort")
    args = parser.parse_args()
    if args.models:
        for model_id in GroqClient().list_models():
            print(model_id)
    elif args.probe_effort:
        _probe_effort(args.repeats)
    elif args.selftest:
        _selftest()
    else:
        parser.print_help()
