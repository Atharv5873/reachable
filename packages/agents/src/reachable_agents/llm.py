"""One door to the LLMs: a LiteLLM Router with fallbacks, logging who served each call.

    primary   Gemini Flash (free tier)            GEMINI_API_KEY
    fallback  a Groq model (free tier)            GROQ_API_KEY
    reserve   a small paid model (optional)       LLM_RESERVE_MODEL + LLM_RESERVE_API_KEY

Every agent calls `chat(messages, tools, agent=...)` and gets an LLMReply back:
the text or the tool calls the model chose, plus WHICH deployment served it,
tokens and latency. The agents never see a provider SDK.

How a 429 is handled. Each deployment is one entry in the Router's model_list.
A call goes to the first one. If the provider answers 429 (rate limit) or a
5xx, the Router's RetryPolicy decides how often to retry *that* deployment
(rate limits: zero times, so we don't burn the minute's quota retrying), then
it walks `fallbacks` in order. A deployment that keeps failing is put in
cooldown for a minute, so the next calls skip straight to the fallback instead
of paying another 429 round trip. Only when every deployment failed does
chat() raise LLMUnavailable; the agent loop then finalises without the LLM.

Keys never print: Settings holds them as SecretStr, they are unwrapped only to
build the Router, and any error text is scrubbed of them before it is logged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Protocol

import litellm
from litellm import Router
from litellm.types.router import RetryPolicy
from pydantic import SecretStr

from reachable_core.settings import Settings, get_settings

log = logging.getLogger("reachable.llm")
litellm.suppress_debug_info = True  # no banners or request dumps on stdout


class LLMUnavailable(RuntimeError):
    """Every deployment failed (or none is configured)."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    error: str | None = None  # the model sent arguments that are not a JSON object


@dataclass
class LLMReply:
    content: str | None
    tool_calls: list[ToolCall]
    served_by: str  # deployment: primary | fallback | reserve | fake
    model: str  # provider model id, e.g. gemini/gemini-2.5-flash
    tokens_in: int
    tokens_out: int
    ms: float
    fallback: bool  # served by something other than the first deployment
    # The assistant message exactly as the provider returned it. The loop appends
    # THIS to the history (not a rebuilt one): providers attach fields to tool
    # calls (Gemini's thought signatures) that must come back unchanged.
    raw: dict | None = None
    waited_s: float = 0.0  # time spent waiting for a rate-limit slot before the call


class ChatModel(Protocol):
    """What an agent needs from a model. RouterLLM and FakeLLM both provide it.
    tool_choice="none" asks for a final answer: tools stay declared (the history
    holds tool calls) but the model may not call one."""

    async def chat(
        self, messages: list[dict], tools: list[dict], *, agent: str, tool_choice: str = "auto"
    ) -> LLMReply: ...


@dataclass(frozen=True)
class Deployment:
    name: str  # primary | fallback | reserve
    model: str
    api_key: SecretStr = field(repr=False)


def deployments(s: Settings) -> list[Deployment]:
    """The deployments that have a key, in fallback order."""
    out = []
    if s.gemini_api_key:
        out.append(Deployment("primary", s.llm_primary_model, s.gemini_api_key))
    if s.groq_api_key:
        out.append(Deployment("fallback", s.llm_fallback_model, s.groq_api_key))
    if s.llm_reserve_model and s.llm_reserve_api_key:
        out.append(Deployment("reserve", s.llm_reserve_model, s.llm_reserve_api_key))
    return out


def provider_params(model: str) -> dict:
    """Per-model litellm params. Gemini 2.5 "thinks" by default and its thinking
    tokens count against max_tokens: a long JSON answer got cut off at 2048. We
    turn it off there (faster, cheaper, steadier at temperature 0). Gemini 3
    always thinks (we keep it "low", ~700 tokens), and needs its thought
    signatures passed back, which the loop does by appending the provider's raw
    message."""
    if model.startswith("gemini/gemini-2.5"):
        return {"reasoning_effort": "disable"}
    if model.startswith("gemini/gemini-3"):
        return {"reasoning_effort": "low"}
    return {}


class Pacer:
    """At most `rpm` calls in any 60 s window. A call that would exceed it waits
    for the oldest call to age out, if that is <= max_wait seconds; otherwise it
    goes ahead and the Router's fallback absorbs the 429."""

    def __init__(self, rpm: int, max_wait: float) -> None:
        self.rpm, self.max_wait = rpm, max_wait
        self.times: deque[float] = deque()

    async def slot(self) -> float:
        """Wait for a slot; return the seconds waited."""
        if self.rpm <= 0:
            return 0.0
        waited = 0.0
        now = time.monotonic()
        while self.times and now - self.times[0] >= 60:
            self.times.popleft()
        if len(self.times) >= self.rpm:
            delay = 60 - (now - self.times[0]) + 0.2
            if delay <= self.max_wait:
                log.info("llm pacing: waiting %.1f s for a slot (%d/min)", delay, self.rpm)
                await asyncio.sleep(delay)
                waited = delay
        self.times.append(time.monotonic())
        return waited


def build_router(
    deps: list[Deployment], s: Settings, *, extra: dict[str, dict] | None = None
) -> Router:
    """A Router over `deps`, falling back in list order. `extra` adds litellm
    params per deployment name (tests use it to inject a mock 429)."""
    extra = extra or {}
    names = [d.name for d in deps]
    retries = s.llm_retries
    return Router(
        model_list=[
            {
                "model_name": d.name,
                "litellm_params": {
                    "model": d.model,
                    "api_key": d.api_key.get_secret_value(),
                    "timeout": s.llm_timeout_s,
                    **provider_params(d.model),
                    **extra.get(d.name, {}),
                },
                "model_info": {"id": d.name},  # the id the response reports back
            }
            for d in deps
        ],
        fallbacks=[{names[0]: names[1:]}] if len(names) > 1 else [],
        num_retries=retries,
        retry_policy=RetryPolicy(
            RateLimitErrorRetries=0,  # 429: fall back now, don't spend quota retrying
            TimeoutErrorRetries=0,
            # 503 "model overloaded" is usually gone a second later: retry first.
            InternalServerErrorRetries=retries,
            ServiceUnavailableErrorRetries=retries + 1,
            BadRequestErrorRetries=0,
            AuthenticationErrorRetries=0,
            NotFoundErrorRetries=0,  # a retired model id: fall back, `check` reports it
        ),
        timeout=s.llm_timeout_s,
        allowed_fails=2,  # two failures in a minute ...
        cooldown_time=30,  # ... and the deployment sits out 30 s
    )


class RouterLLM:
    """The real model behind the agents."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        deps: list[Deployment] | None = None,
        extra: dict[str, dict] | None = None,
    ) -> None:
        s = settings or get_settings()
        self.deps = deps if deps is not None else deployments(s)
        if not self.deps:
            raise LLMUnavailable(
                "no LLM key configured: set GEMINI_API_KEY and/or GROQ_API_KEY in .env "
                "(or run with --fake)"
            )
        self.router = build_router(self.deps, s, extra=extra)
        self.entry = self.deps[0].name
        self.models = {d.name: d.model for d in self.deps}
        self.max_tokens = s.llm_max_tokens
        self.pacer = Pacer(s.llm_rpm, s.llm_max_wait_s)
        self.patience_s, self.patience_left = 35.0, s.llm_patience_retries
        self._secrets = [d.api_key.get_secret_value() for d in self.deps]

    def describe(self) -> list[str]:
        return [f"{d.name}={d.model}" for d in self.deps]

    def _scrub(self, text: str) -> str:
        for sec in self._secrets:
            if sec:
                text = text.replace(sec, "***")
        return text

    async def chat(
        self, messages: list[dict], tools: list[dict], *, agent: str, tool_choice: str = "auto"
    ) -> LLMReply:
        waited = await self.pacer.slot()
        t = time.perf_counter()
        try:
            resp = await self.router.acompletion(
                model=self.entry,
                messages=messages,
                tools=tools or None,
                tool_choice=tool_choice if tools else None,
                temperature=0,
                max_tokens=self.max_tokens,
            )
        except Exception as exc:  # noqa: BLE001 - every provider error ends up here
            msg = self._scrub(f"{type(exc).__name__}: {exc}")[:400]
            if self.patience_left > 0 and _short_lived_limit(msg):
                # A per-minute limit or a 30 s cooldown passes; a daily quota does
                # not. Wait once and retry rather than finalise without the model.
                self.patience_left -= 1
                log.warning(
                    "llm agent=%s rate-limited on every deployment; waiting %.0f s, retrying once",
                    agent,
                    self.patience_s,
                )
                await asyncio.sleep(self.patience_s)
                return await self.chat(messages, tools, agent=agent, tool_choice=tool_choice)
            log.warning("llm agent=%s FAILED on every deployment: %s", agent, msg)
            raise LLMUnavailable(msg) from exc
        ms = round((time.perf_counter() - t) * 1000, 1)
        served = (getattr(resp, "_hidden_params", None) or {}).get("model_id") or self.entry
        msg = resp.choices[0].message
        usage = getattr(resp, "usage", None)
        reply = LLMReply(
            content=msg.content,
            tool_calls=[_tool_call(tc) for tc in (msg.tool_calls or [])],
            served_by=served,
            model=self.models.get(served, str(resp.model)),
            tokens_in=getattr(usage, "prompt_tokens", 0) or 0,
            tokens_out=getattr(usage, "completion_tokens", 0) or 0,
            ms=ms,
            fallback=served != self.entry,
            raw=msg.model_dump(exclude_none=True),
            waited_s=round(waited, 1),
        )
        log.info(
            "llm agent=%s served_by=%s model=%s ms=%.0f tokens=%d+%d tool_calls=%s",
            agent,
            reply.served_by,
            reply.model,
            ms,
            reply.tokens_in,
            reply.tokens_out,
            [c.name for c in reply.tool_calls],
        )
        return reply


async def check_deployments(s: Settings | None = None) -> list[dict]:
    """Probe every configured deployment, directly (no fallback), with one real
    tool-calling request. Catches a retired model id or a dead key before a demo."""
    s = s or get_settings()
    tool = {
        "type": "function",
        "function": {
            "name": "ping",
            "description": "Answer a ping.",
            "parameters": {"type": "object", "properties": {"n": {"type": "integer"}}},
        },
    }
    out = []
    for d in deployments(s):
        t = time.perf_counter()
        try:
            r = await litellm.acompletion(
                model=d.model,
                api_key=d.api_key.get_secret_value(),
                messages=[{"role": "user", "content": "Call ping with n=1."}],
                tools=[tool],
                timeout=s.llm_timeout_s,
                max_tokens=256,
            )
            calls = r.choices[0].message.tool_calls or []
            ok, note = bool(calls), (calls[0].function.name if calls else "no tool call")
        except Exception as exc:  # noqa: BLE001
            ok, note = False, f"{type(exc).__name__}: {exc}"
            for sec in (x.api_key.get_secret_value() for x in deployments(s)):
                note = note.replace(sec, "***")
        out.append(
            {
                "deployment": d.name,
                "model": d.model,
                "ok": ok,
                "ms": round((time.perf_counter() - t) * 1000),
                "note": note.splitlines()[0][:200],
            }
        )
    return out


def _short_lived_limit(msg: str) -> bool:
    """A rate limit that will pass within a minute (not Gemini's PerDay quota)."""
    rate_limited = "RateLimit" in msg or "cooldown" in msg or "429" in msg
    return rate_limited and "PerDay" not in msg


def _tool_call(tc) -> ToolCall:
    raw = tc.function.arguments or "{}"
    try:
        args = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except ValueError:
        return ToolCall(tc.id, tc.function.name, {}, error=f"arguments are not JSON: {raw[:200]}")
    if not isinstance(args, dict):
        return ToolCall(tc.id, tc.function.name, {}, error="arguments must be a JSON object")
    return ToolCall(tc.id, tc.function.name, args)
