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

import json
import logging
import time
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
            InternalServerErrorRetries=retries,
            ServiceUnavailableErrorRetries=retries,
            BadRequestErrorRetries=0,
            AuthenticationErrorRetries=0,
        ),
        timeout=s.llm_timeout_s,
        allowed_fails=1,  # one failure ...
        cooldown_time=60,  # ... and the deployment sits out a minute
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


def _tool_call(tc) -> ToolCall:
    raw = tc.function.arguments or "{}"
    try:
        args = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except ValueError:
        return ToolCall(tc.id, tc.function.name, {}, error=f"arguments are not JSON: {raw[:200]}")
    if not isinstance(args, dict):
        return ToolCall(tc.id, tc.function.name, {}, error="arguments must be a JSON object")
    return ToolCall(tc.id, tc.function.name, args)
