"""Our MCP tools, as tools an LLM can call. (Our equivalent of langchain-mcp-adapters.)

Why not langchain-mcp-adapters itself: 0.3.x pins `mcp<2`, and our server is
built on the mcp 2.x MCPServer API. Installing it silently downgraded mcp to
1.30 and would have broken the server. The adapter's job is small enough to own:

  1. list_tools() over an MCP session -> each tool's name, description and
     JSON Schema (the schema the server derives from our Pydantic inputs);
  2. turn each into an OpenAI-style function schema the LLM is shown;
  3. call_tool(name, args) over the same session -> the ToolResult dict, or the
     server's error text.

So the LLM only ever sees what the MCP server advertises, and every call it
picks travels over MCP (JSON-RPC), in-process or over stdio.

Two arguments are hidden from the LLM and filled in by the run instead: `org`
(an agent works on one graph; it must not wander to another) and `as_of` (the
run's clock; a model must not pick the time).
"""

from __future__ import annotations

import json
import os
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp import Client, StdioServerParameters

from reachable_core.settings import REPO_ROOT

HIDDEN_ARGS = ("org", "as_of")
# JSON Schema keywords providers reject or ignore; the server validates them anyway.
_DROP_KEYWORDS = ("title", "pattern", "minLength", "maxLength", "additionalProperties")


@dataclass
class McpTool:
    name: str
    description: str
    schema: dict[str, Any]


@dataclass
class CallOutcome:
    ok: bool
    result: dict | None  # the ToolResult {summary, data, evidence, queries, truncated}
    error: str | None
    ms: float


class McpToolbox:
    """One MCP client session, the tools it advertises, and calls through it."""

    def __init__(self, client: Client) -> None:
        self.client = client
        self.tools: dict[str, McpTool] = {}

    @classmethod
    @asynccontextmanager
    async def open(cls, transport: str = "memory"):
        """memory: the server object in this process, spoken to over MCP's
        in-memory transport (fast, no subprocess). stdio: launch
        `python -m reachable_mcp.server` and talk JSON-RPC over its pipes, the
        way any external MCP host would."""
        if transport == "memory":
            from reachable_mcp.server import server

            target: Any = server
        elif transport == "stdio":
            target = StdioServerParameters(
                command=sys.executable,
                args=["-m", "reachable_mcp.server"],
                cwd=str(REPO_ROOT),
                env=dict(os.environ),
            )
        else:
            raise ValueError(f"unknown MCP transport {transport!r} (memory | stdio)")
        async with Client(target) as client:
            box = cls(client)
            await box.load()
            yield box

    async def load(self) -> None:
        for t in (await self.client.list_tools()).tools:
            self.tools[t.name] = McpTool(t.name, t.description or "", t.input_schema)

    def takes(self, tool: str, arg: str) -> bool:
        return arg in self.tools[tool].schema.get("properties", {})

    def llm_schemas(self, names: list[str] | tuple[str, ...], *, brief: bool = True) -> list[dict]:
        """OpenAI-style function schemas for these tools, as the LLM sees them.
        brief: only the "what it answers" part of each description (see
        brief_description); the schemas are re-sent on every turn."""
        return [
            {
                "type": "function",
                "function": {
                    "name": n,
                    "description": brief_description(self.tools[n].description)
                    if brief
                    else self.tools[n].description,
                    "parameters": llm_parameters(self.tools[n].schema),
                },
            }
            for n in names
            if n in self.tools
        ]

    async def call(self, name: str, args: dict) -> CallOutcome:
        t = time.perf_counter()
        try:
            r = await self.client.call_tool(name, args)
        except Exception as exc:  # noqa: BLE001 - transport failure: report, don't crash the run
            return CallOutcome(False, None, f"{type(exc).__name__}: {exc}", _ms(t))
        if r.is_error:
            text = " ".join(getattr(c, "text", "") for c in r.content) or "tool error"
            return CallOutcome(False, None, text, _ms(t))
        return CallOutcome(True, r.structured_content, None, _ms(t))


BRIEF_CHARS = 320


def brief_description(text: str) -> str:
    """A tool description up to its "USE ..." / "Do NOT ..." guidance.

    The MCP server's descriptions are written for a host that picks among all 15
    tools, so each says when to use the tool and when not to. Our agents get 2-4
    tools each and a job that names them; the guidance is then repeated cost
    (the schemas are re-sent every turn), so they get what the tool answers."""
    for cut in (" USE ", " Do NOT "):
        i = text.find(cut)
        if i > 0:
            text = text[:i]
    text = text.strip()
    return text if len(text) <= BRIEF_CHARS else text[: BRIEF_CHARS - 3].rstrip() + "..."


def llm_parameters(schema: dict) -> dict:
    """The MCP input schema minus hidden args, simplified for any provider:
    Optional[X] (anyOf [X, null]) becomes X (omit the argument to get null), the
    default moves into the description, and keywords providers choke on go."""
    props = {
        name: _simplify(p)
        for name, p in schema.get("properties", {}).items()
        if name not in HIDDEN_ARGS
    }
    required = [r for r in schema.get("required", []) if r in props]
    return {"type": "object", "properties": props, "required": required}


def _simplify(p: dict) -> dict:
    p = dict(p)
    if "anyOf" in p:
        options = [x for x in p.pop("anyOf") if x.get("type") != "null"]
        if len(options) == 1:
            p = {**options[0], **p}
    default = p.pop("default", None)
    for k in _DROP_KEYWORDS:
        p.pop(k, None)
    if default is not None:
        p["description"] = f"{p.get('description', '')} (default {json.dumps(default)})".strip()
    if isinstance(p.get("items"), dict):
        p["items"] = _simplify(p["items"])
    return p


def _ms(t: float) -> float:
    return round((time.perf_counter() - t) * 1000, 1)
