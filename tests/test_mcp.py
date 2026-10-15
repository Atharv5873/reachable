"""MCP smoke: the server lists every contract tool and three calls work end to end."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from mcp import Client
from starlette.responses import PlainTextResponse

from reachable_graph.tools import TOOL_NAMES
from reachable_mcp.server import ApiKeyMiddleware, server

pytestmark = pytest.mark.integration


def _run(coro):
    return asyncio.run(coro)


def test_mcp_lists_contract_tools_with_bounded_schemas():
    async def go():
        async with Client(server) as c:
            return (await c.list_tools()).tools

    tools = {t.name: t for t in _run(go())}
    assert set(tools) == set(TOOL_NAMES)
    k = tools["attack_paths"].input_schema["properties"]["k"]
    assert (k["minimum"], k["maximum"]) == (1, 25)
    for t in tools.values():
        assert "Do NOT" in t.description or "LAST RESORT" in t.description


def test_mcp_three_calls(db):
    if "org_a" not in db.list_graphs():
        pytest.skip("org_a not seeded")

    async def go():
        async with Client(server) as c:
            paths = await c.call_tool("attack_paths", {"org": "org_a", "k": 2})
            cut = await c.call_tool("min_cut", {"org": "org_a"})
            tokens = cut.structured_content["data"]["fix_tokens"]
            sim = await c.call_tool("simulate_fix", {"org": "org_a", "fix_tokens": tokens})
            bad = await c.call_tool("attack_paths", {"org": "org_a", "k": 999})
            return paths, cut, sim, bad

    paths, cut, sim, bad = _run(go())
    assert not paths.is_error and paths.structured_content["data"]["paths"]
    assert not cut.is_error and cut.structured_content["data"]["max_flow"] >= 1
    assert sim.structured_content["data"]["all_crown_jewels_disconnected"] is True
    assert bad.is_error  # cap enforced at the MCP boundary too


def test_api_key_middleware():
    async def ok(scope, receive, send):
        await PlainTextResponse("ok")(scope, receive, send)

    app = ApiKeyMiddleware(ok, "k" * 32)

    async def go():
        t = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=t, base_url="http://localhost") as c:
            return [
                (await c.post("/mcp")).status_code,
                (await c.post("/mcp", headers={"X-API-Key": "wrong"})).status_code,
                (await c.post("/mcp", headers={"X-API-Key": "k" * 32})).status_code,
                (await c.post("/mcp", headers={"Authorization": "Bearer " + "k" * 32})).status_code,
                (await c.get("/health")).status_code,
            ]

    assert _run(go()) == [401, 401, 200, 200, 200]
