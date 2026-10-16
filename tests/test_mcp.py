"""MCP smoke: the server lists every contract tool and three calls work end to end.

S8: the calls run against this module's OWN freshly seeded graphs (org_a and org_c
at test scale, as `test_mcp_a` / `test_mcp_c`), never the live org_a / org_c a
concurrent `make seed` or `make triage` may be rewriting, so the suite is
order-independent.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from conftest import TEST_SCALE, TEST_SEED, drop
from mcp import Client
from starlette.responses import PlainTextResponse

import reachable_mcp.server as mcp_server
from reachable_graph.derive import derive
from reachable_graph.tools import TOOL_NAMES, GraphTools
from reachable_mcp.server import ApiKeyMiddleware, server
from reachable_orggen.build import generate_org
from reachable_orggen.generate import GenConfig
from reachable_orggen.load_falkordb import load_org

pytestmark = pytest.mark.integration

A, C = "test_mcp_a", "test_mcp_c"


@pytest.fixture(scope="module")
def mcp_graphs(db):
    """org_a and org_c at test scale in their own graphs, the in-process MCP server
    pointed at them (and only them) for this module, restored afterwards."""
    for org, name in (("org_a", A), ("org_c", C)):
        ob = generate_org(org, TEST_SEED, GenConfig(scale=TEST_SCALE))
        ob.dataset.org = name
        load_org(db, ob.dataset)
        derive(db.select_graph(name))
    before = mcp_server._tools
    mcp_server.use_tools(GraphTools(db, allowed_orgs=[A, C]))
    try:
        yield db
    finally:
        mcp_server._tools = before
        drop(db, A, C)


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


def test_mcp_three_calls(mcp_graphs):
    async def go():
        async with Client(server) as c:
            paths = await c.call_tool("attack_paths", {"org": A, "k": 2})
            cut = await c.call_tool("min_cut", {"org": A})
            tokens = cut.structured_content["data"]["fix_tokens"]
            sim = await c.call_tool("simulate_fix", {"org": A, "fix_tokens": tokens})
            bad = await c.call_tool("attack_paths", {"org": A, "k": 999})
            live = await c.call_tool("attack_paths", {"org": "org_a", "k": 2})
            return paths, cut, sim, bad, live

    paths, cut, sim, bad, live = _run(go())

    assert not paths.is_error and paths.structured_content["data"]["paths"]
    assert not cut.is_error and cut.structured_content["data"]["max_flow"] >= 1
    assert sim.structured_content["data"]["all_crown_jewels_disconnected"] is True
    assert bad.is_error  # cap enforced at the MCP boundary too
    assert live.is_error  # the live demo graph is not reachable from this test


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


def test_mcp_company_and_memory_tools(mcp_graphs):
    """The S3 tools answer end to end over MCP on a freshly seeded org_c."""
    db = mcp_graphs
    gw = (
        db.select_graph(C)
        .ro_query("MATCH (a:Asset {kind: 'gateway'})<-[:CHANGED]-(:ADR) RETURN a.id LIMIT 1")
        .result_set
    )
    assert gw, "the generator's org_c has a company layer"
    asset = gw[0][0]
    fid = (
        db.select_graph(C)
        .ro_query("MATCH (:RiskAcceptance)-[:ON]->(f:Finding) RETURN f.id")
        .result_set
    )

    async def go():
        async with Client(server) as c:
            return (
                await c.call_tool("owners", {"org": C, "asset_id": asset}),
                await c.call_tool("decision_trail", {"org": C, "asset_id": asset}),
                await c.call_tool(
                    "company_query",
                    {
                        "org": C,
                        "question_kind": "who_approved",
                        "params": {"asset_id": asset, "port": 443},
                    },
                ),
                await c.call_tool("triage_memory", {"org": C, "finding_ids": [r[0] for r in fid]}),
                await c.call_tool("min_cut", {"org": C, "mode": "cheapest"}),
                await c.call_tool(
                    "company_query",
                    {"org": C, "question_kind": "who_owns", "params": {"q": "x"}},
                ),
            )

    own, trail, appr, mem, cheap, bad = _run(go())
    for r in (own, trail, appr, mem, cheap):
        assert not r.is_error, r.content[0].text
    assert own.structured_content["data"]["teams"]
    assert trail.structured_content["data"]["decisions"]
    assert "[org_c:adr:" in appr.structured_content["data"]["answer"]  # cites the ADR
    findings = mem.structured_content["data"]["findings"]
    assert {f["suppressed"] for f in findings} == {True, False}  # one live, one expired
    assert cheap.structured_content["data"]["mode"] == "cheapest"
    assert bad.is_error  # unknown parameter for the intent is refused at the boundary
