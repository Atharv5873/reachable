"""S6: the API additions the UI draws from, on throwaway graphs.

* /orgs/{org}/findings: the same findings in the scanner's order and in
  Reachable's, with a reason per row and a headline pair.
* /runs/{id}/subgraph: a run's attack paths and both min cuts as Cytoscape
  elements, capped, filterable by finding, with one hop of context on demand.
* /runs/{id}/fixplan + /orgs/{org}/simulate: a fix set in either mode, and the
  proof that it disconnects every crown jewel.
* /orgs/{org}/ask: English -> one fixed company_query intent (model or rules),
  never free text to Cypher; a model's made-up id is rejected.
* The concurrent-run cap: a third run while two execute is refused with 429
  and Retry-After, before anything is written.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest
from conftest import drop, load_scans
from fastapi.testclient import TestClient

import reachable_api.main as api_main
import reachable_mcp.server as mcp_server
from reachable_agents.fake import FakeLLM
from reachable_agents.llm import LLMReply, ToolCall
from reachable_api.main import create_app
from reachable_graph.memory import MemoryRepo
from reachable_graph.tools import GraphTools

pytestmark = pytest.mark.integration

KEY = "test-key-" + "y" * 24
H = {"X-API-Key": KEY}
BASE = "test_s6_org_a"
KINDS = {"internet", "asset", "identity", "secret", "datastore"}


class ScriptedAsk:
    """A model for /ask that answers with a fixed tool call."""

    def __init__(self, kind: str, entity: str) -> None:
        self.kind, self.entity, self.calls = kind, entity, 0

    async def chat(self, messages, tools, *, agent, tool_choice="auto"):
        self.calls += 1
        assert agent == "ask" and tools[0]["function"]["name"] == "company_query"
        return LLMReply(
            content=None,
            tool_calls=[
                ToolCall(
                    "c1", "company_query", {"question_kind": self.kind, "entity_id": self.entity}
                )
            ],
            served_by="fake",
            model="fake/ask",
            tokens_in=10,
            tokens_out=5,
            ms=0.0,
            fallback=False,
        )


class GatedLLM(FakeLLM):
    """The stub model, but every call waits for the test to open the gate."""

    def __init__(self, gate: threading.Event) -> None:
        super().__init__()
        self.gate = gate

    async def chat(self, *a, **kw):
        await asyncio.to_thread(self.gate.wait, 30)
        return await super().chat(*a, **kw)


def _app(db, **kw):
    graphs = [BASE, f"{BASE}_v2"]
    tools = GraphTools(db, allowed_orgs=graphs)
    repo = MemoryRepo(db, allowed_orgs=graphs)
    kw.setdefault("llm_factory", lambda fake: FakeLLM())
    app = create_app(
        api_key=KEY,
        repo=repo,
        tools=tools,
        scan_graph=lambda org, scan: BASE if scan == "v1" else f"{BASE}_v2",
        **kw,
    )
    return TestClient(app), repo, tools


@pytest.fixture(scope="module")
def env(db):
    load_scans(db, "org_a", BASE)
    graphs = [BASE, f"{BASE}_v2"]
    tools = GraphTools(db, allowed_orgs=graphs)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(mcp_server, "_tools", lambda: tools)
        c, repo, _ = _app(db)
        r = c.post("/runs", json={"org": "org_a", "scan": "v1", "fake": True}, headers=H)
        run_id = r.json()["run_id"]
        _wait_final(repo, BASE, run_id)
        yield {"db": db, "c": c, "repo": repo, "run": run_id, "tools": tools}
    drop(db, *graphs)


def _wait_final(repo, graph, run_id, timeout=120):
    t = time.monotonic()
    while time.monotonic() - t < timeout:
        if (repo.run_head(graph, run_id) or {}).get("status") in api_main.FINAL:
            return
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} did not finish")


# ------------------------------------------------------------------ findings
def test_findings_board_two_orders_same_findings(env):
    c, run = env["c"], env["run"]
    live = c.get("/orgs/org_a/findings", headers=H).json()
    board = c.get(f"/orgs/org_a/findings?run_id={run}", headers=H).json()
    assert live["source"] == "live" and board["source"] == "run"
    for b in (live, board):
        rows = b["findings"]
        assert set(b["by_severity"]) == set(b["by_reachability"]) == set(rows)
        reach = [f for f in b["by_reachability"] if rows[f]["reach_rank"]]
        assert reach and b["by_reachability"][: len(reach)] == reach  # reachable first
        assert [rows[f]["reach_rank"] for f in reach] == sorted(
            rows[f]["reach_rank"] for f in reach
        )
        ranks = [rows[f]["scanner_rank"] for f in b["by_severity"]]
        assert ranks == sorted(ranks)  # the scanner's order: CVSS, KEV, EPSS
        for f in reach:
            assert rows[f]["status"] == "reachable" and "path #" in rows[f]["why"]
        for x in rows.values():
            assert x["why"] and x["status"] in {
                "reachable",
                "accepted",
                "mitigated",
                "dead_end",
                "internal",
                "unreachable",
            }
        heads = {x["headline"]: x for x in rows.values() if x["headline"]}
        assert heads["reachable"]["reach_rank"] == 1
        if "unreachable" in heads:
            assert heads["unreachable"]["reach_rank"] is None
    assert c.get("/orgs/org_zzz/findings", headers=H).status_code == 404
    other = f"{BASE}_v2:run:abc"
    assert c.get(f"/orgs/org_a/findings?run_id={other}", headers=H).status_code == 422


# ------------------------------------------------------------------ subgraph
def test_subgraph_is_cytoscape_ready_and_marks_the_cuts(env):
    c, run = env["c"], env["run"]
    g = c.get(f"/runs/{run}/subgraph", headers=H).json()
    ids = {n["id"] for n in g["nodes"]}
    assert "internet" in ids and g["paths"] and g["source"] == "run"
    assert {n["kind"] for n in g["nodes"]} <= KINDS
    assert any(n["crown"] and n["kind"] == "datastore" for n in g["nodes"])
    for e in g["edges"]:
        assert e["source"] in ids and e["target"] in ids
        assert e["technique"] and e["id"].startswith(e["rule"])
    for p in g["paths"]:  # every kept path is drawable hop by hop
        assert p["nodes"][0] == "internet" and len(p["steps"]) == len(p["nodes"]) - 1
    edges = {e["id"]: e for e in g["edges"]}
    for mode in ("fewest", "cheapest"):
        cut = set(g["cuts"][mode])
        assert cut
        # Every path crosses at least one edge of each cut.
        for p in g["paths"]:
            assert any(edges[k][f"in_{mode}"] for k in p["steps"]), (mode, p["index"])
    # A fix token that cuts several paths is reported as such.
    for e in g["edges"]:
        assert e["token_paths"] >= e["shared"] >= (0 if e.get("context") else 1)


def test_subgraph_filters_caps_and_context(env):
    c, run = env["c"], env["run"]
    full = c.get(f"/runs/{run}/subgraph", headers=H).json()
    entry = next(e for e in full["edges"] if e["source"] == "internet")
    one = c.get(f"/runs/{run}/subgraph", params={"finding": entry["fix_token"]}, headers=H).json()
    assert one["paths"] and all(
        any(entry["fix_token"] in k for k in p["steps"]) for p in one["paths"]
    )
    assert len(one["nodes"]) <= len(full["nodes"])
    capped = c.get(f"/runs/{run}/subgraph", params={"max_nodes": 6}, headers=H).json()
    assert len(capped["nodes"]) <= 6
    if len(full["nodes"]) > 6:
        assert capped["truncated"] is True
    ctx = c.get(
        f"/runs/{run}/subgraph", params={"finding": entry["fix_token"], "context": True}, headers=H
    ).json()
    assert len(ctx["nodes"]) >= len(one["nodes"])
    assert len(ctx["nodes"]) <= one["caps"]["max_nodes"] + one["caps"]["context_nodes"]
    assert all(
        n.get("context") for n in ctx["nodes"] if n["id"] not in {x["id"] for x in one["nodes"]}
    )
    assert c.get("/runs/test_s6_org_a:run:nope/subgraph", headers=H).status_code == 404


# ------------------------------------------------------- fix plan + simulate
def test_fixplan_both_modes_and_simulate_disconnects(env):
    c, run = env["c"], env["run"]
    got = c.get(f"/runs/{run}", headers=H).json()
    chosen = got["outputs"]["FixPlan"]["payload"]["chosen"]
    for mode in ("fewest", "cheapest"):
        fp = c.get(f"/runs/{run}/fixplan", params={"mode": mode}, headers=H).json()
        assert fp["mode"] == mode and fp["fix_tokens"]
        assert fp["source"] == ("run" if mode == chosen else "tools")
        assert [f["token"] for f in fp["fixes"]] == fp["fix_tokens"] or set(
            f["token"] for f in fp["fixes"]
        ) == set(fp["fix_tokens"])
        for f in fp["fixes"]:
            assert f["ticket"]["title"] and f["action"] and f["paths_cut"] >= 1
        sim = c.post(
            "/orgs/org_a/simulate", json={"scan": "v1", "fix_tokens": fp["fix_tokens"]}, headers=H
        ).json()
        assert sim["data"]["all_crown_jewels_disconnected"] is True
        assert sim["data"]["reachable_before"] and not sim["data"]["reachable_after"]
    assert c.get(f"/runs/{run}/fixplan", params={"mode": "bogus"}, headers=H).status_code == 422
    one = c.post(
        "/orgs/org_a/simulate",
        json={"scan": "v1", "fix_tokens": [fp["fix_tokens"][0]]},
        headers=H,
    ).json()
    assert one["data"]["removed_steps"] >= 1


def test_why_step_endpoint(env):
    c, run = env["c"], env["run"]
    e = c.get(f"/runs/{run}/subgraph", headers=H).json()["edges"][0]
    w = c.get("/orgs/org_a/why_step", params={"key": e["id"]}, headers=H).json()
    assert w["data"]["key"] == e["id"] and w["data"]["fix"]["token"] == e["fix_token"]
    assert w["evidence"]["edges"] and w["queries"]
    bad = c.get("/orgs/org_a/why_step", params={"key": "nope|x|y|z"}, headers=H)
    assert bad.status_code == 422


# ----------------------------------------------------------------------- ask
def test_ask_rules_and_model_map_to_fixed_intents(env):
    db, tools = env["db"], env["tools"]
    adr_asset = tools._q(BASE, "MATCH (:ADR)-[:CHANGED]->(a:Asset) RETURN a.id, a.hostname", {}, [])
    aid, host = adr_asset[0]

    c, _, _ = _app(db)
    r = c.post(
        "/orgs/org_a/ask",
        json={"question": f"Who approved exposing {host}?", "mode": "rules"},
        headers=H,
    ).json()
    assert r["resolved_by"] == "rules" and r["intent"] == "who_approved"
    assert r["params"]["asset_id"] == aid and r["answer"]
    labels = {n["label"] for n in r["evidence"]["nodes"]}
    assert {"ADR", "Person"} <= labels and r["evidence"]["edges"]
    assert all(q["cypher"].lstrip().upper().startswith("MATCH") for q in r["queries"])

    # The model picks the intent; a whole copied line still yields the id.
    model = ScriptedAsk("who_owns", f"{aid}: {host} (web_server); ADR-001 ...")
    c2, _, _ = _app(db, ask_llm=lambda: model)
    r2 = c2.post("/orgs/org_a/ask", json={"question": "who looks after it?"}, headers=H).json()
    assert model.calls == 1 and r2["resolved_by"] == "llm"
    assert r2["intent"] == "who_owns" and r2["params"] == {"asset_id": aid}

    # An id the model made up is never trusted: the rules answer instead.
    liar = ScriptedAsk("who_owns", "org_a:asset:99999999")
    c3, _, _ = _app(db, ask_llm=lambda: liar)
    r3 = c3.post("/orgs/org_a/ask", json={"question": f"who owns {host}?"}, headers=H).json()
    assert r3["resolved_by"] == "rules" and "not in the allowed lists" in r3["note"]
    assert r3["params"]["asset_id"] == aid

    # A host that does not exist is refused, not fuzzily matched.
    r4 = c.post(
        "/orgs/org_a/ask",
        json={"question": "who owns nosuch-host-edge-999?", "mode": "rules"},
        headers=H,
    ).json()
    assert r4["answer"] is None and "No asset named" in r4["error"]


# ------------------------------------------------------------ concurrency cap
def test_third_concurrent_run_gets_429_until_a_slot_frees(env):
    db, repo = env["db"], env["repo"]
    gate = threading.Event()
    c, _, _ = _app(db, llm_factory=lambda fake: GatedLLM(gate), max_runs=2)
    body = {"org": "org_a", "scan": "v1", "fake": True}
    before = len(repo.recent_runs(BASE, 50))
    a = c.post("/runs", json=body, headers=H)
    b = c.post("/runs", json=body, headers=H)
    assert a.status_code == b.status_code == 202
    third = c.post("/runs", json=body, headers=H)
    assert third.status_code == 429
    assert int(third.headers["Retry-After"]) > 0 and "retry" in third.json()["detail"]
    assert len(repo.recent_runs(BASE, 50)) == before + 2  # the refused run wrote nothing
    gate.set()
    for r in (a, b):
        _wait_final(repo, BASE, r.json()["run_id"])
    time.sleep(0.3)  # the worker releases its slot just after the final write
    again = c.post("/runs", json=body, headers=H)
    assert again.status_code == 202
    _wait_final(repo, BASE, again.json()["run_id"])


# ------------------------------------------------- verdict with risk + evals
def test_verdict_can_accept_a_finding_as_a_risk(env):
    c, repo, run = env["c"], env["repo"], env["run"]
    v = c.get(f"/runs/{run}", headers=H).json()["outputs"]["Report"]["payload"]["verdicts"][0]
    r = c.post(
        f"/runs/{run}/verdict",
        json={
            "finding": v["finding"],
            "decision": "accept",
            "reason": "Compensating control in place until the next release.",
            "accept_risk_days": 30,
        },
        headers=H,
    ).json()
    acc = r["risk_acceptance"]
    assert acc["findings"] == [v["finding"]] and acc["expires"] - acc["created"] == 30 * 86400
    live = repo.risk_acceptances(BASE, [v["finding"]], now=acc["created"] + 1)
    assert any(x.id == acc["id"] and x.live for x in live)


def test_evals_endpoint_reads_result_files(env, tmp_path, monkeypatch):
    (tmp_path / "gate_x.json").write_text(json.dumps({"pass": True, "n": 3}), encoding="utf-8")
    (tmp_path / "broken.json").write_text("{nope", encoding="utf-8")
    monkeypatch.setattr(api_main, "EVALS_DIR", tmp_path)
    r = env["c"].get("/evals", headers=H).json()["results"]
    assert r["gate_x"] == {"pass": True, "n": 3} and "error" in r["broken"]
