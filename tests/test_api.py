"""S5: the API and its live stream (fake model), on throwaway graphs.

A run started with POST /runs streams ordered events over SSE: agent entered,
tool called (with the Cypher and timing the tool logged), path found, finding
ranked, fix chosen, ending in report_ready. The stream is read from the trace
the agents write; it can be resumed with Last-Event-ID.
"""

from __future__ import annotations

import json

import pytest
from conftest import drop, load_scans
from fastapi.testclient import TestClient

import reachable_mcp.server as mcp_server
from reachable_agents.fake import FakeLLM
from reachable_api.main import create_app
from reachable_graph.memory import MemoryRepo
from reachable_graph.tools import GraphTools

pytestmark = pytest.mark.integration

KEY = "test-key-" + "x" * 24
H = {"X-API-Key": KEY}
BASE = "test_api_org_a"


@pytest.fixture(scope="module")
def client(db):
    load_scans(db, "org_a", BASE)
    graphs = [BASE, f"{BASE}_v2"]
    tools = GraphTools(db, allowed_orgs=graphs)
    repo = MemoryRepo(db, allowed_orgs=graphs)
    app = create_app(
        api_key=KEY,
        repo=repo,
        tools=tools,
        llm_factory=lambda fake: FakeLLM(),
        scan_graph=lambda org, scan: BASE if scan == "v1" else f"{BASE}_v2",
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(mcp_server, "_tools", lambda: tools)
        yield TestClient(app), repo
    drop(db, *graphs)


def read_stream(c: TestClient, run_id: str, headers: dict | None = None) -> list[dict]:
    """Every event until report_ready / run_failed, with its SSE id."""
    events, ev, eid = [], None, None
    with c.stream("GET", f"/runs/{run_id}/stream", headers={**H, **(headers or {})}) as s:
        assert s.status_code == 200
        assert s.headers["content-type"].startswith("text/event-stream")
        for line in s.iter_lines():
            if line.startswith("id:"):
                eid = int(line[3:])
            elif line.startswith("event:"):
                ev = line[6:].strip()
            elif line.startswith("data:"):
                d = json.loads(line[5:])
                assert d["type"] == ev
                events.append({**d, "_id": eid})
                if ev in ("report_ready", "run_failed"):
                    break
    return events


def test_auth_matches_the_mcp_server(client):
    c, _ = client
    assert c.get("/orgs").status_code == 401
    assert c.get("/orgs", headers={"X-API-Key": "wrong"}).status_code == 401
    assert c.get("/orgs", headers={"Authorization": f"Bearer {KEY}"}).status_code == 200
    assert c.get("/health").status_code in (200, 503)  # open, no key


def test_run_streams_ordered_events_ending_in_report_ready(client):
    c, repo = client
    r = c.post("/runs", json={"org": "org_a", "scan": "v1", "fake": True}, headers=H)
    assert r.status_code == 202
    run_id = r.json()["run_id"]
    events = read_stream(c, run_id)
    types = [e["type"] for e in events]
    assert types[-1] == "report_ready" and events[-1]["status"] == "complete"
    seqs = [e["seq"] for e in events if "seq" in e]
    assert seqs == sorted(seqs)  # in trace order
    assert types[0] == "agent_entered" and events[0]["agent"] == "triage"
    entered = [e["agent"] for e in events if e["type"] == "agent_entered"]
    assert entered == ["triage", "pathfinder", "fixer", "reporter"]
    for kind in ("tool_called", "llm_called", "path_found", "finding_ranked", "fix_chosen"):
        assert kind in types, kind
    order = [types.index(k) for k in ("path_found", "finding_ranked", "fix_chosen")]
    assert order == sorted(order) and order[-1] < types.index("report_ready")
    tool = next(e for e in events if e["type"] == "tool_called" and e["queries"])
    assert tool["queries"][0]["cypher"] and "ms" in tool["queries"][0] and tool["ms"] is not None
    fix = next(e for e in events if e["type"] == "fix_chosen")
    assert fix["verified"] is True and fix["fix_tokens"]

    # the finished run, from the graph
    got = c.get(f"/runs/{run_id}", headers=H).json()
    assert got["run"]["status"] == "complete"
    assert set(got["outputs"]) == {"Triage", "PathAnalysis", "FixPlan", "Report"}
    assert all("result" not in s for s in got["steps"])

    # resume: Last-Event-ID replays only what came after it
    mid = events[len(events) // 2]["_id"]
    again = read_stream(c, run_id, {"Last-Event-ID": str(mid)})
    assert all(e["seq"] > mid for e in again if "seq" in e)
    assert again[-1]["type"] == "report_ready"


def test_v2_run_streams_the_sentinel_and_its_alert(client):
    c, _ = client
    run_id = c.post("/runs", json={"org": "org_a", "scan": "v2", "fake": True}, headers=H).json()[
        "run_id"
    ]
    events = read_stream(c, run_id)
    types = [e["type"] for e in events]
    assert events[0]["type"] == "agent_entered" and events[0]["agent"] == "sentinel"
    assert types.index("drift_checked") < types.index("alert_raised") < types.index("triage_done")
    assert "memory" in types and types[-1] == "report_ready"


def test_drift_orgs_and_verdict_endpoints(client):
    c, repo = client
    d = c.get("/orgs/org_a/drift", headers=H).json()
    assert d["data"]["new_crown_path"] is True and len(d["data"]["new_paths"]) == 1
    orgs = c.get("/orgs", headers=H).json()
    a = next(o for o in orgs if o["org"] == "org_a")
    assert [s["scan"] for s in a["scans"]] == ["v1", "v2"] and a["scans"][0]["recent_runs"]
    run_id = a["scans"][0]["recent_runs"][0]["id"]
    verdicts = c.get(f"/runs/{run_id}", headers=H).json()["outputs"]["Report"]["payload"][
        "verdicts"
    ]
    v = verdicts[0]
    r = c.post(
        f"/runs/{run_id}/verdict",
        json={"finding": v["finding"], "decision": "accept", "reason": "Agreed, as decided."},
        headers=H,
    )
    assert r.status_code == 200 and r.json()["decision"] == v["decision"]
    bad = c.post(
        f"/runs/{run_id}/verdict",
        json={"finding": "org_a:finding:99999", "decision": "reject", "reason": "nope nope"},
        headers=H,
    )
    assert bad.status_code == 422
    assert c.get("/runs/org_zzz:run:abc", headers=H).status_code == 404
