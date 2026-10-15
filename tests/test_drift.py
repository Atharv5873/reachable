"""S5: exposure_drift and the Sentinel.

v1 -> v2 of every org (test scale): the drift reports exactly ONE new crown-jewel
path, the planted config change, with evidence; the paths that the fixes closed
are reported as closed, never alerted on. A rescan whose only change is a fix
raises nothing.
"""

from __future__ import annotations

import asyncio

import pytest
from conftest import ORGS, drop, load_scans

import reachable_mcp.server as mcp_server
from reachable_agents.sentinel import run_sentinel
from reachable_graph.derive import derive
from reachable_graph.memory import MemoryRepo
from reachable_graph.tools import GraphTools

pytestmark = pytest.mark.integration


def _ids(seq: list[str]) -> list[str]:
    """planted node sequence ('asset:<id>', 'internet') -> graph node ids."""
    return [n if n == "internet" else n.split(":", 1)[1] for n in seq]


@pytest.fixture(scope="module")
def scans(db):
    out = {}
    for org in ORGS:
        base = f"test_drift_{org}"
        out[org] = (base, *load_scans(db, org, base))
    # A rescan that ONLY fixed something: org_a v1 with the easy path's entry
    # finding marked fixed (no new path anywhere).
    ob1 = out["org_a"][1]
    easy = next(p for p in ob1.ground_truth.paths if p.name == "easy_web_db")
    entry = _ids([easy.hops[0].dst])[0]
    fixonly = "test_drift_fixonly_org_a"
    drop(db, fixonly, f"{fixonly}_v2")
    db.select_graph(out["org_a"][0]).copy(fixonly)
    db.select_graph(out["org_a"][0]).copy(f"{fixonly}_v2")
    g = db.select_graph(f"{fixonly}_v2")
    g.query("MATCH (f:Finding)-[:ON]->(:Asset {id: $a}) SET f.status = 'fixed'", {"a": entry})
    derive(g)
    graphs = [b for b, *_ in out.values()] + [fixonly]
    allowed = [x for b in graphs for x in (b, f"{b}_v2")]
    tools = GraphTools(db, allowed_orgs=allowed)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(mcp_server, "_tools", lambda: tools)
        yield out, tools, MemoryRepo(db, allowed_orgs=allowed), fixonly
    drop(db, *allowed)


@pytest.mark.parametrize("org", ORGS)
def test_drift_fires_on_exactly_the_planted_path(scans, org):
    out, tools, _, _ = scans
    base, ob1, ob2, new_path = out[org]
    d = tools.exposure_drift(base).data
    assert d["new_crown_path"] is True
    assert len(d["new_paths"]) == 1
    (p,) = d["new_paths"]
    assert [n["id"] for n in p["nodes"]] == _ids(new_path.node_sequence())
    # evidence: the config change's nodes and steps did not exist in v1
    assert p["new_nodes"] and set(p["new_nodes"]) <= {n["id"] for n in p["nodes"]}
    assert len(p["new_steps"]) == len(p["steps"])
    assert not tools._nodes(base, p["new_nodes"], [])  # absent from v1
    assert set(tools._nodes(f"{base}_v2", p["new_nodes"], [])) == set(p["new_nodes"])
    # silent on closed paths: reported, with the fix that closed them, never "new"
    assert d["closed_paths"] and d["cost_changed"] == []
    fixed = set(ob2.ground_truth.fixed_findings)
    for c in d["closed_paths"]:
        assert set(c["fixed_findings"]) <= fixed and c["fixed_findings"]
    assert d["paths_after"] == d["paths_before"] - len(d["closed_paths"]) + 1
    assert d["unchanged"] == d["paths_before"] - len(d["closed_paths"])


def test_drift_is_silent_when_a_rescan_only_fixed_things(scans):
    _, tools, _, fixonly = scans
    d = tools.exposure_drift(fixonly).data
    assert d["new_crown_path"] is False and d["new_paths"] == []
    assert len(d["closed_paths"]) >= 1 and d["arrived_findings"] == []


def test_arrivals_need_no_path_search(scans):
    out, tools, _, _ = scans
    r = tools.exposure_drift(out["org_a"][0], include_paths=False)
    assert r.data["arrived_findings"] and "new_paths" not in r.data
    assert not any("ATTACK_STEP" in q.cypher for q in r.queries)


def test_sentinel_alerts_on_the_new_path_and_not_on_a_fix(scans):
    out, _, repo, fixonly = scans
    base, _, _, new_path = out["org_c"]
    res = asyncio.run(run_sentinel("org_c", repo=repo, graph=f"{base}_v2", carry=False))
    d = res["drift"]
    assert res["status"] == "complete" and d["alert"]
    alerts = repo.alerts(f"{base}_v2")
    assert [a["id"] for a in alerts] == [d["alert"]] and alerts[0]["kind"] == "new_crown_path"
    cited = repo._r(
        f"{base}_v2",
        "MATCH (:Alert {id: $id})-[:CITES]->(f:Finding) RETURN f.id",
        {"id": d["alert"]},
    )
    assert {r[0] for r in cited} == set(d["new_path_findings"])
    # the Sentinel's trace: arrivals (no path search) before the path diff
    steps = repo.agent_run(f"{base}_v2", res["run_id"])["steps"]
    drift_calls = [s for s in steps if s.get("tool") == "exposure_drift"]
    assert [s["input"].get("include_paths", True) for s in drift_calls] == [False, True]

    quiet = asyncio.run(run_sentinel("org_a", repo=repo, graph=f"{fixonly}_v2", carry=False))
    assert quiet["drift"]["alert"] is None and quiet["drift"]["new_crown_path"] is False
    assert repo.alerts(f"{fixonly}_v2") == []
