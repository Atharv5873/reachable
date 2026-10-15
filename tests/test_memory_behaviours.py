"""S5: the three memory behaviours, each shown changing what a later run does,
and memory lift (Gate B) with the deterministic stub model.

One org at test scale: scan v1 in `test_mb_org_a`, the rescan v2 in
`test_mb_org_a_v2`. The agents triage v1 once (that run is the memory); every
v2 comparison is cold (memory reset, nothing carried) vs warm (memory reset, then
v1's memory carried over by the Sentinel), on the same graph.
"""

from __future__ import annotations

import asyncio
import importlib.util

import pytest
from conftest import drop, load_scans
from test_memory import infra_fingerprint

import reachable_mcp.server as mcp_server
from reachable_agents.fake import FakeLLM
from reachable_agents.graph import run_agents
from reachable_core.settings import REPO_ROOT
from reachable_graph.memory import ESCALATE, MemoryRepo, is_reusable
from reachable_graph.tools import GraphTools

pytestmark = pytest.mark.integration

BASE = "test_mb_org_a"
V2 = f"{BASE}_v2"
REASON = (
    "An Internet-facing exploit on a crown-jewel path gets patched now, even when the cut "
    "is further in: one funnel fix is a single point of failure."
)


@pytest.fixture(scope="module")
def env(db):
    ob1, ob2, new_path = load_scans(db, "org_a", BASE)
    tools = GraphTools(db, allowed_orgs=[BASE, V2])
    repo = MemoryRepo(db, allowed_orgs=[BASE, V2])
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(mcp_server, "_tools", lambda: tools)
        v1 = asyncio.run(run_agents("org_a", "v1", llm=FakeLLM(), repo=repo, graph=BASE))
        yield ob1, ob2, new_path, tools, repo, v1
    drop(db, BASE, V2)


def run_v2(repo, *, warm: bool) -> dict:
    """Reset v2's memory, run, and capture the run right away (the next run's
    reset deletes it from the graph)."""
    repo.reset_memory(V2)
    res = asyncio.run(
        run_agents("org_a", "v2", llm=FakeLLM(), repo=repo, graph=V2, carry_memory=warm)
    )
    return {**res, **repo.agent_run(V2, res["run_id"])}


def out(repo, res, label):
    return res["outputs"][label]["payload"]


def steps(repo, res):
    return res["steps"]


# ------------------------------------------------------------------ episodic
def test_episodic_warm_run_does_not_reinvestigate_standing_verdicts(env):
    *_, repo, v1 = env
    cold, warm = run_v2(repo, warm=False), run_v2(repo, warm=True)
    tc, tw = out(repo, cold, "Triage"), out(repo, warm, "Triage")
    assert tc["carried"] == [] and tc["skipped_by_memory"] == 0
    assert tw["skipped_by_memory"] == len(tw["carried"]) > 0
    assert len(tw["investigate"]) < len(tc["investigate"])
    # every carried finding starts from v1's verdict, not from scratch
    v1_verdicts = {
        v["id"] for v in repo.read_output(BASE, v1["run_id"], "Report")["payload"]["verdicts"]
    }
    assert {c["verdict"] for c in tw["carried"]} <= v1_verdicts
    carried = {c["finding"] for c in tw["carried"]}
    assert not carried & {f["finding"] for f in tw["investigate"]}
    # recall happens BEFORE the model reasons: the memory step precedes Triage's first LLM call
    trace = steps(repo, warm)
    mem = next(s["seq"] for s in trace if s.get("tool") == "carried_verdicts")
    first_llm = next(s["seq"] for s in trace if s["kind"] == "llm" and s["agent"] == "triage")
    assert mem < first_llm
    # and the Fixer reused v1's routing instead of looking every owner up again
    routes = next(s for s in trace if s.get("tool") == "remembered_routes")
    assert routes["detail"]["from_run"] == v1["run_id"] and routes["detail"]["assets"]
    owners = lambda r: sum(1 for s in steps(repo, r) if s.get("tool") == "owners")  # noqa: E731
    assert owners(warm) < owners(cold)


# ------------------------------------------------------------------ semantic
def test_semantic_pattern_from_v1_flags_the_new_entry_on_arrival(env):
    *_, new_path, _, repo, v1 = env
    learned = repo.read_output(BASE, v1["run_id"], "Report")["payload"]["patterns_learned"]
    assert learned and all(p["cpe"] for p in learned)
    entry_asset = new_path.hops[0].dst.split(":", 1)[1]
    cold, warm = run_v2(repo, warm=False), run_v2(repo, warm=True)
    dc, dw = out(repo, cold, "Drift"), out(repo, warm, "Drift")
    assert dc["flagged_on_arrival"] == {}  # cold: no pattern to fire
    ctx = repo.finding_context(V2, list(dw["flagged_on_arrival"]))
    entry = [f for f, c in ctx.items() if c["asset"] == entry_asset]
    assert entry, "the new path's entry finding was not flagged on arrival"
    learned_ids = {p["id"] for p in learned}
    assert learned_ids & {p["pattern"] for p in dw["flagged_on_arrival"][entry[0]]}
    # before any path search: the flag step precedes the Sentinel's path diff
    trace = steps(repo, warm)
    flag = next(s["seq"] for s in trace if s.get("tool") == "pattern_flags")
    paths = next(
        s["seq"]
        for s in trace
        if s.get("tool") == "exposure_drift" and s["input"].get("include_paths", True)
    )
    assert flag < paths
    tw = out(repo, warm, "Triage")
    assert entry[0] in {f["finding"] for f in tw["investigate"] if f.get("flagged_by")}


# ---------------------------------------------------------------- procedural
def test_procedural_reject_writes_a_playbook_version_that_changes_a_later_decision(env):
    *_, repo, v1 = env
    tp = repo.read_output(BASE, v1["run_id"], "Triage")["payload"]
    entries = {f["finding"]: f for f in tp["investigate"] + tp["carried"]}
    verdicts = repo.read_output(BASE, v1["run_id"], "Report")["payload"]["verdicts"]
    target = next(
        v["finding"] for v in verdicts if v["decision"] == "schedule" and v["finding"] in entries
    )
    tech = entries[target]["techniques"][0]
    before = repo.current_playbook(BASE, tech)

    assert is_reusable(REASON) and not is_reusable("This host is decommissioned on Friday.")
    res = repo.record_analyst_verdict(BASE, v1["run_id"], target, "reject", REASON)
    assert res["decision"] == ESCALATE["schedule"] == "fix_now" and res["reusable"]
    (pb,) = res["playbooks"]
    assert pb["version"] == before.version + 1 and pb["supersedes"] == before.id
    hist = repo.playbook_history(BASE, tech)
    assert [h.version for h in hist] == list(range(pb["version"], 0, -1))  # old versions kept
    assert repo.current_playbook(BASE, tech).policy[-1]["decision"] == "fix_now"

    # The next scan's run uses v3 and decides differently on the same finding...
    warm = run_v2(repo, warm=True)
    tw = out(repo, warm, "Triage")
    assert any(p["version"] == pb["version"] for p in tw["playbooks"] if p["technique"] == tech)
    got = {v["finding"]: v for v in out(repo, warm, "Report")["verdicts"]}
    assert got[target]["decision"] == "fix_now" and got[target]["playbook"] == pb["id"]
    # ...while a cold run (no playbook rule) keeps the default decision.
    cold = run_v2(repo, warm=False)
    assert {v["finding"]: v["decision"] for v in out(repo, cold, "Report")["verdicts"]}[
        target
    ] == "schedule"
    # A reject about one instance only records the verdict: no new version.
    other = next(v["finding"] for v in verdicts if v["finding"] != target)
    res = repo.record_analyst_verdict(
        BASE, v1["run_id"], other, "reject", "This host is decommissioned on Friday."
    )
    assert res["reusable"] is False and res["playbooks"] == []


# ------------------------------------------------------- reset and carry-over
def test_reset_is_genuinely_cold_and_never_touches_infrastructure(env, db):
    *_, repo, _ = env
    g = db.select_graph(V2)
    before = infra_fingerprint(g)
    repo.reset_memory(V2)
    assert infra_fingerprint(g) == before
    left = repo._r(
        V2,
        "MATCH (n) WHERE n:Run OR n:Verdict OR n:RiskAcceptance OR n:Pattern OR n:Triage "
        "OR n:AgentStep OR n:Alert RETURN count(n)",
    )
    assert left == [[0]]
    starters = repo._r(V2, "MATCH (p:Playbook) RETURN count(p), count(p.source)")
    assert starters[0][0] > 0 and starters[0][1] == 0  # starter playbooks only


def test_carry_over_is_idempotent(env):
    *_, repo, _ = env
    repo.reset_memory(V2)
    first = repo.carry_over(BASE, V2)
    count = lambda: repo._r(V2, "MATCH (n:Verdict) RETURN count(n)")[0][0]  # noqa: E731
    n = count()
    assert repo.carry_over(BASE, V2) == first and count() == n


# ---------------------------------------------------------------- memory lift
def test_memory_lift_warm_does_less_work_and_both_are_correct(db, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "memory_lift", REPO_ROOT / "evals" / "memory_lift.py"
    )
    lift = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lift)
    # the eval re-points the in-process MCP server; restore it afterwards
    monkeypatch.setattr(mcp_server, "_tools", mcp_server._tools)
    args = type("A", (), {"org": "org_b", "seed": 42, "scale": 0.05, "fake": True, "keep": False})
    res = asyncio.run(lift.main_async(args))
    c, w = res["cold"], res["warm"]
    assert res["gate_b"]["pass"], res["gate_b"]
    assert w["findings_investigated"] < c["findings_investigated"]
    assert w["tool_calls"] < c["tool_calls"] and w["llm_calls"] <= c["llm_calls"]
    for r in (c, w):
        assert r["eval_simulate_fix_disconnects"] and r["fix_set_size"] == r["oracle_min_cut_size"]
    assert "lift_org_b" not in db.list_graphs()  # the eval cleaned up its namespace
