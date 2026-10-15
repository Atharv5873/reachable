"""S5: two runs on the same org graph at once.

Per-run keying keeps their traces apart (FalkorDB applies each write query
atomically, one writer per graph at a time); the one read-modify-write memory
update, publishing the next playbook version, is serialised by a short lock in
the FalkorDB server itself, so concurrent writers do not lose updates.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest
from conftest import drop, load_scans

import reachable_mcp.server as mcp_server
from reachable_agents.fake import FakeLLM
from reachable_agents.graph import run_agents
from reachable_graph.memory import MemoryError_, MemoryRepo
from reachable_graph.tools import GraphTools

pytestmark = pytest.mark.integration

BASE = "test_conc_org_a"


@pytest.fixture(scope="module")
def env(db):
    load_scans(db, "org_a", BASE)
    graphs = [BASE, f"{BASE}_v2"]
    tools = GraphTools(db, allowed_orgs=graphs)
    repo = MemoryRepo(db, allowed_orgs=graphs)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(mcp_server, "_tools", lambda: tools)
        yield repo
    drop(db, *graphs)


def _run(repo, graph, scan):
    return asyncio.run(run_agents("org_a", scan, llm=FakeLLM(), repo=repo, graph=graph))


@pytest.mark.parametrize("scan", ["v1", "v2"])
def test_two_simultaneous_runs_keep_intact_separate_traces(env, scan):
    repo = env
    graph = BASE if scan == "v1" else f"{BASE}_v2"
    with ThreadPoolExecutor(2) as ex:
        a, b = ex.map(lambda _: _run(repo, graph, scan), range(2))
    assert a["run_id"] != b["run_id"]
    for r in (a, b):
        assert r["status"] == "complete"
        dump = repo.agent_run(graph, r["run_id"])
        assert dump["chain_ok"]  # seq 0..n-1, NEXT edges exactly in order
        labels = {"Triage", "PathAnalysis", "FixPlan", "Report"} | (
            {"Drift"} if scan == "v2" else set()
        )
        assert set(dump["outputs"]) == labels
        assert dump["outputs"]["FixPlan"]["payload"]["verified"] is True
        # every handoff each agent read back was its own run's
        chain = repo._r(
            graph,
            "MATCH (:Run {id: $id})-[:HAS_OUTPUT]->(o) RETURN count(o)",
            {"id": r["run_id"]},
        )
        assert chain == [[len(labels)]]
    # no step belongs to two runs; no NEXT edge crosses from one run into the other
    assert repo._r(
        graph,
        "MATCH (s:AgentStep)<-[:HAS_STEP]-(r:Run) WITH s, count(r) AS n WHERE n <> 1 "
        "RETURN count(s)",
    ) == [[0]]
    assert repo._r(
        graph,
        "MATCH (ra:Run)-[:HAS_STEP]->(:AgentStep)-[:NEXT]->(:AgentStep)<-[:HAS_STEP]-(rb:Run) "
        "WHERE ra <> rb RETURN count(*)",
    ) == [[0]]
    # memory writes from both runs landed: each run's Triage holds its own verdicts
    for r in (a, b):
        n = repo._r(
            graph,
            "MATCH (:Run {id: $id})-[:HAS_TRIAGE]->(:Triage)-[:HAS_VERDICT]->(v:Verdict) "
            "RETURN count(v)",
            {"id": r["run_id"]},
        )[0][0]
        rep = repo.read_output(graph, r["run_id"], "Report")["payload"]["verdicts"]
        assert n == len(rep) > 0


def test_playbook_versions_lose_updates_without_the_lock_and_none_with_it(env):
    repo = env

    def bump(i, lock):
        try:
            return repo.add_playbook_version(BASE, "T1210", f"writer {i}", lock=lock).version
        except MemoryError_:
            return None  # refused: someone published "my" version first

    start = repo.current_playbook(BASE, "T1210").version
    with ThreadPoolExecutor(8) as ex:
        racy = list(ex.map(lambda i: bump(i, False), range(8)))
    mid = repo.current_playbook(BASE, "T1210").version
    published = [v for v in racy if v is not None]
    # Without the lock several writers read the same current version: their
    # updates collide and are refused (by the deterministic id), i.e. lost.
    assert len(published) == mid - start and len(published) <= 8

    repo.lock_waits = 0
    with ThreadPoolExecutor(8) as ex:
        locked = list(ex.map(lambda i: bump(i, True), range(8)))
    assert sorted(locked) == list(range(mid + 1, mid + 9))  # all 8, consecutive
    hist = repo.playbook_history(BASE, "T1210")
    assert [h.version for h in hist] == list(range(mid + 8, 0, -1))
    # each version supersedes exactly the one before it (the starter v1 keeps the
    # generator's id prefix, hence the suffix check)
    broken = [
        (h.version, h.supersedes)
        for h in hist[:-1]
        if not h.supersedes.endswith(f":playbook:T1210:v{h.version - 1}")
    ]
    assert broken == []
