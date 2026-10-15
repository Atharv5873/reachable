"""S5 Step 0: the token trim.

Compared with the S4 pipeline measured on the SAME graph (org_a v1, test scale)
with the same stub model and the same token proxy (tests/data/s4_baseline_org_a.json,
measured with the S4 code at commit 2637d6f), the S5 pipeline sends at most half
the input tokens and reaches the same triage decision: the same fix set and the
same verdict on every finding. (The real-model numbers: learning/S05.md.)
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from conftest import TEST_SCALE, TEST_SEED, drop

import reachable_mcp.server as mcp_server
from reachable_agents.agents import verify_mismatch
from reachable_agents.fake import FakeLLM
from reachable_agents.graph import run_agents
from reachable_agents.mcp_tools import brief_description
from reachable_agents.runtime import for_llm
from reachable_graph.derive import derive
from reachable_graph.memory import MemoryRepo
from reachable_graph.tools import GraphTools
from reachable_orggen.build import generate_org
from reachable_orggen.generate import GenConfig
from reachable_orggen.load_falkordb import load_org

BASELINE = json.loads((Path(__file__).parent / "data" / "s4_baseline_org_a.json").read_text())
GRAPH = "test_trim_org_a"


@pytest.fixture(scope="module")
def run(db):
    ob = generate_org("org_a", TEST_SEED, GenConfig(scale=TEST_SCALE))
    ob.dataset.org = GRAPH
    load_org(db, ob.dataset)
    derive(db.select_graph(GRAPH))
    tools = GraphTools(db, allowed_orgs=[GRAPH])
    repo = MemoryRepo(db, allowed_orgs=[GRAPH])
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(mcp_server, "_tools", lambda: tools)
        res = asyncio.run(run_agents("org_a", llm=FakeLLM(), repo=repo, graph=GRAPH))
        yield res, repo.agent_run(GRAPH, res["run_id"]), tools
    drop(db, GRAPH)


@pytest.mark.integration
def test_tokens_at_most_half_of_s4_on_the_same_graph(run):
    res, _, _ = run
    assert res["status"] == "complete"
    assert res["stats"]["tokens_in"] <= 0.5 * BASELINE["tokens_in"], (
        res["stats"]["tokens_in"],
        BASELINE["tokens_in"],
    )
    assert res["stats"]["llm_calls"] < BASELINE["llm_calls"]


@pytest.mark.integration
def test_triage_decision_unchanged(run):
    _, dump, _ = run
    tp = dump["outputs"]["Triage"]["payload"]
    rp = dump["outputs"]["Report"]["payload"]
    assert dump["outputs"]["FixPlan"]["payload"]["fix_tokens"] == BASELINE["fix"]
    assert {v["finding"]: v["decision"] for v in rp["verdicts"]} == BASELINE["verdicts"]
    assert sorted(s["finding"] for s in tp["suppressed"]) == BASELINE["suppressed"]
    assert sorted(d["finding"] for d in tp["deprioritised"]) == BASELINE["deprioritised"]
    assert sorted(e["finding"] for e in tp["expired_acceptances"]) == BASELINE["expired"]
    # Triage now names only the Internet-facing candidates; S4's list also had the
    # internal crown-path hops, which the Pathfinder still ranks (same verdicts above).
    inv = {f["finding"] for f in tp["investigate"]}
    assert inv <= set(BASELINE["investigate"]) and all(
        f["from_internet"] for f in tp["investigate"]
    )


@pytest.mark.integration
def test_the_model_reads_compact_views_and_the_trace_keeps_everything(run):
    _, dump, _ = run
    tool_steps = [s for s in dump["steps"] if s["kind"] == "tool" and s.get("result")]
    full = sum(len(for_llm(s["result"])) for s in tool_steps)
    shown = sum(len(for_llm(s["result"], tool=s["tool"])) for s in tool_steps)
    assert shown < 0.75 * full
    owners = next(s for s in tool_steps if s["tool"] == "owners")
    view = json.loads(for_llm(owners["result"], tool="owners"))["data"]
    assert view["teams"][0]["id"] and view["teams"][0]["on_call"]["person"]  # ids survive
    assert "members" in owners["result"]["data"]["teams"][0]  # the trace keeps the rest
    preloaded = [s["tool"] for s in tool_steps if s.get("by") == "run"]
    assert {"scan_findings", "attack_paths", "min_cut"} <= set(preloaded)


def test_brief_description_keeps_what_the_tool_answers():
    d = "Top-k paths from the Internet. Each path lists hops. USE to rank. Do NOT use for cuts."
    assert brief_description(d) == "Top-k paths from the Internet. Each path lists hops."
    assert len(brief_description("x" * 1000)) <= 320


def test_fixer_must_answer_with_the_set_it_simulated():
    class R:
        def __init__(self, toks):
            self.result = {"data": {"fix_tokens": toks}}

    class Ctx:
        def results_of(self, name):
            return [R(["a", "b"])]

    assert verify_mismatch(Ctx(), {"fix_tokens": ["b", "a"]}) is None
    msg = verify_mismatch(Ctx(), {"fix_tokens": ["a", "c"]})
    assert msg and "NOT verified" in msg
