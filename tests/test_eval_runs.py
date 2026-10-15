"""S7: every prioritiser ranks exactly the scan's open findings, and the ablation
(graph tools off) loses attack-path recall, on a real (test-scale) org.

The three LLM prioritisers run their real toolboxes (read-only SQL, pgvector
search with the local embedder, the FalkorDB tools over MCP) driven by a
policy model: it makes one tool call, then ranks the finding ids it saw in the
tool results, else those in CONTEXT.scanner_top. No network.
"""

from __future__ import annotations

import asyncio
import json
import re

import pytest

from reachable_agents.llm import LLMReply, ToolCall
from reachable_eval.base import SeveritySort, SmartScore
from reachable_eval.reachable import UNAVAILABLE, reachable
from reachable_eval.scoring import score_order
from reachable_eval.sql_agent import sql_agent
from reachable_eval.vector_rag import vector_rag

pytestmark = pytest.mark.integration

FINDING = re.compile(r"[a-z_]+:finding:\d{5}")
FIRST_CALL = {
    "sql_agent": ("sql_query", {"sql": "SELECT id FROM findings WHERE status = 'open' LIMIT 8"}),
    "vector_rag": ("search_inventory", {"query": "Internet-facing web server finding", "k": 8}),
    "reachable": ("scan_findings", {"limit": 20}),
    "reachable_graph_off": ("scan_findings", {"limit": 20}),
}


class Policy:
    model = "fake/policy"

    def __init__(self, first: tuple[str, dict]) -> None:
        self.first, self.calls = first, 0

    async def chat(self, messages, tools, *, agent, tool_choice="auto"):
        self.calls += 1
        if self.calls == 1 and tool_choice != "none":
            return LLMReply(
                None, [ToolCall("t1", *self.first)], "fake", self.model, 50, 5, 0, False
            )
        seen = []
        for m in messages:
            if m["role"] == "tool" and '"error"' not in m["content"][:12]:
                seen += FINDING.findall(m["content"])
        if not seen:  # nothing from the tools: fall back on the scanner's list
            ctx = json.loads(messages[1]["content"].split("\n", 1)[1])
            seen = [f["finding"] for f in ctx["scanner_top"]]
        ranked = [{"finding": f, "why": "seen"} for f in dict.fromkeys(seen)][:20]
        body = json.dumps({"ranked": ranked, "fix_set": [], "reasoning": "policy"})
        return LLMReply(body, [], "fake", self.model, 50, 5, 0, False)


def llm_prioritisers():
    def f(name):
        return lambda seed: Policy(FIRST_CALL[name])

    return [
        sql_agent(llm_factory=f("sql_agent")),
        vector_rag(llm_factory=f("vector_rag")),
        reachable(llm_factory=f("reachable")),
    ]


def test_universe_is_the_graphs_open_findings(eval_env):
    g = eval_env["db"].select_graph(eval_env["ref"].graph)
    ids = {r[0] for r in g.ro_query("MATCH (f:Finding {status: 'open'}) RETURN f.id").result_set}
    assert set(eval_env["data"].universe) == ids


@pytest.mark.parametrize(
    "which", ["severity_sort", "smart_score", "sql_agent", "vector_rag", "reachable"]
)
def test_every_prioritiser_ranks_exactly_the_scans_findings(eval_env, which):
    data = eval_env["data"]
    p = {x.name: x for x in [SeveritySort(), SmartScore(), *llm_prioritisers()]}[which]
    r = asyncio.run(p.rank(data, seed=1))
    assert len(r.order) == len(set(r.order)) == len(data.universe)
    assert set(r.order) == set(data.universe)
    if p.uses_llm:
        assert r.head and r.meta["llm_answered"], r.meta
        assert all(t["ok"] for t in r.tool_log), r.tool_log


def test_ablation_graph_off_loses_path_recall(eval_env):
    data, truth = eval_env["data"], eval_env["truth"]
    on = asyncio.run(reachable(llm_factory=lambda s: Policy(FIRST_CALL["reachable"])).rank(data))
    off = asyncio.run(
        reachable(llm_factory=lambda s: Policy(FIRST_CALL["reachable"]), graph_off=True).rank(data)
    )
    assert [t["error"] for t in off.tool_log] == [UNAVAILABLE]
    s_on, s_off = score_order(on.order, truth), score_order(off.order, truth)
    assert s_off["path_recall@10"] < s_on["path_recall@10"]
    assert s_off["ndcg@10"] < s_on["ndcg@10"]
