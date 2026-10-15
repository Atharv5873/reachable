"""The agent graph: a LangGraph StateGraph, Triage -> Pathfinder -> Fixer -> Reporter.

State is a small, JSON-serialisable dict: who/what/when (org, scan, graph,
run_id, as_of), the budget snapshot, and POINTERS to each agent's output node
in the org graph. The outputs themselves are not in the state: each agent
writes its output to FalkorDB (via MemoryRepo) and the next agent reads it back
by run id. So the state is cheap to checkpoint, and the run is replayable from
the graph alone.

Live objects (the MCP session, the LLM, the FalkorDB connection) are NOT state:
they live in RunCtx, which the nodes close over. A checkpointer can then save
the state after every node without trying to pickle a socket.
"""

from __future__ import annotations

import operator
import time
from typing import Annotated, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from reachable_core.settings import get_settings
from reachable_graph.memory import MemoryRepo

from .agents import fixer_agent, pathfinder_agent, reporter_agent, triage_agent
from .llm import ChatModel
from .mcp_tools import McpToolbox
from .runtime import Budget, RunCtx

AGENTS = (
    ("triage", "Triage", triage_agent),
    ("pathfinder", "PathAnalysis", pathfinder_agent),
    ("fixer", "FixPlan", fixer_agent),
    ("reporter", "Report", reporter_agent),
)


def _merge(a: dict, b: dict) -> dict:
    return {**a, **b}


class RunState(TypedDict, total=False):
    org: str
    scan: str
    graph: str  # the FalkorDB graph: <org> for v1, <org>_v2 for v2
    run_id: str
    as_of: int  # the run's clock (epoch s): the scan's time, never wall clock
    scan_info: dict
    budget: dict  # caps + usage, refreshed after every agent
    outputs: Annotated[dict[str, str], _merge]  # output label -> node id (the handoffs)
    summaries: Annotated[dict[str, str], _merge]
    log: Annotated[list[str], operator.add]


def build_graph(ctx: RunCtx):
    g = StateGraph(RunState)
    for name, label, agent in AGENTS:
        g.add_node(name, _node(ctx, name, label, agent))
    g.add_edge(START, "triage")
    g.add_edge("triage", "pathfinder")
    g.add_edge("pathfinder", "fixer")
    g.add_edge("fixer", "reporter")
    g.add_edge("reporter", END)
    # The checkpointer saves the state after each node, keyed by thread_id =
    # run_id: possible only because the state is plain data.
    return g.compile(checkpointer=InMemorySaver())


def _node(ctx: RunCtx, name: str, label: str, agent):
    async def run(state: RunState) -> dict:
        t = time.perf_counter()
        oid, summary = await agent(ctx, state)
        secs = time.perf_counter() - t
        return {
            "outputs": {label: oid},
            "summaries": {label: summary},
            "budget": ctx.budget.snapshot(),
            "log": [f"{name}: {summary} ({secs:.1f} s)"],
        }

    run.__name__ = name
    return run


async def run_agents(
    org: str,
    scan: str = "v1",
    *,
    llm: ChatModel,
    as_of: int | None = None,
    max_llm_calls: int | None = None,
    max_tool_calls: int | None = None,
    transport: str = "memory",
    repo: MemoryRepo | None = None,
    graph: str | None = None,
) -> dict:
    """Run the four agents on one scan; everything is written under a new run id."""
    s = get_settings()
    graph = graph or s.scan_graph(org, scan)
    repo = repo or MemoryRepo()
    info = repo.scan_info(graph)
    if as_of is None:
        if not info:
            raise RuntimeError(f"{graph} has no Scan node: re-run `make seed`, or pass as_of")
        as_of = info["ts"]
    budget = Budget(
        max_llm_calls=max_llm_calls or s.agent_max_llm_calls,
        max_tool_calls=max_tool_calls or s.agent_max_tool_calls,
    )
    run_id = repo.start_agent_run(
        graph, kind="agent_triage", scan=scan, as_of=as_of, budget=budget.snapshot()
    )
    t0 = time.perf_counter()
    status, ctx, final = "failed", None, {}
    try:
        async with McpToolbox.open(transport) as toolbox:
            ctx = RunCtx(
                graph=graph,
                run_id=run_id,
                as_of=as_of,
                llm=llm,
                toolbox=toolbox,
                repo=repo,
                budget=budget,
            )
            app = build_graph(ctx)
            final = await app.ainvoke(
                {
                    "org": org,
                    "scan": scan,
                    "graph": graph,
                    "run_id": run_id,
                    "as_of": as_of,
                    "scan_info": info or {},
                    "budget": budget.snapshot(),
                    "outputs": {},
                    "summaries": {},
                    "log": [],
                },
                config={"configurable": {"thread_id": run_id}},
            )
        status = "budget_exhausted" if budget.exhausted else "complete"
    finally:
        stats = {**(ctx.stats() if ctx else budget.snapshot())}
        stats["wall_ms"] = round((time.perf_counter() - t0) * 1000)
        models = [f"{k}:{v}" for k, v in sorted((ctx.models if ctx else {}).items())]
        repo.finish_run(graph, run_id, status=status, stats=stats, models=models)
    return {
        "run_id": run_id,
        "graph": graph,
        "as_of": as_of,
        "status": status,
        "stats": stats,
        "models": models,
        "outputs": final.get("outputs", {}),
        "log": final.get("log", []),
    }
