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
from reachable_graph.tools import scan_graph_name

from .agents import fixer_agent, pathfinder_agent, reporter_agent, triage_agent
from .llm import ChatModel
from .mcp_tools import McpToolbox
from .runtime import Budget, RunCtx
from .sentinel import previous_scan, sentinel_check

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
    prev_scan: str | None  # the scan before this one ("v1" for a v2 run): Sentinel runs
    carry_from: str | None  # graph to carry memory from (None: a cold start)
    budget: dict  # caps + usage, refreshed after every agent
    outputs: Annotated[dict[str, str], _merge]  # output label -> node id (the handoffs)
    summaries: Annotated[dict[str, str], _merge]
    log: Annotated[list[str], operator.add]


def build_graph(ctx: RunCtx):
    g = StateGraph(RunState)
    for name, label, agent in AGENTS:
        g.add_node(name, _node(ctx, name, label, agent))
    g.add_node("sentinel", _node(ctx, "sentinel", "Drift", _sentinel))
    # A run over a NEW scan starts with the Sentinel (carry memory, flag arrivals,
    # diff the path sets); a run over the first scan starts at Triage.
    g.add_conditional_edges(
        START, lambda st: "sentinel" if st.get("prev_scan") else "triage", ["sentinel", "triage"]
    )
    g.add_edge("sentinel", "triage")
    g.add_edge("triage", "pathfinder")
    g.add_edge("pathfinder", "fixer")
    g.add_edge("fixer", "reporter")
    g.add_edge("reporter", END)
    # The checkpointer saves the state after each node, keyed by thread_id =
    # run_id: possible only because the state is plain data.
    return g.compile(checkpointer=InMemorySaver())


async def _sentinel(ctx: RunCtx, state: RunState) -> tuple[str, str]:
    oid, payload = await sentinel_check(
        ctx, prev_scan=state["prev_scan"], scan=state["scan"], carry_from=state.get("carry_from")
    )
    return oid, (ctx.repo.read_output(ctx.graph, ctx.run_id, "Drift") or {}).get("summary", "")


def _node(ctx: RunCtx, name: str, label: str, agent):
    async def run(state: RunState) -> dict:
        t = time.perf_counter()
        ctx.record_agent(name)
        oid, summary = await agent(ctx, state)
        ctx.record_output(name, label, oid, summary)
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
    run_id: str | None = None,
    carry_memory: bool = True,
) -> dict:
    """Run the agents on one scan; everything is written under one run id.

    On a scan with an earlier scan loaded (v2), the Sentinel runs first. With
    carry_memory (the default) it brings the org's memory over from the earlier
    scan's graph; carry_memory=False is a cold start (memory lift's baseline).
    run_id: a Run the caller already created (the API returns it before the run
    starts); by default a new one."""
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
        graph, kind="agent_triage", scan=scan, as_of=as_of, budget=budget.snapshot(), run_id=run_id
    )
    prev = previous_scan(graph, scan, repo.allowed)
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
                    "prev_scan": prev,
                    "carry_from": scan_graph_name(graph, prev) if prev and carry_memory else None,
                    "budget": budget.snapshot(),
                    "outputs": {},
                    "summaries": {},
                    "log": [],
                },
                config={"configurable": {"thread_id": run_id}},
            )
        # complete: every agent's model answered. degraded: some LLM call failed on
        # every deployment, so an agent finalised from its tool results alone.
        status = (
            "budget_exhausted"
            if budget.exhausted
            else "degraded"
            if ctx.llm_failures
            else "complete"
        )
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
