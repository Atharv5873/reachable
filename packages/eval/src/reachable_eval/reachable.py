"""reachable: the same LLM loop with the FalkorDB tools, over MCP.

The tools are the product's read-only analysis tools, exactly as the MCP server
advertises them, and every call goes over MCP (the in-memory transport, as the
agents use). Left out on purpose, so the comparison is about the context layer
for "what do I fix first" and nothing else:
  * memory (triage_memory, playbooks) and the company layer (owners,
    decision_trail, company_query): no baseline gets the analogous Postgres
    tables either, and the seeded memory holds verdicts on the decoys;
  * scan_findings' `previously_decided` (the same seeded memory) is stripped;
  * run_cypher_readonly (the escape hatch) and exposure_drift (a scan diff).

graph_off=True is the ablation: the SAME toolbox, the same schemas shown to the
model, but every call answers "unavailable". Nothing else changes.

S8: after the model answers, a ranking step (graph_finalise) orders the head by
path-criticality and takes min_cut's verified fix set, as the product's run does.
It goes through the same toolbox, so with the graph off it gets nothing and the
model's answer stands: the ablation still measures the graph alone.
"""

from __future__ import annotations

import re
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from reachable_agents.mcp_tools import CallOutcome, McpToolbox

from .agent import MAX_RANKED, LLMPrioritiser
from .store import ScanData

GRAPH_TOOLS = (
    "scan_findings",
    "exposure_surface",
    "attack_paths",
    "min_cut",
    "blast_radius",
    "choke_points",
    "why_step",
    "simulate_fix",
    "vuln_intel",
)
UNAVAILABLE = "unavailable: the graph store (FalkorDB) is offline for this run"
MEMORY_FIELDS = {"scan_findings": ("previously_decided",)}
_MEMORY_SUMMARY = re.compile(r"\d+ carry an earlier decision \(check triage_memory\)\. ?")


class GraphToolbox:
    """McpToolbox, minus memory fields; or, graph-off, every call refused."""

    def __init__(self, box: McpToolbox, *, graph_off: bool = False) -> None:
        self.box, self.graph_off = box, graph_off
        self.meta = None

    def takes(self, tool: str, arg: str) -> bool:
        return self.box.takes(tool, arg)

    def llm_schemas(self, names, *, brief: bool = True) -> list[dict]:
        return self.box.llm_schemas(names, brief=brief)

    async def call(self, name: str, args: dict) -> CallOutcome:
        if self.graph_off:
            return CallOutcome(False, None, UNAVAILABLE, 0.0)
        out = await self.box.call(name, args)
        if out.ok and out.result and name in MEMORY_FIELDS:
            data = dict(out.result.get("data") or {})
            for k in MEMORY_FIELDS[name]:
                data.pop(k, None)
            summary = _MEMORY_SUMMARY.sub("", str(out.result.get("summary") or ""))
            out.result = {**out.result, "data": data, "summary": summary}
        return out


def graph_toolbox_factory(*, graph_off: bool = False):
    @asynccontextmanager
    async def make(data: ScanData):
        async with McpToolbox.open("memory") as box:
            yield GraphToolbox(box, graph_off=graph_off)

    return make


@dataclass
class Finalised:
    head: list[str]
    fix_set: list[str] | None
    why: dict[str, str] = field(default_factory=dict)
    meta: dict = field(default_factory=dict)
    log: list[dict] = field(default_factory=list)  # the run's own tool calls (by="run")


class RunCalls:
    """Tool calls the RUN makes (by="run"), not the model: through the same
    toolbox, outside the model's budget (which stays identical for every LLM
    prioritiser), each one logged."""

    def __init__(self, box, graph: str) -> None:
        self.box, self.graph, self.log = box, graph, []

    async def __call__(self, name: str, args: dict) -> dict | None:
        out = await self.box.call(name, {"org": self.graph, **args})
        self.log.append(
            {
                "tool": name,
                "input": args,
                "ok": out.ok,
                "cached": False,
                "by": "run",
                "error": (out.error or "")[:200] or None,
            }
        )
        return ((out.result or {}).get("data") or {}) if out.ok else None


async def graph_order(call: RunCalls, head: list[str]) -> tuple[list[str], dict, dict]:
    """scan_findings ranks every finding on a crown-jewel path by its
    path-criticality (criticality.py): those first, in that order, then the
    model's other picks in its order. The head is as full as the graph allows
    (S7: some runs named 7 findings and stopped)."""
    sf = await call("scan_findings", {"view": "ranked", "limit": MAX_RANKED})
    if sf is None:
        return list(head), {}, {"ranking": "model"}
    rows = [r for r in sf.get("findings", []) if r.get("crown_paths")]
    crit = [r["finding"] for r in rows]
    new_head = crit + [f for f in head if f not in crit]
    why = {
        r["finding"]: f"On {r['crown_paths']} crown-jewel path(s) (path-criticality "
        f"{r['criticality']}): ranked by the graph."
        for r in rows
    }
    return new_head, why, {"ranking": "graph", "graph_ranked": len(crit)}


async def min_cut_fix_set(call: RunCalls, fix_set: list[str]) -> tuple[list[str] | None, dict]:
    """The fix plan is min_cut's set: the fewest fixes, or the cheapest cut when it
    has as few. simulate_fix proves it. Only if a crown jewel stayed reachable
    (it should not: the max-flow/min-cut self-check runs inside min_cut) would the
    model's own tokens be added and the union proved again. S7: the model wrote
    one fix per path (6-9) instead of min_cut's 5 on some scans."""
    cuts = {m: await call("min_cut", {"mode": m}) for m in ("fewest", "cheapest")}
    few, cheap = cuts["fewest"], cuts["cheapest"]
    if not (few and few.get("fix_tokens")):
        return None, {"fix_set_source": "model"}
    chosen = "fewest"
    if (
        cheap
        and len(cheap.get("fix_tokens") or []) == len(few["fix_tokens"])
        and cheap["total_effort"] < few["total_effort"]
    ):
        chosen = "cheapest"
    tokens = list(cuts[chosen]["fix_tokens"])
    sim = await call("simulate_fix", {"fix_tokens": tokens})
    verified = bool(sim and sim.get("all_crown_jewels_disconnected"))
    expanded = False
    extra = [t for t in fix_set if t not in tokens]
    if sim is not None and not verified and extra:  # min_cut left a crown jewel reachable
        sim = await call("simulate_fix", {"fix_tokens": tokens + extra})
        if sim and sim.get("all_crown_jewels_disconnected"):
            tokens, verified, expanded = tokens + extra, True, True
    return tokens, {
        "fix_set_source": f"min_cut:{chosen}",
        "fix_set_verified": verified,
        "fix_set_expanded": expanded,
    }


async def graph_finalise(box, data: ScanData, head: list[str], fix_set: list[str]) -> Finalised:
    """The ranking step after the model answers (S8): what the product's run does
    deterministically, here through the SAME toolbox the model had. Label-free:
    every input is a graph tool's answer at runtime. Graph off (the ablation),
    every call answers "unavailable" and the model's answer is kept unchanged."""
    call = RunCalls(box, data.ref.graph)
    new_head, why, meta = await graph_order(call, head)
    new_fix, fix_meta = await min_cut_fix_set(call, fix_set)
    meta.update(fix_meta, run_tool_calls=len(call.log))
    return Finalised(new_head, new_fix, why, meta, call.log)


def reachable(llm_factory=None, *, graph_off: bool = False) -> LLMPrioritiser:
    kw = {"llm_factory": llm_factory} if llm_factory else {}
    name = "reachable_graph_off" if graph_off else "reachable"
    return LLMPrioritiser(
        name,
        graph_toolbox_factory(graph_off=graph_off),
        GRAPH_TOOLS,
        finalise=graph_finalise,
        **kw,
    )
