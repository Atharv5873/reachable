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
"""

from __future__ import annotations

import re
from contextlib import asynccontextmanager

from reachable_agents.mcp_tools import CallOutcome, McpToolbox

from .agent import LLMPrioritiser
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


def reachable(llm_factory=None, *, graph_off: bool = False) -> LLMPrioritiser:
    kw = {"llm_factory": llm_factory} if llm_factory else {}
    name = "reachable_graph_off" if graph_off else "reachable"
    return LLMPrioritiser(name, graph_toolbox_factory(graph_off=graph_off), GRAPH_TOOLS, **kw)
