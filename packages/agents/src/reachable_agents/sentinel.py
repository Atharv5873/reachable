"""Sentinel: what a NEW scan changes, with no LLM.

When a rescan lands, re-triaging all ~7k findings from scratch is wasted work:
almost nothing an attacker can do has changed. The Sentinel does incremental
recompute instead, in this order:

  0. carry memory   the org's memory (verdicts, risk acceptances, patterns,
                    playbooks, earlier runs' outputs) follows it into the new
                    scan's graph (MemoryRepo.carry_over; idempotent).
  1. arrivals       which open findings arrived / left (exposure_drift with
                    include_paths=false: two id reads, NO path search).
  2. on arrival     semantic memory: does any learned Pattern reach an arrived
                    finding (same asset, same image/CPE, same CVE)? Those are
                    flagged BEFORE any path is computed.
  3. drift          exposure_drift: the Internet -> crown-jewel path sets of both
                    scans, diffed (new / closed / cost-changed).
  4. alert          an Alert ONLY when new_crown_path is true: a brand-new path
                    to a crown jewel. Closed paths and cost changes never alert.

Every step goes through the run's trace (tool steps over MCP, by="run"; memory
steps), so the SSE stream shows the Sentinel like any agent. Its output is a
`Drift` node on the run; Triage is BUILT_ON it.
"""

from __future__ import annotations

import time

from reachable_core.settings import get_settings
from reachable_graph.memory import MemoryRepo
from reachable_graph.tools import label_of, scan_graph_name

from .loop import day
from .mcp_tools import McpToolbox
from .runtime import Budget, RunCtx


async def sentinel_check(
    ctx: RunCtx, *, prev_scan: str, scan: str, carry_from: str | None
) -> tuple[str, dict]:
    """Run the Sentinel inside a run; returns (Drift output id, payload)."""
    carried = None
    if carry_from:
        t = time.perf_counter()
        carried = ctx.repo.carry_over(carry_from, ctx.graph)
        ctx.record_memory(
            "sentinel",
            "carry_over",
            {"from": carry_from, "to": ctx.graph, "copied": carried},
            ms=round((time.perf_counter() - t) * 1000, 1),
        )

    base = {"from_scan": prev_scan, "to_scan": scan}
    arr, _ = await ctx.preload("sentinel", "exposure_drift", {**base, "include_paths": False})
    arrived = ((arr or {}).get("data") or {}).get("arrived_findings", [])

    flags: dict[str, list[dict]] = {}
    if arrived:  # semantic memory, before any path search
        tm, _ = await ctx.preload("sentinel", "triage_memory", {"finding_ids": arrived[:200]})
        data = (tm or {}).get("data") or {}
        pats = {p["id"]: p for p in data.get("patterns", [])}
        for f in data.get("findings", []):
            if f["patterns"]:
                flags[f["finding"]] = [
                    {
                        "pattern": pid,
                        "kind": pats[pid]["kind"],
                        "description": pats[pid]["description"],
                    }
                    for pid in f["patterns"]
                    if pid in pats
                ]
        if flags:
            ctx.record_memory(
                "sentinel",
                "pattern_flags",
                {"arrived": len(arrived), "flagged": sorted(flags)},
            )

    dr, _ = await ctx.preload("sentinel", "exposure_drift", base)
    d = (dr or {}).get("data") or {}

    def findings_on(paths: list[dict]) -> list[str]:
        return sorted(
            {
                s["fix_token"]
                for p in paths
                for s in p["steps"]
                if label_of(s["fix_token"]) == "Finding"
            }
        )

    def compact(p: dict) -> dict:
        return {
            "target": p["target"],
            "likelihood": round(p["likelihood"], 4),
            "hops": [n["name"] for n in p["nodes"]],
            "nodes": [n["id"] for n in p["nodes"]],
            "steps": [s["key"] for s in p["steps"]],
            **{k: p[k] for k in ("new_nodes", "new_steps", "fixed_findings") if k in p},
        }

    new_paths = d.get("new_paths", [])
    payload = {
        "from": d.get("from"),
        "to": d.get("to"),
        "carried_memory": carried,
        "arrived": len(arrived),
        "left": len(d.get("left_findings", [])),
        "flagged_on_arrival": flags,
        "new_crown_path": bool(d.get("new_crown_path")),
        "new_paths": [compact(p) for p in new_paths],
        "closed_paths": [compact(p) for p in d.get("closed_paths", [])],
        "cost_changed": [compact(p) for p in d.get("cost_changed", [])],
        "unchanged": d.get("unchanged", 0),
        "new_path_findings": findings_on(new_paths),
        "changed_path_findings": findings_on(d.get("cost_changed", [])),
        "closed_path_findings": findings_on(d.get("closed_paths", [])),
        "alert": None,
    }
    if payload["new_crown_path"]:
        hops = "; ".join(" -> ".join(p["hops"]) for p in payload["new_paths"])
        payload["alert"] = ctx.repo.raise_alert(
            ctx.graph,
            ctx.run_id,
            kind="new_crown_path",
            ts=ctx.as_of,
            from_scan=prev_scan,
            to_scan=scan,
            summary=f"New path to a crown jewel since scan {prev_scan}: {hops}",
            payload={k: payload[k] for k in ("new_paths", "new_path_findings")},
            findings=payload["new_path_findings"],
            assets=[
                n
                for p in new_paths
                for n in (x["id"] for x in p["nodes"])
                if label_of(n) == "Asset"
            ],
        )
    summary = (
        f"Scan {prev_scan} -> {scan} ({day(ctx.as_of)}): {payload['arrived']} finding(s) arrived, "
        f"{payload['left']} left; {len(flags)} flagged on arrival by a learned pattern; crown "
        f"paths: {len(payload['new_paths'])} new, {len(payload['closed_paths'])} closed, "
        f"{len(payload['cost_changed'])} cost-changed, {payload['unchanged']} unchanged. "
        + (f"ALERT {payload['alert']}: new crown-jewel path." if payload["alert"] else "No alert.")
    )
    oid = ctx.repo.write_output(
        ctx.graph,
        ctx.run_id,
        "Drift",
        agent="sentinel",
        payload=payload,
        summary=summary,
        as_of=ctx.as_of,
        cites=sorted(set(payload["new_path_findings"]) | set(flags)),
    )
    return oid, payload


def previous_scan(graph: str, scan: str, allowed: set[str]) -> str | None:
    """The scan before this one, if its graph is loaded (v2 -> v1)."""
    if scan != "v2":
        return None
    prev = scan_graph_name(graph, "v1")
    return "v1" if prev in allowed else None


async def run_sentinel(
    org: str,
    scan: str = "v2",
    *,
    repo: MemoryRepo | None = None,
    graph: str | None = None,
    carry: bool = True,
    transport: str = "memory",
) -> dict:
    """`make drift`: the Sentinel on its own, as a Run (kind="sentinel") on the new
    scan's graph, with its trace, its Drift output and any Alert."""
    s = get_settings()
    graph = graph or s.scan_graph(org, scan)
    repo = repo or MemoryRepo()
    prev = previous_scan(graph, scan, repo.allowed)
    if prev is None:
        raise RuntimeError(f"{graph}: no earlier scan loaded to diff against")
    info = repo.scan_info(graph)
    if not info:
        raise RuntimeError(f"{graph} has no Scan node: re-run `make seed`")
    budget = Budget(max_llm_calls=0, max_tool_calls=10)
    run_id = repo.start_agent_run(
        graph, kind="sentinel", scan=scan, as_of=info["ts"], budget=budget.snapshot()
    )
    t0, status, ctx, payload = time.perf_counter(), "failed", None, {}
    try:
        async with McpToolbox.open(transport) as toolbox:
            ctx = RunCtx(
                graph=graph,
                run_id=run_id,
                as_of=info["ts"],
                llm=None,
                toolbox=toolbox,
                repo=repo,
                budget=budget,
            )
            ctx.record_agent("sentinel")
            oid, payload = await sentinel_check(
                ctx,
                prev_scan=prev,
                scan=scan,
                carry_from=scan_graph_name(graph, prev) if carry else None,
            )
            ctx.record_output("sentinel", "Drift", oid, "drift checked")
        status = "complete"
    finally:
        stats = {**(ctx.stats() if ctx else budget.snapshot())}
        stats["wall_ms"] = round((time.perf_counter() - t0) * 1000)
        repo.finish_run(graph, run_id, status=status, stats=stats, models=[])
    return {"run_id": run_id, "graph": graph, "status": status, "drift": payload, "stats": stats}
