"""Gate B: memory lift. Does the agent do less work on a rescan when it remembers?

    uv run python evals/memory_lift.py --org org_a [--fake] [--keep]

The same agents, the same rescan (scan v2), the same correctness bar, two
memory states:

  cold  a fresh memory namespace: no earlier runs, no verdicts, no risk
        acceptances, no patterns; only the starter playbooks.
  warm  memory as it stands after the agents triaged scan v1: v1's run and its
        verdicts, the risk acceptances, the patterns it learned (carried into the
        v2 graph by the Sentinel, exactly as a normal v2 run does).

Honest by construction:
  * Fresh namespaced graphs (`lift_<org>` = v1, `lift_<org>_v2` = v2) are built
    from the generator with the same seed/scale as `make seed`, so the eval never
    reads or writes the demo graphs and starts from the same infrastructure.
  * Cold and warm run on the SAME v2 graph, one after the other; the memory is
    reset before each, so warm cannot benefit from cold's run (only from v1's).
  * Same model, same budgets, same prompts. The only difference is memory.
  * Correctness is re-checked outside the agents: simulate_fix on each final fix
    set must disconnect every crown jewel, and its size must equal the oracle's
    minimum cut for v2 (labels_v2.json).

Writes evals/results/memory_lift.md + .json (and runs/<run_id>.md/.json).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

import litellm

import reachable_mcp.server as mcp_server
from reachable_agents.cli import dump_run
from reachable_agents.fake import FakeLLM
from reachable_agents.graph import run_agents
from reachable_agents.llm import RouterLLM
from reachable_core.db import connect, drop_graph
from reachable_core.settings import REPO_ROOT, get_settings
from reachable_graph.derive import derive
from reachable_graph.memory import MemoryRepo
from reachable_graph.tools import GraphTools
from reachable_orggen.build import drift_org, generate_org
from reachable_orggen.generate import GenConfig
from reachable_orggen.load_falkordb import load_org

OUT = REPO_ROOT / "evals" / "results"


def build_namespace(db, org: str, seed: int, scale: float) -> tuple[str, str, dict]:
    """Fresh v1 + v2 graphs for this eval, straight from the generator."""
    v1, v2 = f"lift_{org}", f"lift_{org}_v2"
    cfg = GenConfig(scale=scale)
    ob = generate_org(org, seed, cfg)
    ob.dataset.org = v1
    load_org(db, ob.dataset)
    derive(db.select_graph(v1))
    ob2, new_path = drift_org(org, seed, cfg)
    ob2.dataset.org = v2
    load_org(db, ob2.dataset)
    derive(db.select_graph(v2))
    oracle = {
        "min_cut": ob2.ground_truth.min_cut,
        "min_cut_size": len(ob2.ground_truth.min_cut),
        "new_path": new_path.node_sequence(),
    }
    return v1, v2, oracle


def measure(repo: MemoryRepo, tools: GraphTools, graph: str, res: dict, oracle: dict) -> dict:
    """What the run did (work) and whether it got the right answer (correctness)."""
    dump = repo.agent_run(graph, res["run_id"])
    out = dump["outputs"]
    tp = out["Triage"]["payload"]
    fp = out["FixPlan"]["payload"]
    st = res["stats"]
    tokens = fp_tokens = sorted(fp["fix_tokens"])
    check = tools.simulate_fix(graph, fp_tokens).data if tokens else {}
    steps = dump["steps"]
    by_agent: dict[str, dict] = {}
    for s in steps:
        a = by_agent.setdefault(s.get("agent") or "?", {"llm": 0, "tool": 0, "tokens_in": 0})
        if s["kind"] == "llm" and s.get("ok", True) is not False:
            a["llm"] += 1
            a["tokens_in"] += s.get("tokens_in") or 0
        if s["kind"] == "tool" and s.get("ok") and not s.get("cached"):
            a["tool"] += 1
    cost = 0.0
    for m, n in (st.get("models") or {}).items():
        model = m.split("=", 1)[1]
        if model.startswith("fake"):
            continue
        share = n / max(1, st["llm_calls"])
        try:
            i, o = litellm.cost_per_token(
                model=model,
                prompt_tokens=int(st["tokens_in"] * share),
                completion_tokens=int(st["tokens_out"] * share),
            )
            cost += i + o
        except Exception:  # noqa: BLE001 - a model not in LiteLLM's price map
            pass
    drift = (out.get("Drift") or {}).get("payload") or {}
    return {
        "run_id": res["run_id"],
        "status": res["status"],
        "findings_investigated": len(tp["investigate"]),
        "investigated": [f["finding"] for f in tp["investigate"]],
        "skipped_by_memory": len(tp.get("carried", [])),
        "carried": {c["finding"]: c["decision"] for c in tp.get("carried", [])},
        "flagged_on_arrival": sorted(drift.get("flagged_on_arrival") or {}),
        "alert": drift.get("alert"),
        "llm_calls": st["llm_calls"],
        "tool_calls": st["tool_calls"],
        "cache_hits": st["cache_hits"],
        "tokens_in": st["tokens_in"],
        "tokens_out": st["tokens_out"],
        "wall_s": round(st["wall_ms"] / 1000, 1),
        "models": st.get("models"),
        "memory_events": st.get("memory"),
        "by_agent": by_agent,
        "usd": round(cost, 5),
        "fix_tokens": tokens,
        "chosen": fp["chosen"],
        "verified_in_run": fp["verified"],
        "eval_simulate_fix_disconnects": bool(check.get("all_crown_jewels_disconnected")),
        "fix_set_size": len(tokens),
        "oracle_min_cut_size": oracle["min_cut_size"],
        "correct": bool(check.get("all_crown_jewels_disconnected"))
        and len(tokens) == oracle["min_cut_size"],
    }


async def main_async(args) -> dict:
    db = connect()
    t0 = time.perf_counter()
    v1, v2, oracle = build_namespace(db, args.org, args.seed, args.scale)
    allowed = [v1, v2]
    tools = GraphTools(db, allowed_orgs=allowed)
    repo = MemoryRepo(db, allowed_orgs=allowed)
    mcp_server.use_tools(tools)  # the in-process MCP server reads the eval graphs
    llm = FakeLLM() if args.fake else RouterLLM()
    print(
        f"namespace {v1}, {v2} built in {time.perf_counter() - t0:.1f} s; model:",
        "fake" if args.fake else ", ".join(llm.describe()),
    )

    runs = {}
    # 1. The agents triage scan v1: this is the memory warm will have.
    print("v1 run (builds the memory warm starts from) ...")
    r1 = await run_agents(args.org, "v1", llm=llm, repo=repo, graph=v1)
    runs["v1"] = {"run_id": r1["run_id"], "status": r1["status"], "stats": r1["stats"]}
    dump_run(repo, v1, r1["run_id"], REPO_ROOT / "runs")

    # 2. cold: v2 with a fresh memory namespace (starter playbooks only).
    reset_cold = repo.reset_memory(v2)
    print("cold v2 run ...")
    rc = await run_agents(args.org, "v2", llm=llm, repo=repo, graph=v2, carry_memory=False)
    dump_run(repo, v2, rc["run_id"], REPO_ROOT / "runs")
    cold = measure(repo, tools, v2, rc, oracle)

    # 3. warm: the same v2 graph, memory reset again (cold's run must not help),
    #    then the Sentinel carries v1's memory in, as every normal v2 run does.
    reset_warm = repo.reset_memory(v2)
    print("warm v2 run ...")
    rw = await run_agents(args.org, "v2", llm=llm, repo=repo, graph=v2, carry_memory=True)
    dump_run(repo, v2, rw["run_id"], REPO_ROOT / "runs")
    warm = measure(repo, tools, v2, rw, oracle)

    if not args.keep:
        for g in allowed:
            drop_graph(db, g)
    result = {
        "org": args.org,
        "seed": args.seed,
        "scale": args.scale,
        "model": "fake" if args.fake else [f"{d.name}={d.model}" for d in llm.deps],
        "v1_run": runs["v1"],
        "resets": {"before_cold": reset_cold, "before_warm": reset_warm},
        "oracle": {k: oracle[k] for k in ("min_cut_size", "new_path")},
        "cold": cold,
        "warm": warm,
    }
    work_less = warm["findings_investigated"] < cold["findings_investigated"] or (
        warm["llm_calls"] + warm["tool_calls"] < cold["llm_calls"] + cold["tool_calls"]
    )
    no_more = (
        warm["findings_investigated"] <= cold["findings_investigated"]
        and warm["llm_calls"] <= cold["llm_calls"]
        and warm["tool_calls"] <= cold["tool_calls"]
    )
    result["gate_b"] = {
        "warm_does_strictly_less_work": work_less and no_more,
        "both_fix_sets_correct": cold["correct"] and warm["correct"],
    }
    result["gate_b"]["pass"] = all(result["gate_b"].values())
    return result


ROWS = (
    ("findings investigated", "findings_investigated"),
    ("skipped by memory (carried verdicts)", "skipped_by_memory"),
    ("flagged on arrival by a learned pattern", lambda r: len(r["flagged_on_arrival"])),
    ("LLM calls", "llm_calls"),
    ("tool calls (real MCP calls)", "tool_calls"),
    ("tokens in", "tokens_in"),
    ("tokens out", "tokens_out"),
    ("wall time (s)", "wall_s"),
    ("approx cost (USD, LiteLLM price map)", "usd"),
    ("fix set (size)", lambda r: f"{r['chosen']} ({r['fix_set_size']})"),
    ("simulate_fix disconnects every crown jewel", "eval_simulate_fix_disconnects"),
    ("fix-set size = oracle min cut", lambda r: r["fix_set_size"] == r["oracle_min_cut_size"]),
    ("run status", "status"),
)


def render(res: dict) -> str:
    c, w = res["cold"], res["warm"]

    def val(r, k):
        return k(r) if callable(k) else r[k]

    lines = [
        f"# Gate B: memory lift ({res['org']}, scan v2)",
        "",
        "Same agents, same rescan, same model and budgets; only the memory differs.",
        "",
        "* **cold**: fresh memory namespace: no earlier runs, verdicts, risk acceptances or "
        "patterns; starter playbooks only (and no carry-over from v1).",
        "* **warm**: memory after the agents triaged scan v1 "
        f"(run `{res['v1_run']['run_id']}`): its verdicts and routing, the risk acceptances, "
        "the patterns it learned; carried into the v2 graph by the Sentinel.",
        "",
        f"Model: {res['model']}. Graphs: fresh `lift_{res['org']}` / `lift_{res['org']}_v2` "
        f"(seed {res['seed']}, scale {res['scale']}), memory reset before each v2 run.",
        "",
        "| | cold | warm |",
        "|---|---:|---:|",
        *(f"| {name} | {val(c, k)} | {val(w, k)} |" for name, k in ROWS),
        "",
        f"**Gate B: {'PASS' if res['gate_b']['pass'] else 'FAIL'}**: "
        f"warm does strictly less work: {res['gate_b']['warm_does_strictly_less_work']}; "
        f"both fix sets correct: {res['gate_b']['both_fix_sets_correct']}.",
        "",
        "## Where the work went (per agent: LLM calls / tool calls / tokens in)",
        "",
        "| agent | cold | warm |",
        "|---|---:|---:|",
    ]
    for a in ("sentinel", "triage", "pathfinder", "fixer", "reporter"):
        x, y = c["by_agent"].get(a, {}), w["by_agent"].get(a, {})

        def fmt(z):
            return f"{z.get('llm', 0)} / {z.get('tool', 0)} / {z.get('tokens_in', 0)}"

        lines.append(f"| {a} | {fmt(x)} | {fmt(y)} |")
    lines += [
        "",
        "## What memory changed (warm)",
        "",
        f"* Episodic: {w['skipped_by_memory']} candidate(s) carried on a standing verdict, not "
        f"re-investigated: {w['carried']}.",
        f"* Semantic: flagged on arrival, before any path search: {w['flagged_on_arrival']}.",
        f"* Memory events in the trace: {w['memory_events']}.",
        f"* Investigated cold: {c['investigated']}",
        f"* Investigated warm: {w['investigated']}",
        f"* Fix sets: cold {c['fix_tokens']}; warm {w['fix_tokens']}.",
        f"* Alert (new crown path) raised in both: cold {c['alert']}, warm {w['alert']}.",
        "",
        f"Runs: cold `{c['run_id']}`, warm `{w['run_id']}` (runs/*.md).",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--org", default="org_a", choices=get_settings().orgs)
    p.add_argument("--seed", type=int, default=get_settings().seed)
    p.add_argument("--scale", type=float, default=1.0)
    p.add_argument("--fake", action="store_true", help="the deterministic stub model")
    p.add_argument("--keep", action="store_true", help="keep the lift_* graphs afterwards")
    p.add_argument("--out", type=Path, default=OUT)
    args = p.parse_args()
    logging.basicConfig(level=logging.WARNING)
    for name in ("LiteLLM", "LiteLLM Router", "LiteLLM Proxy"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    res = asyncio.run(main_async(args))
    args.out.mkdir(parents=True, exist_ok=True)
    stem = "memory_lift" + ("_fake" if args.fake else "")
    (args.out / f"{stem}.json").write_text(json.dumps(res, indent=1, default=str), "utf-8")
    md = render(res)
    (args.out / f"{stem}.md").write_text(md, "utf-8")
    print(md)
    sys.exit(0 if res["gate_b"]["pass"] else 1)


if __name__ == "__main__":
    main()
