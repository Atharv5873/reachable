"""Run health: a gate may only say PASS about a run that really ran (S8).

S7's trap: Gate B was re-run during an API outage. Every model call failed, the
run finished `degraded` with 0 LLM tokens, and the gate still said PASS, because
the run's deterministic calls alone produce the right fix set. The verdict was
true of the tools and said nothing about the agents. So every gate (and the eval)
first asks whether each run it judges is healthy:

  * the run's status is "complete" (not degraded / budget_exhausted / failed);
  * it has a trace (steps were recorded);
  * when a model was expected: LLM tokens > 0 and at least one model call answered;
  * no tool answered "unavailable" (the graph or a service was down), and none of
    the calls the RUN itself makes (by="run", never the model's choice) failed.

A model's own bad tool call (a hallucinated edge key) is not ill health: the
tool refused it and the run went on.
"""

from __future__ import annotations

UNAVAILABLE_MARKERS = ("unavailable", "connection refused", "timed out", "offline")


def run_health(
    status: str | None, stats: dict, steps: list[dict], *, expect_llm: bool = True
) -> list[str]:
    """Why this run cannot back a PASS; [] when it is healthy."""
    why: list[str] = []
    if status != "complete":
        why.append(f"run status is {status!r}, not 'complete'")
    if not steps:
        why.append("empty trace (no steps recorded)")
    if expect_llm:
        if not ((stats.get("tokens_in") or 0) + (stats.get("tokens_out") or 0)):
            why.append("0 LLM tokens although the run needs a model")
        if not any(s.get("kind") == "llm" and s.get("ok", True) is not False for s in steps):
            why.append("no model call answered")
        if stats.get("llm_failures"):
            why.append(f"{stats['llm_failures']} model call(s) failed on every deployment")
    tools = [s for s in steps if s.get("kind") == "tool" and s.get("ok") is False]
    down = [s for s in tools if _unavailable(s.get("error"))]
    if down:
        why.append(
            f"{len(down)} tool call(s) unavailable: {down[0].get('tool')}: "
            f"{(down[0].get('error') or '')[:120]}"
        )
    run_made = [s for s in tools if s.get("by") == "run" and s not in down]
    if run_made:
        why.append(f"{len(run_made)} run-made tool call(s) failed: {run_made[0].get('tool')}")
    return why


def _unavailable(error: str | None) -> bool:
    low = (error or "").lower()
    return any(m in low for m in UNAVAILABLE_MARKERS)


def gate_verdict(criteria: dict[str, bool], health: dict[str, list[str]]) -> dict:
    """PASS needs every criterion AND every judged run healthy. An unhealthy run
    makes the gate DEGRADED (a failure), whatever the criteria say."""
    degraded = {name: why for name, why in health.items() if why}
    ok = all(criteria.values())
    verdict = "DEGRADED" if degraded else "PASS" if ok else "FAIL"
    return {
        **criteria,
        "healthy": not degraded,
        "degraded": degraded,
        "verdict": verdict,
        "pass": verdict == "PASS",
    }


def ranking_health(
    meta: dict, tool_log: list[dict], *, expect_llm: bool, graph_off: bool = False
) -> list[str]:
    """run_health for one eval run (a Ranking's meta + tool log). The ablation's
    graph-off run is SUPPOSED to see every graph tool unavailable: for it, only
    the model side is checked."""
    status = "degraded" if meta.get("llm_failures") else "complete"
    steps = [
        {**t, "kind": "tool"} for t in tool_log if not (graph_off and _unavailable(t.get("error")))
    ]
    if expect_llm:
        steps += [{"kind": "llm"}] * int(meta.get("llm_calls") or 0)
    elif not steps:
        steps = [{"kind": "rank"}]  # a deterministic ordering has no trace to speak of
    return run_health(status, meta, steps, expect_llm=expect_llm)
