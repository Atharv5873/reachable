"""S8: a gate may only say PASS about a healthy run (no model, no database)."""

from __future__ import annotations

from reachable_eval.health import gate_verdict, ranking_health, run_health

LLM_OK = {"kind": "llm", "ok": True}
TOOL_OK = {"kind": "tool", "tool": "min_cut", "ok": True, "by": "run"}
HEALTHY_STATS = {"tokens_in": 21_000, "tokens_out": 900, "llm_failures": 0}


def test_a_healthy_run_passes():
    assert run_health("complete", HEALTHY_STATS, [LLM_OK, TOOL_OK]) == []
    v = gate_verdict({"criterion": True}, {"cold": [], "warm": []})
    assert v["verdict"] == "PASS" and v["pass"] and v["healthy"]


def test_a_zero_token_run_is_degraded_not_pass():
    """The S7 outage: every model call failed, the run's deterministic calls still
    produced the right fix set, and the gate said PASS. Now it says DEGRADED."""
    stats = {"tokens_in": 0, "tokens_out": 0, "llm_failures": 7}
    steps = [{"kind": "llm", "ok": False}, TOOL_OK]
    why = run_health("degraded", stats, steps)
    assert any("0 LLM tokens" in w for w in why)
    assert any("status" in w for w in why) and any("no model call" in w for w in why)
    # ...even with every correctness criterion true, and the status somehow "complete"
    assert run_health("complete", {"tokens_in": 0, "tokens_out": 0}, [TOOL_OK])
    v = gate_verdict(
        {"warm_does_strictly_less_work": True, "both_fix_sets_correct": True},
        {"v1": [], "cold": why, "warm": []},
    )
    assert v["verdict"] == "DEGRADED" and v["pass"] is False and not v["healthy"]
    assert v["degraded"] == {"cold": why}


def test_empty_trace_and_tool_outage_are_degraded():
    assert "empty trace" in " ".join(run_health("complete", HEALTHY_STATS, []))
    down = {"kind": "tool", "tool": "attack_paths", "ok": False, "error": "unavailable: offline"}
    assert run_health("complete", HEALTHY_STATS, [LLM_OK, down])
    failed_run_call = {**TOOL_OK, "ok": False, "error": "boom"}
    assert run_health("complete", HEALTHY_STATS, [LLM_OK, failed_run_call])
    # a model's own bad call (a hallucinated edge key) is not ill health
    bad_arg = {"kind": "tool", "tool": "why_step", "ok": False, "error": "no ATTACK_STEP with key"}
    assert run_health("complete", HEALTHY_STATS, [LLM_OK, bad_arg]) == []


def test_eval_runs_degraded_unless_the_graph_off_ablation():
    meta = {"llm_calls": 2, "tokens_in": 12_000, "tokens_out": 600, "llm_failures": 0}
    down = [{"tool": "scan_findings", "ok": False, "error": "unavailable: FalkorDB is offline"}]
    assert ranking_health(meta, [], expect_llm=True) == []
    assert ranking_health(meta, down, expect_llm=True)  # the graph agent lost its graph
    assert ranking_health(meta, down, expect_llm=True, graph_off=True) == []  # by design
    zero = {**meta, "tokens_in": 0, "tokens_out": 0}
    assert ranking_health(zero, [], expect_llm=True, graph_off=True)  # 0 tokens: never OK
    assert ranking_health({"llm_calls": 0}, [], expect_llm=False) == []  # severity_sort
