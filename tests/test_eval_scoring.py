"""S7 scoring and the two deterministic prioritisers, against hand calculations.

No database, no model: a six-finding fixture whose metrics are worked out by
hand in the comments, a hand-built ScanData for severity_sort / smart_score,
and the shared LLM loop driven by a scripted model over a fake toolbox.
"""

from __future__ import annotations

import asyncio
import json
import math
import random
from contextlib import asynccontextmanager

import pytest

from reachable_agents.llm import LLMReply, ToolCall
from reachable_eval.agent import LLMPrioritiser, LocalTool, LocalToolbox, build_context
from reachable_eval.base import SeveritySort, SmartScore, complete, severity_order, smart_score
from reachable_eval.scoring import (
    Truth,
    fix_efficiency,
    ideal_order,
    ndcg_at,
    path_recall_at,
    precision_at,
    score_order,
    truth_from_labels,
)
from reachable_eval.store import FindingRow, ScanData, ScanRef

# Fixture: relevance a=1.0, b=0.5, c=0.5, everything else 0.
#   P1 = {a, b} (+ step:1)   P2 = {c} (+ step:1)   P3 = {a} (+ step:2)
#   decoys: d (severity), e (dead_end); oracle min cut = {step:1, step:2}.
TRUTH = Truth(
    priority={"a": 1.0, "b": 0.5, "c": 0.5, "d": 0.0, "e": 0.0, "x": 0.0},
    paths=[
        {"name": "P1", "difficulty": "easy", "fixes": {"a", "b", "step:1"}, "findings": {"a", "b"}},
        {"name": "P2", "difficulty": "hard", "fixes": {"c", "step:1"}, "findings": {"c"}},
        {"name": "P3", "difficulty": "hard", "fixes": {"a", "step:2"}, "findings": {"a"}},
    ],
    decoys={"d": "severity", "e": "dead_end"},
    min_cut=["step:1", "step:2"],
    oracle_path_count=3,
)
ORDER = ["d", "a", "e", "c", "b", "x"]
L2 = math.log2


def test_ndcg_matches_hand_calculation():
    # DCG@3 = 0/log2(2) + 1/log2(3) + 0/log2(4) = 0.63093
    # IDCG@3 = 1/log2(2) + 0.5/log2(3) + 0.5/log2(4) = 1.56546   -> 0.40303
    assert ndcg_at(ORDER, TRUTH.priority, 3) == pytest.approx(
        (1 / L2(3)) / (1 + 0.5 / L2(3) + 0.5 / L2(4))
    )
    assert ndcg_at(ORDER, TRUTH.priority, 3) == pytest.approx(0.40303, abs=1e-5)
    # DCG@5 adds c at 4 (0.5/log2(5)) and b at 5 (0.5/log2(6)) = 1.03970; IDCG@5 = IDCG@3 -> 0.66414
    assert ndcg_at(ORDER, TRUTH.priority, 5) == pytest.approx(0.66414, abs=1e-5)
    assert ndcg_at(ideal_order(TRUTH), TRUTH.priority, 3) == pytest.approx(1.0)
    assert ndcg_at(["x", "d", "e"], TRUTH.priority, 3) == 0.0


def test_precision_recall_and_decoys_match_hand_calculation():
    assert precision_at(ORDER, TRUTH.priority, 3) == pytest.approx(1 / 3)  # only a
    assert precision_at(ORDER, TRUTH.priority, 5) == pytest.approx(3 / 5)  # a, c, b
    assert path_recall_at(ORDER, TRUTH.paths, 3) == pytest.approx(2 / 3)  # a covers P1, P3
    assert path_recall_at(ORDER, TRUTH.paths, 4) == pytest.approx(1.0)  # + c covers P2
    s = score_order(ORDER, TRUTH)
    assert s["decoy_rate@5"] == pytest.approx(1.0)  # d and e both in the top 5
    assert s["decoys_in_top10"] == ["severity:d", "dead_end:e"]


def test_fix_efficiency_matches_hand_calculation():
    f = fix_efficiency(["a"], TRUTH)  # a is on P1 and P3
    assert (f["paths_cut"], f["paths_per_fix"], f["cuts_every_path"]) == (2, 2.0, False)
    assert f["oracle_paths_per_fix"] == pytest.approx(1.5)  # 3 paths / 2 fixes
    assert fix_efficiency(TRUTH.min_cut, TRUTH)["cuts_every_path"]
    # No fix set of its own: the top |min cut| = 2 of the order, {d, a} -> P1, P3.
    s = score_order(ORDER, TRUTH)["fix"]
    assert (s["source"], s["size"], s["paths_cut"]) == ("derived", 2, 2)


def test_labels_must_carry_hop_fix_tokens():
    labels = {
        "paths": [{"name": "p", "difficulty": "easy", "hops": [{"rule": "r", "fix": None}]}],
        "decoys": [],
        "finding_priority": {},
        "min_cut": [],
    }
    with pytest.raises(ValueError, match="make seed"):
        truth_from_labels(labels)


# ------------------------------------------------------- deterministic two
def row(fid, cvss, epss=0.0, kev=False, exposed=False, mitigated=None) -> FindingRow:
    return FindingRow(
        id=fid,
        cve="CVE-2024-0001",
        cvss=cvss,
        epss=epss,
        kev=kev,
        ransomware=False,
        av="NETWORK",
        asset=f"asset-{fid}",
        hostname=f"host-{fid}",
        kind="server",
        zone="z",
        env="prod",
        product="acme thing 1.0",
        internet_facing=exposed,
        mitigated_by=mitigated,
    )


ROWS = [
    row("f1", 9.8, epss=0.9, kev=True),  # internal critical KEV
    row("f2", 5.0, epss=0.3, exposed=True),  # exposed medium
    row("f3", 9.8, epss=0.9, kev=True, exposed=True, mitigated="waf"),  # blocked by a WAF
    row("f4", 9.8, epss=0.9, kev=True, exposed=True),  # exposed critical KEV
    row("f5", 7.5),
]


def scan(rows=ROWS) -> ScanData:
    return ScanData(ScanRef("org_x", "v1", "org_x"), list(rows), [], 10, 2)


def test_smart_score_formula_by_hand():
    # 0.30 * cvss/10 + 0.25 * epss + 0.20 * kev + 0.25 * exposed, x0.25 if mitigated
    assert smart_score(ROWS[0]) == pytest.approx(0.30 * 0.98 + 0.25 * 0.9 + 0.20)
    assert smart_score(ROWS[1]) == pytest.approx(0.30 * 0.5 + 0.25 * 0.3 + 0.25)
    assert smart_score(ROWS[3]) == pytest.approx(0.30 * 0.98 + 0.25 * 0.9 + 0.20 + 0.25)
    assert smart_score(ROWS[2]) == pytest.approx(smart_score(ROWS[3]) * 0.25)


def test_deterministic_prioritisers_rank_exactly_the_findings_and_repeat():
    d = scan()
    for p in (SeveritySort(), SmartScore()):
        a = asyncio.run(p.rank(d)).order
        b = asyncio.run(p.rank(d)).order
        shuffled = list(ROWS)
        random.Random(7).shuffle(shuffled)
        c = asyncio.run(p.rank(scan(shuffled))).order
        assert a == b == c, p.name  # same input, any input order -> same ranking
        assert sorted(a) == sorted(d.universe) and len(a) == len(set(a))
    assert asyncio.run(SmartScore().rank(d)).order[0] == "f4"
    assert asyncio.run(SeveritySort().rank(d)).order[-1] == "f2"


def test_complete_dedupes_drops_unknown_ids_and_appends_the_tail():
    d = scan()
    order, invalid = complete(["f5", "nope", "f5", "f2"], d, severity_order(d))
    assert order[:2] == ["f5", "f2"] and invalid == ["nope"]
    assert sorted(order) == sorted(d.universe)


# --------------------------------------------- the shared LLM loop (scripted)
class Scripted:
    """Turn 1: call `probe`. Turn 2: answer with ids, some valid, some not."""

    model = "fake/scripted"

    def __init__(self, answer: dict) -> None:
        self.answer, self.calls = answer, 0

    async def chat(self, messages, tools, *, agent, tool_choice="auto"):
        self.calls += 1
        if self.calls == 1:
            calls, content = [ToolCall("c1", "probe", {})], None
        else:
            calls, content = [], json.dumps(self.answer)
        return LLMReply(content, calls, "fake", self.model, 100, 10, 0.0, False)


def probe_toolbox():
    @asynccontextmanager
    async def make(data):
        async def probe(args):
            return {"summary": "ok", "data": {"fix": "step:real:token"}, "truncated": False}

        yield LocalToolbox([LocalTool("probe", "Probe.", {"type": "object"}, probe)])

    return make


def test_llm_prioritiser_returns_a_valid_ranking_and_grounds_fix_tokens():
    answer = {
        "ranked": [{"finding": "f2", "why": "w"}, {"finding": "ghost"}, {"finding": "f1"}],
        "fix_set": ["f2", "step:real:token", "step:made:up"],
        "reasoning": "r",
    }
    p = LLMPrioritiser(
        "probe_agent", probe_toolbox(), ("probe",), llm_factory=lambda s: Scripted(answer)
    )
    r = asyncio.run(p.rank(scan(), seed=1))
    assert r.order[:2] == ["f2", "f1"] and sorted(r.order) == sorted(scan().universe)
    assert r.invalid_ids == ["ghost"]
    assert r.fix_set == ["f2", "step:real:token"]  # a token no tool returned is dropped
    assert r.meta["fix_tokens_dropped"] == ["step:made:up"]
    assert r.meta["llm_calls"] == 2 and r.meta["tool_calls"] == 1


FORBIDDEN_KEYS = (
    "priority",
    "finding_priority",
    "on_crown_path",
    "crown_path",
    "best_likelihood",
    "attack_step",
    "fix_token",
    "labels",
    "decoy",
    "planted",
    "verdict",
    "acceptance",
)


def test_context_carries_no_label_path_or_memory_field():
    text = json.dumps(build_context(scan())).lower()
    for k in FORBIDDEN_KEYS:
        assert k not in text, k
