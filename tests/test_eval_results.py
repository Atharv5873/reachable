"""S9: the committed eval tables regenerate from the raw outputs, and the structural
metrics survived the sensitivity tiers.

The tiers reweight priority only, so for reachable the structural metrics must be
what they were in S8 (path recall@10 100%, decoys@10 0%, the fix set cuts every
path at the oracle's 1.16 paths per fix), and no baseline may get anywhere near.
Needs the seeded labels (`make seed`); skips without them.
"""

from __future__ import annotations

import json

import pytest

from reachable_core.settings import get_settings
from reachable_eval import run as R
from reachable_eval.report import build_comparison

# reachable, S8 (3b541fc, 18 runs): the structural numbers S9 must not move.
S8_REACHABLE = {"path_recall@10": 1.0, "decoy_rate@10": 0.0, "fix_paths_per_fix": 1.16}
NOISE = 0.02

COMPARISON = R.RESULTS / "comparison.json"


def _labels_present() -> bool:
    d = get_settings().orgs_dir
    return all((d / o / "labels.json").exists() for o in ("org_a", "org_b", "org_c"))


pytestmark = pytest.mark.skipif(
    not (COMPARISON.exists() and _labels_present()), reason="needs make seed + make eval"
)


def _overall(doc: dict, p: str) -> dict:
    all_ = doc["aggregate"]["overall"][p]["all"]
    return {m: v["mean"] for m, v in all_.items() if isinstance(v, dict)}


def test_committed_tables_regenerate_from_raw():
    committed = json.loads(COMPARISON.read_text(encoding="utf-8"))
    fresh = build_comparison(R.score_all(R.load_raws()))
    for p in committed["aggregate"]["prioritisers"]:
        assert _overall(fresh, p) == pytest.approx(_overall(committed, p), abs=1e-4), p


def test_structural_metrics_unchanged_for_reachable():
    doc = json.loads(COMPARISON.read_text(encoding="utf-8"))
    me = _overall(doc, "reachable")
    for m, before in S8_REACHABLE.items():
        assert me[m] == pytest.approx(before, abs=NOISE), (m, me[m], before)
    assert me["fix_cut_share"] == 1.0
    for p in ("severity_sort", "smart_score", "vector_rag", "sql_agent"):
        theirs = _overall(doc, p)
        assert theirs["path_recall@10"] <= 0.25 and theirs["fix_cut_share"] <= 0.25, p
