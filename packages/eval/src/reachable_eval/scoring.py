"""Score a ranking against the oracle. The ONLY module that reads labels.json.

Relevance of a finding = its oracle `finding_priority` (0..1): the sum, over
every Internet -> crown-jewel path the finding's step lies on, of the target's
sensitivity weight, normalised so the top finding is 1.0. Most findings are 0.

  NDCG@K            sum_i rel_i / log2(i + 1) over the top K, divided by the same
                    sum for the ideal order (linear gain). 1.0 = the oracle's order.
  P@K               the share of the top K with rel > 0 (on a real path).
                    Ceiling = min(K, #relevant) / K.
  path recall@K     of the planted paths, the share with at least one of their
                    findings (a hop whose fix is a Finding id) in the top K.
  decoys@K          of the planted decoy findings (severity: critical KEV, no route;
                    mitigated: a WAF blocks it; dead_end: exposed, leads nowhere),
                    the share ranked in the top K. Lower is better.
  fix efficiency    the fix set (the prioritiser's own, else its top M findings with
                    M = the oracle min-cut size, the evaluator's budget): planted
                    paths cut (any hop's fix in the set), per fix, vs the oracle
                    min cut, which cuts every path.
"""

from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass
from pathlib import Path

from reachable_core.settings import get_settings

KS = (5, 10, 20)
HEADLINE_K = 10


@dataclass
class Truth:
    priority: dict[str, float]
    paths: list[dict]  # {name, difficulty, fixes: set, findings: set}
    decoys: dict[str, str]  # finding id -> decoy kind
    min_cut: list[str]
    oracle_path_count: int

    @property
    def relevant(self) -> int:
        return sum(1 for v in self.priority.values() if v > 0)


def labels_path(org: str, scan: str) -> Path:
    return get_settings().orgs_dir / org / ("labels.json" if scan == "v1" else "labels_v2.json")


def truth_from_labels(labels: dict) -> Truth:
    paths = []
    for p in labels["paths"]:
        fixes = {h.get("fix") for h in p["hops"] if h.get("fix")}
        if not fixes:
            raise ValueError(
                f"labels path {p['name']!r} has no hop fix tokens: re-run `make seed` (S7 labels)"
            )
        paths.append(
            {
                "name": p["name"],
                "difficulty": p["difficulty"],
                "fixes": fixes,
                "findings": {f for f in fixes if ":finding:" in f},
            }
        )
    decoys = {fid: d["kind"] for d in labels["decoys"] for fid in d["finding_ids"]}
    return Truth(
        priority={k: float(v) for k, v in labels["finding_priority"].items()},
        paths=paths,
        decoys=decoys,
        min_cut=list(labels["min_cut"]),
        oracle_path_count=int(labels.get("oracle_path_count", len(paths))),
    )


def load_truth(org: str, scan: str) -> Truth:
    return truth_from_labels(json.loads(labels_path(org, scan).read_text(encoding="utf-8")))


# -------------------------------------------------------------------- metrics
def dcg(gains: list[float]) -> float:
    return sum(g / math.log2(i + 2) for i, g in enumerate(gains))


def ndcg_at(order: list[str], pri: dict[str, float], k: int) -> float:
    ideal = dcg(sorted(pri.values(), reverse=True)[:k])
    return dcg([pri.get(f, 0.0) for f in order[:k]]) / ideal if ideal > 0 else 0.0


def precision_at(order: list[str], pri: dict[str, float], k: int) -> float:
    return sum(1 for f in order[:k] if pri.get(f, 0.0) > 0) / k


def path_recall_at(order: list[str], paths: list[dict], k: int) -> float:
    top = set(order[:k])
    return sum(1 for p in paths if p["findings"] & top) / len(paths) if paths else 0.0


def decoys_at(order: list[str], decoys: dict[str, str], k: int) -> tuple[float, list[str]]:
    hit = [f"{decoys[f]}:{f}" for f in order[:k] if f in decoys]
    return (len(hit) / len(decoys) if decoys else 0.0), hit


def fix_efficiency(fix_set: list[str], truth: Truth) -> dict:
    fs = set(fix_set)
    cut = [p["name"] for p in truth.paths if p["fixes"] & fs]
    n = len(truth.paths)
    return {
        "size": len(fs),
        "paths_cut": len(cut),
        "paths": n,
        "cut_share": round(len(cut) / n, 4) if n else 0.0,
        "paths_per_fix": round(len(cut) / len(fs), 4) if fs else 0.0,
        "cuts_every_path": n > 0 and len(cut) == n,
        "oracle_size": len(truth.min_cut),
        "oracle_paths_per_fix": round(n / len(truth.min_cut), 4) if truth.min_cut else 0.0,
    }


def score_order(order: list[str], truth: Truth, fix_set: list[str] | None = None) -> dict:
    out: dict = {}
    for k in KS:
        rate, hits = decoys_at(order, truth.decoys, k)
        out[f"ndcg@{k}"] = round(ndcg_at(order, truth.priority, k), 4)
        out[f"p@{k}"] = round(precision_at(order, truth.priority, k), 4)
        out[f"path_recall@{k}"] = round(path_recall_at(order, truth.paths, k), 4)
        out[f"decoy_rate@{k}"] = round(rate, 4)
        if k == HEADLINE_K:
            out["decoys_in_top10"] = hits
    derived = not fix_set
    chosen = list(fix_set) if fix_set else order[: len(truth.min_cut)]
    out["fix"] = {**fix_efficiency(chosen, truth), "source": "derived" if derived else "own"}
    return out


def score_raw(raw: dict, truth: Truth) -> dict:
    """Score one raw output file. `head` keeps the top 100 of the order."""
    return score_order(raw["head"], truth, raw.get("fix_set"))


def ideal_order(truth: Truth) -> list[str]:
    """The oracle's own order: the ceiling every metric is measured against."""
    return sorted(truth.priority, key=lambda f: -truth.priority[f])


# ---------------------------------------------------------------- aggregation
def spread(values: list[float]) -> dict:
    vals = [v for v in values if v is not None]
    if not vals:
        return {"mean": None, "sd": None, "min": None, "max": None, "n": 0}
    return {
        "mean": round(statistics.fmean(vals), 4),
        "sd": round(statistics.pstdev(vals), 4) if len(vals) > 1 else 0.0,
        "min": round(min(vals), 4),
        "max": round(max(vals), 4),
        "n": len(vals),
    }


METRICS = tuple(f"{m}@{k}" for k in KS for m in ("ndcg", "p", "path_recall", "decoy_rate")) + (
    "fix_paths_per_fix",
    "fix_cut_share",
    "fix_size",
)


def flat(score: dict) -> dict:
    """A score with the fix block flattened, for aggregation."""
    out = {k: v for k, v in score.items() if isinstance(v, int | float)}
    out["fix_paths_per_fix"] = score["fix"]["paths_per_fix"]
    out["fix_cut_share"] = score["fix"]["cut_share"]
    out["fix_size"] = score["fix"]["size"]
    return out
