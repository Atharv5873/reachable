"""Tables: comparison.json/.md and ablation.json/.md, from scored raw outputs.

Aggregation. Per scan, a metric's mean / sd / min / max is over the seeds (one
run for the deterministic two). Overall, each seed's metric is first averaged
over the scans of a split (all six, the three v1 scans, the three held-out v2
scans), then spread over the seeds. The ceiling row is the oracle's own order.

Losses are found, not written: every headline metric where some other
prioritiser's mean beats reachable's is listed, with the numbers. The one-line
"why" for each lives in evals/comparison_notes.md (written by a person after
reading the raw outputs) and is included verbatim.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import UTC, datetime

from reachable_core.settings import REPO_ROOT

from .scoring import flat, ideal_order, load_truth, score_order, spread

NOTES = REPO_ROOT / "evals" / "comparison_notes.md"
ORDER = ("severity_sort", "smart_score", "vector_rag", "sql_agent", "reachable")
# Structural metrics first (S9): they ask "did it find the paths, avoid the decoys,
# pick a fix set that cuts them", which no prioritiser can satisfy by sharing the
# oracle's definition of priority. NDCG / P@K (agreement with that priority) after.
HEADLINE = (
    ("path_recall@10", "path recall@10", True),
    ("decoy_rate@10", "decoys@10", False),
    ("fix_paths_per_fix", "paths cut / fix", True),
    ("ndcg@10", "NDCG@10", True),
    ("p@10", "P@10", True),
)
NDCG_CAVEAT = (
    "reachable's ranker and the ground truth both define importance as reachability to "
    "the crown jewels (weighted by each target's sensitivity tier), so agreement between "
    "them is expected, not a discovery. The informative comparison is reachable vs the "
    "reachability-blind baselines, and the ablation isolates the graph's contribution."
)
COST = ("llm_calls", "tool_calls", "tokens_in", "tokens_out", "usd", "wall_s", "active_s")
SPLITS = {"all": ("v1", "v2"), "v1": ("v1",), "v2": ("v2",)}


def _by(scored: list[dict], *keys) -> dict:
    out: dict = defaultdict(list)
    for s in scored:
        out[tuple(s[k] for k in keys)].append(s)
    return out


def aggregate(scored: list[dict]) -> dict:
    prioritisers = [p for p in ORDER if any(s["prioritiser"] == p for s in scored)]
    prioritisers += sorted({s["prioritiser"] for s in scored} - set(prioritisers))
    graphs = sorted({(s["scan"], s["org"], s["graph"]) for s in scored})
    per_scan: dict = defaultdict(dict)
    for (p, g), runs in _by(scored, "prioritiser", "graph").items():
        flats = [flat(r["score"]) for r in runs]
        per_scan[p][g] = {m: spread([f[m] for f in flats]) for m in flats[0]}
        per_scan[p][g]["seeds"] = sorted(r["seed"] for r in runs)
    overall: dict = defaultdict(dict)
    for p in prioritisers:
        for split, scan_names in SPLITS.items():
            by_seed: dict[int, list[dict]] = defaultdict(list)
            for s in scored:
                if s["prioritiser"] == p and s["scan"] in scan_names:
                    by_seed[s["seed"]].append(flat(s["score"]))
            if not by_seed:
                continue
            metrics = next(iter(by_seed.values()))[0].keys()
            seed_means = {
                seed: {m: statistics.fmean(f[m] for f in fl) for m in metrics}
                for seed, fl in by_seed.items()
            }
            overall[p][split] = {m: spread([sm[m] for sm in seed_means.values()]) for m in metrics}
            overall[p][split]["scans"] = len(next(iter(by_seed.values())))
    cost: dict = {}
    totals = defaultdict(float)
    for p in prioritisers:
        runs = [s["meta"] for s in scored if s["prioritiser"] == p]
        for m in runs:  # raw files from before wait accounting: active = wall
            m.setdefault("active_s", m.get("wall_s"))
        cost[p] = {k: spread([float(m.get(k) or 0) for m in runs]) for k in COST}
        cost[p]["runs"] = len(runs)
        cost[p]["invalid_ids_per_run"] = spread(
            [len(s["invalid_ids"]) for s in scored if s["prioritiser"] == p]
        )
        for m in runs:
            for k in ("llm_calls", "tokens_in", "tokens_out", "usd", "embed_tokens"):
                totals[k] += float(m.get(k) or 0)
    ceiling = {}
    for scan, org, g in graphs:
        t = load_truth(org, scan)
        sc = score_order(ideal_order(t), t, t.min_cut)
        ceiling[g] = {
            **flat(sc),
            "relevant": t.relevant,
            "paths": len(t.paths),
            "min_cut": len(t.min_cut),
            "decoys": len(t.decoys),
        }
    return {
        "prioritisers": prioritisers,
        "scans": [{"org": o, "scan": s, "graph": g} for s, o, g in graphs],
        "per_scan": dict(per_scan),
        "overall": dict(overall),
        "cost": cost,
        "totals": {k: round(v, 6) for k, v in totals.items()},
        "ceiling": ceiling,
    }


def losses(agg: dict, me: str = "reachable") -> list[dict]:
    """Every (metric, where) a different prioritiser's mean beats `me` on."""
    out = []
    places = [("overall", s, agg["overall"]) for s in SPLITS] + [
        ("scan", g["graph"], agg["per_scan"]) for g in agg["scans"]
    ]
    for kind, where, table in places:

        def val(p, m, where=where, table=table):
            return ((table.get(p) or {}).get(where) or {}).get(m, {}).get("mean")

        for m, label, higher in HEADLINE:
            mine = val(me, m)
            if mine is None:
                continue
            for p in agg["prioritisers"]:
                if p == me or val(p, m) is None:
                    continue
                theirs = val(p, m)
                if (theirs > mine + 1e-9) if higher else (theirs < mine - 1e-9):
                    out.append(
                        {
                            "where": f"{kind}:{where}",
                            "metric": label,
                            "winner": p,
                            "winner_value": theirs,
                            "reachable_value": mine,
                        }
                    )
    return out


# ------------------------------------------------------------------ markdown
def _fmt(s: dict | None, pct: bool = False, money: bool = False, n: int = 2) -> str:
    if not s or s.get("mean") is None:
        return "-"
    m, sd = s["mean"], s.get("sd") or 0.0
    if money:
        return f"${m:.4f}"
    if pct:
        body = f"{m * 100:.0f}%"
        return body + (f" ±{sd * 100:.0f}" if s.get("n", 1) > 1 and sd > 0 else "")
    body = f"{m:.{n}f}"
    return body + (f" ±{sd:.{n}f}" if s.get("n", 1) > 1 and sd > 0 else "")


def _row(cells: list) -> str:
    return "| " + " | ".join(str(c) for c in cells) + " |"


def comparison_md(doc: dict) -> str:
    agg = doc["aggregate"]
    L = [
        "# Comparison eval: five prioritisers, one oracle",
        "",
        f"Generated {doc['generated']} by `make eval`. Model for the three LLM prioritisers: "
        f"`{doc['model']}` (temperature 0, provider seeds {doc['seeds']}). Dataset seed "
        f"{doc['dataset_seed']}. K = 10. Every number below is recomputed from "
        "`evals/results/raw/` plus the labels by `python -m reachable_eval score`.",
        "",
        "Scans: v1 of org_a / org_b / org_c (the scans the harness was developed against) and "
        "**held-out v2** of each (the week-later rescan, never looked at while building it).",
        "",
        "## 1. Structural metrics (all six scans; mean ± sd over seeds)",
        "",
        "Did the top 10 cover the real attack paths, stay off the decoys, and come with a "
        "fix set that cuts the paths? None of these depends on how the oracle weights "
        "priority, so none can be won by sharing its definition.",
        "",
        _row(
            [
                "prioritiser",
                "path recall@10",
                "decoys@10 (lower better)",
                "paths cut / fix",
                "fix set cuts (share of paths)",
            ]
        ),
        _row(["---"] * 5),
    ]
    ceil = list(agg["ceiling"].values())

    def cmean(k: str) -> float:
        return statistics.fmean(c[k] for c in ceil)

    for p in agg["prioritisers"]:
        o = agg["overall"].get(p, {}).get("all", {})
        L.append(
            _row(
                [
                    f"**{p}**" if p == "reachable" else p,
                    _fmt(o.get("path_recall@10"), pct=True),
                    _fmt(o.get("decoy_rate@10"), pct=True),
                    _fmt(o.get("fix_paths_per_fix")),
                    _fmt(o.get("fix_cut_share"), pct=True),
                ]
            )
        )
    L.append(
        _row(
            [
                "*oracle*",
                f"{cmean('path_recall@10') * 100:.0f}%",
                f"{cmean('decoy_rate@10') * 100:.0f}%",
                f"{cmean('fix_paths_per_fix'):.2f}",
                "100%",
            ]
        )
    )
    L += [
        "",
        "*path recall@10*: the share of planted attack paths with at least one of their "
        "findings in the top 10. *decoys@10*: the share of the three planted decoys (a "
        "critical KEV with no route, a WAF-mitigated critical, an exposed dead end) ranked "
        "in the top 10. *paths cut / fix*: paths cut by the prioritiser's own fix set "
        "(else its top M findings, M = the oracle min-cut size) per fix; the *oracle* row "
        "is the oracle's min cut, which cuts every path with the fewest fixes. The oracle "
        "row's path recall is its priority order's (not a ceiling: a list can cover every "
        "path without following priority order).",
    ]
    abl = doc.get("ablation")
    if abl:
        on, off = abl["graph_on"], abl["graph_off"]
        L += [
            "",
            f"**Ablation** ({abl['org']} {abl['scan']}, `evals/results/ablation.md`): the same "
            'reachable agent with every graph tool answering "unavailable": path recall@10 '
            f"{_fmt(on.get('path_recall@10'), pct=True)} -> "
            f"{_fmt(off.get('path_recall@10'), pct=True)}, fix set cuts "
            f"{_fmt(on.get('fix_cut_share'), pct=True)} -> "
            f"{_fmt(off.get('fix_cut_share'), pct=True)}, NDCG@10 "
            f"{_fmt(on.get('ndcg@10'))} -> {_fmt(off.get('ndcg@10'))}. "
            "Same model, prompt and budget: the graph supplies the answer, not the model.",
        ]
    L += [
        "",
        "## 2. Agreement with the oracle's priority (secondary)",
        "",
        f"**Caveat.** {NDCG_CAVEAT}",
        "",
        _row(["prioritiser", "NDCG@10", "P@10", "NDCG@10 v1", "NDCG@10 v2 (held out)"]),
        _row(["---"] * 5),
    ]
    for p in agg["prioritisers"]:
        ov = agg["overall"].get(p, {})
        o = ov.get("all", {})
        L.append(
            _row(
                [
                    f"**{p}**" if p == "reachable" else p,
                    _fmt(o.get("ndcg@10")),
                    _fmt(o.get("p@10"), pct=True),
                    _fmt(ov.get("v1", {}).get("ndcg@10")),
                    _fmt(ov.get("v2", {}).get("ndcg@10")),
                ]
            )
        )
    L += [
        _row(
            ["*oracle order*", f"{cmean('ndcg@10'):.2f}", f"{cmean('p@10') * 100:.0f}%", "-", "-"]
        ),
        "",
        "Relevance is the oracle's priority: the sum, over the crown-jewel paths a finding "
        "lies on, of the target's tier weight (critical 1.0, high 0.6, medium 0.3; S9), "
        "normalised per scan. Every org has crown jewels of two or three tiers, so the "
        "ideal order is a real gradient (not just on-path vs off-path). P@10's ceiling is "
        "below 100% where a scan has fewer than 10 relevant findings (org_b has 7, org_c 9).",
        "",
        "## 3. Cost and latency",
        "",
        _row(
            ["prioritiser", "LLM calls / run", "tokens in+out / run", "$ / run", "s / run (active)"]
        ),
        _row(["---"] * 5),
    ]
    for p in agg["prioritisers"]:
        c = agg["cost"][p]
        tok = (c["tokens_in"]["mean"] or 0) + (c["tokens_out"]["mean"] or 0)
        L.append(
            _row(
                [
                    f"**{p}**" if p == "reachable" else p,
                    _fmt(c["llm_calls"], n=1),
                    f"{tok:,.0f}",
                    _fmt(c["usd"], money=True),
                    _fmt(c["active_s"], n=1),
                ]
            )
        )
    L += [
        "",
        "*s / run (active)* is wall time minus the seconds spent waiting on the Gemini "
        "key's rate limit (raw files keep both).",
        "",
        "## Development scans (v1) vs held-out scans (v2): structural",
        "",
        _row(
            [
                "prioritiser",
                "path recall@10 v1",
                "path recall@10 v2",
                "decoys@10 v1",
                "decoys@10 v2",
                "paths cut / fix v1",
                "paths cut / fix v2",
            ]
        ),
        _row(["---"] * 7),
    ]
    for p in agg["prioritisers"]:
        o = agg["overall"].get(p, {})
        L.append(
            _row(
                [
                    p,
                    _fmt(o.get("v1", {}).get("path_recall@10"), pct=True),
                    _fmt(o.get("v2", {}).get("path_recall@10"), pct=True),
                    _fmt(o.get("v1", {}).get("decoy_rate@10"), pct=True),
                    _fmt(o.get("v2", {}).get("decoy_rate@10"), pct=True),
                    _fmt(o.get("v1", {}).get("fix_paths_per_fix")),
                    _fmt(o.get("v2", {}).get("fix_paths_per_fix")),
                ]
            )
        )
    L += [
        "",
        "## Per scan (mean over seeds)",
        "",
        _row(
            [
                "scan",
                "prioritiser",
                "path recall@10",
                "decoys@10",
                "fix: cut / size",
                "NDCG@10",
                "P@10",
            ]
        ),
        _row(["---"] * 7),
    ]
    for g in agg["scans"]:
        gid = g["graph"]
        for p in agg["prioritisers"]:
            s = agg["per_scan"].get(p, {}).get(gid)
            if not s:
                continue
            L.append(
                _row(
                    [
                        gid,
                        p,
                        _fmt(s["path_recall@10"], pct=True),
                        _fmt(s["decoy_rate@10"], pct=True),
                        f"{_fmt(s['fix_cut_share'], pct=True)} / {_fmt(s['fix_size'], n=1)}",
                        _fmt(s["ndcg@10"]),
                        _fmt(s["p@10"], pct=True),
                    ]
                )
            )
        c = agg["ceiling"][gid]
        L.append(
            _row(
                [
                    gid,
                    "*oracle order*",
                    f"{c['path_recall@10'] * 100:.0f}%",
                    f"{c['decoy_rate@10'] * 100:.0f}%",
                    f"{c['relevant']} relevant, {c['paths']} paths, cut {c['min_cut']}",
                    f"{c['ndcg@10']:.2f}",
                    f"{c['p@10'] * 100:.0f}%",
                ]
            )
        )
    L += ["", "## Where reachable does not win", ""]
    lost = doc["losses"]
    if lost:
        for x in lost:
            L.append(
                f"- {x['where']}: **{x['metric']}**: {x['winner']} {x['winner_value']:.3f} vs "
                f"reachable {x['reachable_value']:.3f}"
            )
    else:
        L.append("- No headline metric, on any scan or split.")
    L.append(
        "- Cost and latency: reachable (like the other two LLM prioritisers) costs model calls "
        "and seconds; severity_sort and smart_score cost nothing and answer in milliseconds."
    )
    if NOTES.exists():
        L += ["", NOTES.read_text(encoding="utf-8").strip()]
    L += [
        "",
        "## Variance",
        "",
        _row(
            [
                "prioritiser",
                "runs",
                "NDCG@10 (min-max over seeds)",
                "path recall@10 (min-max)",
                "model answered",
                "invalid ids / run",
            ]
        ),
        _row(["---"] * 6),
    ]
    for p in agg["prioritisers"]:
        o = agg["overall"].get(p, {}).get("all", {})
        nd, rc = o.get("ndcg@10") or {}, o.get("path_recall@10") or {}
        L.append(
            _row(
                [
                    p,
                    agg["cost"][p]["runs"],
                    f"{nd.get('min', 0):.3f}-{nd.get('max', 0):.3f}",
                    f"{(rc.get('min') or 0) * 100:.0f}%-{(rc.get('max') or 0) * 100:.0f}%",
                    doc["answered"].get(p, "-"),
                    _fmt(agg["cost"][p]["invalid_ids_per_run"], n=1),
                ]
            )
        )
    t = agg["totals"]
    L += [
        "",
        "## Spend",
        "",
        f"Matrix: {t.get('llm_calls', 0):.0f} LLM calls, {t.get('tokens_in', 0):,.0f} input + "
        f"{t.get('tokens_out', 0):,.0f} output tokens, ${t.get('usd', 0):.4f} "
        f"(includes vector_rag's query embeddings). RAG index build: "
        f"{doc.get('rag_build', {}).get('embed_tokens', 0):,} embedding tokens, "
        f"${doc.get('rag_build', {}).get('embed_usd', 0):.4f} "
        "(cached on disk after the first build).",
        "",
        "## Method",
        "",
        "- One finding universe per scan: its open findings (`universe.sha` in every raw file).",
        "- LLM prioritisers name up to 20 findings; the rest of their order is the same "
        "severity tail (CVSS desc, hash tie-break). Ids that are not open findings are dropped "
        "and counted (`invalid ids`).",
        "- Same model, temperature, system prompt, CONTEXT, output schema, 6 turns, 8 model "
        "calls, 24 tool calls and 6,000-char tool results for all three; only the toolbox "
        "differs (pgvector search / read-only SQL / FalkorDB tools over MCP).",
        "- Baselines read the eval views only (no company layer, no memory, no label or path "
        "field); `tests/test_eval_leakage.py` proves it.",
        "- Baselines see which data stores are crown jewels, not their sensitivity tier "
        "(S9: the views drop `datastores.sensitivity`; reachable reads it from the graph).",
        "- See `learning/S07.md` for what each metric measures and why, `learning/S09.md` "
        "for why the structural metrics lead.",
        "",
    ]
    return "\n".join(L)


def build_comparison(scored: list[dict], **meta) -> dict:
    agg = aggregate(scored)
    answered = {}
    for p in agg["prioritisers"]:
        runs = [s["meta"] for s in scored if s["prioritiser"] == p]
        if any("llm_answered" in m for m in runs):
            answered[p] = f"{sum(bool(m.get('llm_answered')) for m in runs)}/{len(runs)}"
    return {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        **meta,
        "k": 10,
        "aggregate": agg,
        "losses": losses(agg),
        "answered": answered,
    }


# ------------------------------------------------------------------ ablation
ABL_METRICS = ("path_recall@10", "ndcg@10", "p@10", "decoy_rate@10", "fix_cut_share")


def build_ablation(scored: list[dict], **meta) -> dict:
    on = [s for s in scored if s["prioritiser"] == "reachable"]
    off = [s for s in scored if s["prioritiser"] == "reachable_graph_off"]

    def block(runs):
        fl = [flat(r["score"]) for r in runs]
        out = {m: spread([f[m] for f in fl]) for m in ABL_METRICS}
        for k in (
            "llm_calls",
            "tool_calls",
            "tokens_in",
            "tokens_out",
            "usd",
            "wall_s",
            "active_s",
        ):
            out[k] = spread([float(r["meta"].get(k) or 0) for r in runs])
        out["runs"] = len(runs)
        out["answered"] = sum(bool(r["meta"].get("llm_answered")) for r in runs)
        return out

    b_on, b_off = block(on), block(off)
    drop = {m: round((b_on[m]["mean"] or 0) - (b_off[m]["mean"] or 0), 4) for m in ABL_METRICS}
    org, scan = (on or off)[0]["org"], (on or off)[0]["scan"]
    return {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        **meta,
        "org": org,
        "scan": scan,
        "graph_on": b_on,
        "graph_off": b_off,
        "drop": drop,
        "pass": drop["path_recall@10"] > 0 and drop["ndcg@10"] > 0,
    }


def ablation_md(doc: dict) -> str:
    on, off, d = doc["graph_on"], doc["graph_off"], doc["drop"]
    L = [
        "# Ablation: the same agent, graph tools on vs off",
        "",
        f"Generated {doc['generated']} by `make ablation`. {doc['org']} scan {doc['scan']}, "
        f"model `{doc['model']}`, seeds {doc['seeds']}. Identical prompt, CONTEXT, budgets and "
        "tool schemas; graph-off, every FalkorDB tool call answers *unavailable*, so the agent "
        "can only reason from the CONTEXT (the scanner's top findings by CVSS, the crown "
        "jewels, counts).",
        "",
        _row(
            [
                "",
                "path recall@10",
                "NDCG@10",
                "P@10",
                "decoys@10",
                "fix set cuts",
                "tool calls answered",
                "tokens in / run",
            ]
        ),
        _row(["---"] * 8),
    ]
    for label, b in (("graph ON", on), ("graph OFF", off)):
        L.append(
            _row(
                [
                    f"**{label}**",
                    _fmt(b["path_recall@10"], pct=True),
                    _fmt(b["ndcg@10"]),
                    _fmt(b["p@10"], pct=True),
                    _fmt(b["decoy_rate@10"], pct=True),
                    _fmt(b["fix_cut_share"], pct=True),
                    _fmt(b["tool_calls"], n=1) if label == "graph ON" else "0 (unavailable)",
                    f"{b['tokens_in']['mean'] or 0:,.0f}",
                ]
            )
        )
    L.append(
        _row(
            [
                "**drop**",
                f"**{d['path_recall@10'] * 100:+.0f} pts**",
                f"**{d['ndcg@10']:+.2f}**",
                f"{d['p@10'] * 100:+.0f} pts",
                f"{d['decoy_rate@10'] * 100:+.0f} pts",
                f"{d['fix_cut_share'] * 100:+.0f} pts",
                "",
                "",
            ]
        )
    )
    L += [
        "",
        "Positive drop = what taking FalkorDB away costs (for decoys, a negative drop means "
        "more decoys reached the top 10 without the graph).",
        "",
    ]
    return "\n".join(L)
