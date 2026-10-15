"""Gate A: score the graph tools against ground truth, with NO LLM.

For each org:
  1. RUN (label-free): exposure_surface -> attack_paths from the Internet seed
     (and from every exploitable exposed asset), blast_radius, min_cut (both
     preferences), simulate_fix on each cut, choke_points, why_step on every hop
     of the top path, vuln_intel. Nothing in this phase reads labels.json.
  2. SCORE (labels.json read here only): planted-path recall by difficulty,
     precision vs planted paths, decoys in top paths, min_cut vs the oracle cut,
     evidence validity (a separate Cypher pass: every id/edge must exist),
     p50/p95 latency per tool.
Optional --scale N: generate org_a at scale N into its own graph, derive, and
report memory + the three slowest tools.

    uv run python evals/gate_a.py [--scale 3] [--reps 20]

Writes evals/results/gate_a.json and gate_a.md.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path

from reachable_core.db import connect, drop_graph, memory_usage_mb
from reachable_core.settings import get_settings
from reachable_graph.compat import from_oracle_id, planted_node_sequence, to_oracle_id
from reachable_graph.derive import derive
from reachable_graph.models import Evidence, ToolResult
from reachable_graph.tools import GraphTools, label_of

RESULTS = Path(__file__).parent / "results"
K = 10  # attack_paths budget per call
_REL_RE = re.compile(r"^[A-Z_]+$")


# ------------------------------------------------------------------- RUN
class Timed:
    """Wraps GraphTools; records wall-clock latency and every Evidence returned."""

    def __init__(self, tools: GraphTools) -> None:
        self.t = tools
        self.lat: dict[str, list[float]] = {}
        self.evidence: list[tuple[str, Evidence]] = []

    def __call__(self, name: str, *args, bucket: str | None = None, **kwargs) -> ToolResult:
        t0 = time.perf_counter()
        r = getattr(self.t, name)(*args, **kwargs)
        self.lat.setdefault(bucket or name, []).append((time.perf_counter() - t0) * 1000)
        self.evidence.append((name, r.evidence))
        return r


def run_tools(org: str, tools: GraphTools, reps: int) -> dict:
    """Everything the tools say about one org. Reads NO labels."""
    T = Timed(tools)
    exposure = T("exposure_surface", org, limit=200)
    seeds = [a["asset"] for a in exposure.data["assets"] if a["exploitable"]]

    # Seed = the Internet node (the attack graph's single source).
    internet = T("attack_paths", org, k=K)
    # And from each exploitable exposed asset (what a defender would triage first).
    from_seeds = [
        T("attack_paths", org, source_id=s, k=K, bucket="attack_paths (from a seed asset)")
        for s in seeds
    ]

    blast = T("blast_radius", org, seeds[0]) if seeds else None
    cuts, sims = {}, {}
    for prefer in ("entry", "crown"):
        cuts[prefer] = T("min_cut", org, prefer=prefer)
        sims[prefer] = T("simulate_fix", org, cuts[prefer].data["fix_tokens"])
    choke = T("choke_points", org)
    top = internet.data["paths"][0] if internet.data["paths"] else None
    whys = [T("why_step", org, s["key"]) for s in (top["steps"] if top else [])]
    first_finding = next(
        (s["fix_token"] for s in (top["steps"] if top else []) if ":finding:" in s["fix_token"]),
        None,
    )
    cve = None
    if first_finding:
        cve = tools.run_cypher_readonly(
            org,
            "MATCH (:Finding {id: $f})-[:OF]->(v:Vuln) RETURN v.cve",
            {"f": first_finding},
            limit=1,
        ).data["rows"][0][0]
        T("vuln_intel", cve, org=org)

    # Extra repetitions for stable latency numbers (results discarded).
    for _ in range(reps - 1):
        T("exposure_surface", org, limit=200)
        T("attack_paths", org, k=K)
        if seeds:
            T("blast_radius", org, seeds[0])
        T("min_cut", org)
        T("choke_points", org)
        if top:
            T("why_step", org, top["steps"][0]["key"])
        if cve:
            T("vuln_intel", cve, org=org)
        T("run_cypher_readonly", org, "MATCH (a:Asset) RETURN a.id", limit=50)
    for _ in range(max(1, reps // 4) - 1):
        T("simulate_fix", org, cuts["entry"].data["fix_tokens"])

    return {
        "exposure": exposure,
        "seeds": seeds,
        "internet": internet,
        "from_seeds": from_seeds,
        "blast": blast,
        "cuts": cuts,
        "sims": sims,
        "choke": choke,
        "whys": whys,
        "timed": T,
    }


# ----------------------------------------------------------------- SCORE
def _seq(path: dict) -> tuple[str, ...]:
    return tuple(to_oracle_id(n["id"], n["labels"]) for n in path["nodes"])


def check_evidence(db, org: str, evidence: list[tuple[str, Evidence]]) -> dict:
    """Separate Cypher pass: does every evidence node id and edge exist?"""
    g = db.select_graph(org)
    node_ids, edges = set(), set()
    for _, ev in evidence:
        node_ids.update(ev.node_ids)
        node_ids.update(i for p in ev.paths for i in p)
        edges.update((e.src, e.rel, e.dst, e.key) for e in ev.edges)
        node_ids.update(x for e in ev.edges for x in (e.src, e.dst))

    found: set[str] = set()
    by_label: dict[str, list[str]] = {}
    for i in node_ids:
        by_label.setdefault(label_of(i) or "?", []).append(i)
    for label, ids in by_label.items():
        if label == "?":
            continue
        rows = g.ro_query(
            f"MATCH (n:{label}) WHERE n.id IN $ids RETURN n.id", {"ids": ids}
        ).result_set
        found.update(r[0] for r in rows)
    missing_nodes = sorted(node_ids - found)

    ok_edges = set()
    keyed = [e for e in edges if e[3]]
    if keyed:
        rows = g.ro_query(
            "MATCH (a)-[e:ATTACK_STEP]->(b) WHERE e.key IN $keys RETURN a.id, b.id, e.key",
            {"keys": [e[3] for e in keyed]},
        ).result_set
        real = {(a, "ATTACK_STEP", b, k) for a, b, k in rows}
        ok_edges.update(e for e in keyed if e in real)
    plain: dict[tuple[str, str, str], list[dict]] = {}
    for src, rel, dst, key in edges:
        if key:
            continue
        if not _REL_RE.match(rel):
            continue
        plain.setdefault((rel, label_of(src) or "", label_of(dst) or ""), []).append(
            {"src": src, "dst": dst}
        )
    for (rel, ls, ld), rows_in in plain.items():
        if not ls or not ld:
            continue
        rows = g.ro_query(
            f"UNWIND $rows AS r MATCH (a:{ls} {{id: r.src}})-[:{rel}]->(b:{ld} {{id: r.dst}}) "
            "RETURN DISTINCT r.src, r.dst",
            {"rows": rows_in},
        ).result_set
        ok_edges.update((s, rel, d, None) for s, d in rows)
    missing_edges = sorted(str(e) for e in edges - ok_edges)
    total = len(node_ids) + len(edges)
    bad = len(missing_nodes) + len(missing_edges)
    return {
        "nodes_checked": len(node_ids),
        "edges_checked": len(edges),
        "missing_nodes": missing_nodes[:20],
        "missing_edges": missing_edges[:20],
        "validity": 1.0 if total == 0 else round((total - bad) / total, 4),
    }


def _pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    if not xs:
        return 0.0
    i = min(len(xs) - 1, max(0, round(q * (len(xs) - 1))))
    return round(xs[i], 2)


def latency_table(T: Timed) -> dict:
    return {
        name: {"n": len(v), "p50_ms": _pct(v, 0.5), "p95_ms": _pct(v, 0.95)}
        for name, v in sorted(T.lat.items())
    }


def score(org: str, out: dict, labels: dict, db) -> dict:
    """Compare tool output with labels.json (read ONLY here)."""
    returned = [_seq(p) for p in out["internet"].data["paths"]]
    seeded = {("internet", *_seq(p)) for r in out["from_seeds"] for p in r.data["paths"]}
    planted = {p["name"]: (p["difficulty"], planted_node_sequence(p)) for p in labels["paths"]}

    recall: dict[str, dict] = {}
    for name, (diff, seq) in planted.items():
        d = recall.setdefault(diff, {"planted": 0, "found": 0, "found_from_seeds": 0, "missed": []})
        d["planted"] += 1
        if seq in returned:
            d["found"] += 1
        else:
            d["missed"].append(name)
        if seq in seeded:
            d["found_from_seeds"] += 1
    for d in recall.values():
        d["recall"] = round(d["found"] / d["planted"], 4)
        d["recall_from_seeds"] = round(d["found_from_seeds"] / d["planted"], 4)

    decoy_assets = {f"asset:{d['asset']}" for d in labels["decoys"]}
    decoy_findings = {f for d in labels["decoys"] for f in d["finding_ids"]}
    with_decoy = 0
    for p in out["internet"].data["paths"]:
        seq = set(_seq(p))
        toks = {s["fix_token"] for s in p["steps"]}
        if seq & decoy_assets or toks & decoy_findings:
            with_decoy += 1
    n_ret = len(returned)
    planted_seqs = {s for _, s in planted.values()}

    oracle_cut = set(labels["min_cut"])
    cuts = {}
    for prefer, r in out["cuts"].items():
        toks = set(r.data["fix_tokens"])
        cuts[prefer] = {
            "size": len(toks),
            "max_flow": r.data["max_flow"],
            "oracle_size": labels["min_cut_size"],
            "size_le_oracle": len(toks) <= labels["min_cut_size"],
            "equals_oracle_set": toks == oracle_cut,
            "disconnects_all_crown_jewels": out["sims"][prefer].data[
                "all_crown_jewels_disconnected"
            ],
            "fix_tokens": sorted(toks),
        }

    return {
        "org": org,
        "returned_paths": n_ret,
        "recall_by_difficulty": recall,
        "precision_vs_planted": round(sum(s in planted_seqs for s in returned) / n_ret, 4)
        if n_ret
        else 0.0,
        "decoy_precision": round((n_ret - with_decoy) / n_ret, 4) if n_ret else 1.0,
        "decoys_in_top_paths": with_decoy,
        "min_cut": cuts,
        "oracle_cut": sorted(oracle_cut),
        "evidence": check_evidence(db, org, out["timed"].evidence),
        "latency": latency_table(out["timed"]),
        "seeds": len(out["seeds"]),
        "top_path": [from_oracle_id(x) for x in returned[0]] if returned else [],
        "memory_mb": memory_usage_mb(db, org),
    }


def passes(s: dict) -> dict:
    rec = s["recall_by_difficulty"]
    return {
        "recall_easy_medium_1.0": all(
            rec[d]["recall"] == 1.0 for d in ("easy", "medium") if d in rec
        ),
        "min_cut_disconnects": all(
            c["disconnects_all_crown_jewels"] for c in s["min_cut"].values()
        ),
        "min_cut_le_oracle": all(c["size_le_oracle"] for c in s["min_cut"].values()),
        "evidence_100": s["evidence"]["validity"] == 1.0,
        "no_decoy_in_top_paths": s["decoys_in_top_paths"] == 0,
    }


# -------------------------------------------------------------- SCALE
def scale_check(db, scale: float, reps: int) -> dict:
    from reachable_orggen.build import generate_org
    from reachable_orggen.generate import GenConfig
    from reachable_orggen.load_falkordb import load_org

    name = "scale_org_a"
    t0 = time.perf_counter()
    ob = generate_org("org_a", get_settings().seed, GenConfig(scale=scale))
    gen_s = time.perf_counter() - t0
    ob.dataset.org = name
    t0 = time.perf_counter()
    stats = load_org(db, ob.dataset)
    load_s = time.perf_counter() - t0
    d = derive(db.select_graph(name))
    tools = GraphTools(db, allowed_orgs=[name])
    out = run_tools(name, tools, reps)
    lat = latency_table(out["timed"])
    slowest = sorted(lat.items(), key=lambda kv: -kv[1]["p95_ms"])[:3]
    result = {
        "graph": name,
        "scale": scale,
        "assets": stats["assets"],
        "nodes": stats["nodes"],
        "edges_before_derive": stats["edges"],
        "attack_steps": d["attack_steps"],
        "fix_tokens": d["fix_tokens"],
        "generate_s": round(gen_s, 1),
        "load_s": round(load_s, 1),
        "derive_s": d["seconds"],
        "memory_mb": memory_usage_mb(db, name),
        "min_cut_size": len(out["cuts"]["entry"].data["fix_tokens"]),
        "min_cut_disconnects": out["sims"]["entry"].data["all_crown_jewels_disconnected"],
        "paths_found": len(out["internet"].data["paths"]),
        "latency": lat,
        "slowest_3": [{"tool": k, **v} for k, v in slowest],
    }
    drop_graph(db, name)
    return result


# ---------------------------------------------------------------- MAIN
def to_markdown(report: dict) -> str:
    L = ["# Gate A - graph tools vs ground truth (no LLM)", ""]
    L += [
        f"Generated {report['generated']}. attack_paths budget k={K}. "
        f"Latency reps per tool: {report['reps']}.",
        "",
    ]
    L += [
        "## Verdict",
        "",
        "| org | " + " | ".join(next(iter(report["pass"].values()))) + " |",
        "|---|" + "---|" * len(next(iter(report["pass"].values()))),
    ]
    for org, p in report["pass"].items():
        L.append(f"| {org} | " + " | ".join("PASS" if v else "FAIL" for v in p.values()) + " |")
    L += ["", f"**Overall: {'PASS' if report['overall_pass'] else 'FAIL'}**", ""]

    L += [
        "## Planted-path recall and decoys",
        "",
        "| org | easy | medium | hard | hard (from seeds) | precision vs planted "
        "| decoy precision | decoys in top paths |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for org, s in report["orgs"].items():
        r = s["recall_by_difficulty"]

        def cell(d, r=r):
            return f"{r[d]['found']}/{r[d]['planted']} ({r[d]['recall']:.2f})" if d in r else "-"

        hard_seed = (
            f"{r['hard']['found_from_seeds']}/{r['hard']['planted']}" if "hard" in r else "-"
        )
        L.append(
            f"| {org} | {cell('easy')} | {cell('medium')} | {cell('hard')} | {hard_seed} | "
            f"{s['precision_vs_planted']:.2f} | {s['decoy_precision']:.2f} | "
            f"{s['decoys_in_top_paths']} |"
        )

    L += [
        "",
        "## min_cut vs oracle",
        "",
        "| org | prefer | size | max flow | oracle size | size <= oracle | same set as oracle "
        "| simulate_fix disconnects all |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for org, s in report["orgs"].items():
        for prefer, c in s["min_cut"].items():
            L.append(
                f"| {org} | {prefer} | {c['size']} | {c['max_flow']} | {c['oracle_size']} | "
                f"{c['size_le_oracle']} | {c['equals_oracle_set']} | "
                f"{c['disconnects_all_crown_jewels']} |"
            )

    L += [
        "",
        "## Evidence validity (separate Cypher pass)",
        "",
        "| org | nodes checked | edges checked | validity |",
        "|---|---|---|---|",
    ]
    for org, s in report["orgs"].items():
        e = s["evidence"]
        L.append(f"| {org} | {e['nodes_checked']} | {e['edges_checked']} | {e['validity']:.4f} |")

    L += ["", "## Latency (ms)", ""]
    tools_ = sorted({t for s in report["orgs"].values() for t in s["latency"]})
    L += [
        "| tool | " + " | ".join(f"{o} p50 / p95" for o in report["orgs"]) + " |",
        "|---|" + "---|" * len(report["orgs"]),
    ]
    for t in tools_:
        cells = []
        for s in report["orgs"].values():
            x = s["latency"].get(t)
            cells.append(f"{x['p50_ms']} / {x['p95_ms']}" if x else "-")
        L.append(f"| {t} | " + " | ".join(cells) + " |")

    if report.get("scale"):
        sc = report["scale"]
        L += [
            "",
            f"## Scale check (org_a x{sc['scale']})",
            "",
            f"- {sc['assets']} assets, {sc['nodes']} nodes, {sc['edges_before_derive']} edges "
            f"-> {sc['attack_steps']} ATTACK_STEP edges, {sc['fix_tokens']} fix tokens",
            f"- generate {sc['generate_s']} s, load {sc['load_s']} s, derive {sc['derive_s']} s",
            f"- GRAPH.MEMORY USAGE: {sc['memory_mb']} MB",
            f"- paths found {sc['paths_found']}, min_cut {sc['min_cut_size']} "
            f"(disconnects all: {sc['min_cut_disconnects']})",
            "",
            "Three slowest tools (p95):",
            "",
        ]
        for x in sc["slowest_3"]:
            L.append(f"- `{x['tool']}`: p50 {x['p50_ms']} ms, p95 {x['p95_ms']} ms")
    return "\n".join(L) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scale", type=float, default=0.0, help="also run the scale check at N")
    ap.add_argument("--reps", type=int, default=20)
    args = ap.parse_args()

    settings = get_settings()
    db = connect()
    tools = GraphTools(db)
    report: dict = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "reps": args.reps,
        "orgs": {},
        "pass": {},
    }
    for org in settings.orgs:
        out = run_tools(org, tools, args.reps)  # label-free
        labels = json.loads((settings.orgs_dir / org / "labels.json").read_text("utf-8"))
        s = score(org, out, labels, db)
        report["orgs"][org] = s
        report["pass"][org] = passes(s)
        print(org, json.dumps(report["pass"][org]))
    report["overall_pass"] = all(all(p.values()) for p in report["pass"].values())
    if args.scale:
        report["scale"] = scale_check(db, args.scale, max(5, args.reps // 2))
        print("scale", json.dumps({k: report["scale"][k] for k in ("memory_mb", "slowest_3")}))

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "gate_a.json").write_text(json.dumps(report, indent=2, default=str), "utf-8")
    (RESULTS / "gate_a.md").write_text(to_markdown(report), "utf-8")
    print(f"overall: {'PASS' if report['overall_pass'] else 'FAIL'} -> {RESULTS / 'gate_a.md'}")


if __name__ == "__main__":
    main()
