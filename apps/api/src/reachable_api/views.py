"""Read models the UI (S6) draws from: the findings board, a run's attack
subgraph shaped for Cytoscape, and a fix plan in either min-cut mode.

Everything here prefers what a finished run wrote to the graph (its
PathAnalysis paths, its FixPlan options), so a replayed run renders exactly
what the agents saw and decided, with no model call. Where a run did not
produce something (a Sentinel-only run, the fix plan mode it did not choose),
it falls back to the same read-only tools the agents call. Nothing here
writes.
"""

from __future__ import annotations

from reachable_graph.memory import MemoryRepo
from reachable_graph.tools import GraphTools, ToolError, describe_fix, label_of

# The graph view must never hang a projector: past these, paths are dropped
# (most likely first are kept) and the response says so.
MAX_NODES = 60
MAX_EDGES = 160
CONTEXT_NODES = 24  # one hop of context around a path, at most this many nodes
# The board: the scanner's own top of the list, and the unreachable twins of
# reachable CVEs, are capped so the board stays one screen.
NOISE_TOP = 8
TWINS_MAX = 6
EXPOSED_MAX = 4

KIND = {
    "Internet": "internet",
    "Asset": "asset",
    "Identity": "identity",
    "Secret": "secret",
    "DataStore": "datastore",
}
# Crown-jewel sensitivity tiers (S9), most sensitive first; "crown" is pre-S9 data.
TIER_ORDER = {"critical": 0, "crown": 0, "high": 1, "medium": 2, "low": 3}


def crown_jewels(tools: GraphTools, graph: str) -> dict[str, dict]:
    """Crown jewel id -> {name, tier}."""
    rows = _q(
        tools,
        graph,
        "MATCH (d:DataStore {crown_jewel: true}) "
        "RETURN d.id, coalesce(d.name, d.kind, d.id), d.sensitivity ORDER BY d.id",
    )
    return {i: {"name": n, "tier": t} for i, n, t in rows}


def top_tier(targets, crown: dict[str, dict]) -> str | None:
    """The most sensitive tier among `targets` (crown jewel ids), for the badge."""
    tiers = [crown[t]["tier"] for t in targets if t in crown and crown[t]["tier"]]
    return min(tiers, key=lambda t: TIER_ORDER.get(t, 9), default=None)


def _q(tools: GraphTools, graph: str, cypher: str, params: dict | None = None) -> list[list]:
    return tools._q(graph, cypher, params or {}, [])


# ------------------------------------------------------------------ run reads
def run_outputs(repo: MemoryRepo, graph: str, run_id: str) -> dict[str, dict]:
    out = {}
    for label in ("Drift", "Triage", "PathAnalysis", "FixPlan", "Report"):
        o = repo.read_output(graph, run_id, label)
        if o:
            out[label] = o["payload"]
    return out


def run_paths(tools: GraphTools, graph: str, outputs: dict, k: int = 20) -> list[dict]:
    """The run's attack paths (what the Pathfinder saw), else the live ones."""
    paths = (outputs.get("PathAnalysis") or {}).get("paths")
    if paths:
        return paths
    try:
        return tools.attack_paths(graph, k=k).data.get("paths", [])
    except ToolError:
        return []


def run_cuts(tools: GraphTools, graph: str, outputs: dict) -> dict[str, list[str]]:
    """Both minimum cuts: the run's FixPlan options, else min_cut in each mode."""
    opts = (outputs.get("FixPlan") or {}).get("options") or {}
    cuts = {m: list(o.get("fix_tokens") or []) for m, o in opts.items()}
    for mode in ("fewest", "cheapest"):
        if mode not in cuts:
            try:
                cuts[mode] = list(tools.min_cut(graph, mode=mode).data.get("fix_tokens") or [])
            except ToolError:
                cuts[mode] = []
    return cuts


# ------------------------------------------------------------- findings board
def _reach_reason(path_index: int, path: dict, finding: str, crown_names: dict) -> str:
    target = crown_names.get(path["target"], path["target"])
    for i, s in enumerate(path["steps"]):
        if s.get("fix_token") == finding:
            p = f"p={path['likelihood']:.3f}"
            if i == 0:
                return f"Starts path #{path_index + 1} to the {target} ({p})"
            return f"Hop {i + 1} of path #{path_index + 1} to the {target} ({p})"
    return f"On path #{path_index + 1} to the {target}"


def findings_board(
    tools: GraphTools, repo: MemoryRepo, graph: str, run_id: str | None = None
) -> dict:
    """The same findings in two orders: the scanner's (CVSS, then KEV, then EPSS)
    and Reachable's (what they let an attacker reach).

    The board is every finding on an Internet -> crown-jewel path, plus the
    findings a CVSS-first team would look at instead: the scanner's own top
    rows, other hosts with the same CVE as a reachable finding but no path, and
    Internet-facing criticals whose step leads nowhere or is mitigated. Each
    row says why it ranks where it does."""
    outputs = run_outputs(repo, graph, run_id) if run_id else {}
    paths = run_paths(tools, graph, outputs)
    jewels = crown_jewels(tools, graph)
    crown = {k: v["name"] for k, v in jewels.items()}

    # Every open finding, in the scanner's order: CVSS, then KEV, then EPSS.
    allf = _q(
        tools,
        graph,
        """
        MATCH (f:Finding {status: 'open'})-[:OF]->(v:Vuln)
        RETURN f.id, v.cvss, v.kev, v.epss, v.cve
        """,
    )
    allf.sort(key=lambda r: (-(r[1] or 0), -int(bool(r[2])), -(r[3] or 0), r[0]))
    scanner_rank = {r[0]: i + 1 for i, r in enumerate(allf)}

    # Reachable's order: the run's ranking if it made one, else the best path
    # likelihood each finding's step sits on.
    ranked = (outputs.get("PathAnalysis") or {}).get("ranked") or []
    on_path: dict[str, tuple[int, dict]] = {}
    for i, p in enumerate(paths):
        for s in p["steps"]:
            t = s.get("fix_token") or ""
            if label_of(t) == "Finding" and t not in on_path:
                on_path[t] = (i, p)
    if not ranked:
        best = sorted(on_path, key=lambda f: (-on_path[f][1]["likelihood"], on_path[f][0], f))
        ranked = [
            {"finding": f, "rank": n + 1, "score": round(on_path[f][1]["likelihood"], 4)}
            for n, f in enumerate(best)
        ]
    reach = {r["finding"]: r for r in ranked}

    reachable_cves = {r[4] for r in allf if r[0] in reach}
    twin_rows = [r[0] for r in allf if r[4] in reachable_cves and r[0] not in reach]
    noise = [r[0] for r in allf[:NOISE_TOP]]
    exposed = [
        r[0]
        for r in _q(
            tools,
            graph,
            """
            MATCH (:Internet)-[e:ATTACK_STEP]->(:Asset)
            WITH DISTINCT e.fix_token AS tok
            MATCH (f:Finding)-[:OF]->(v:Vuln)
            WHERE f.id = tok AND v.cvss >= 9.0 AND NOT f.id IN $reach
            RETURN DISTINCT f.id, v.cvss ORDER BY v.cvss DESC, f.id LIMIT $n
            """,
            {"reach": list(reach), "n": EXPOSED_MAX},
        )
    ]
    mitigated = [
        r[0]
        for r in _q(
            tools,
            graph,
            """
            MATCH (c:Control)-[m:MITIGATES]->(v:Vuln)<-[:OF]-(f:Finding {status: 'open'})
            MATCH (f)-[:ON]->(a:Asset)
            WHERE a.id = m.asset AND v.cvss >= 9.0
            RETURN DISTINCT f.id ORDER BY f.id LIMIT $n
            """,
            {"n": EXPOSED_MAX},
        )
    ]
    # Same CVE as a reachable finding, but no path: one per zone first, so an
    # isolated zone's copy shows up next to the edge ones.
    twin_zone = dict(
        _q(
            tools,
            graph,
            "MATCH (f:Finding)-[:ON]->(a:Asset) WHERE f.id IN $ids RETURN f.id, a.zone",
            {"ids": twin_rows[:200]},
        )
    )
    twins, seen = [], set()
    for f in twin_rows[:200]:
        if twin_zone.get(f) not in seen:
            seen.add(twin_zone.get(f))
            twins.append(f)
    twins += [f for f in twin_rows if f not in twins][: max(0, TWINS_MAX - len(twins))]
    twins = twins[:TWINS_MAX]
    ids = list(dict.fromkeys([*reach, *noise, *twins, *exposed, *mitigated]))

    detail = {
        r[0]: r
        for r in _q(
            tools,
            graph,
            """
            MATCH (f:Finding) WHERE f.id IN $ids
            MATCH (f)-[:ON]->(a:Asset), (f)-[:OF]->(v:Vuln)
            RETURN f.id, a.id, a.hostname, v.cve, v.cvss, v.epss, v.kev, a.zone
            """,
            {"ids": ids},
        )
    }
    steps = {
        r[0]: (r[1], r[2])
        for r in _q(
            tools,
            graph,
            """
            MATCH (a)-[e:ATTACK_STEP]->() WHERE e.fix_token IN $ids
            RETURN e.fix_token, count(e), sum(CASE WHEN a:Internet THEN 1 ELSE 0 END)
            """,
            {"ids": ids},
        )
    }
    mitigated_by = {
        r[0]: r[1]
        for r in _q(
            tools,
            graph,
            """
            MATCH (f:Finding) WHERE f.id IN $ids
            MATCH (f)-[:OF]->(v:Vuln)<-[m:MITIGATES]-(c:Control), (f)-[:ON]->(a:Asset)
            WHERE m.asset = a.id
            RETURN f.id, toUpper(coalesce(c.name, c.kind, c.id))
            """,
            {"ids": ids},
        )
    }
    triage = outputs.get("Triage") or {}
    suppressed = {s["finding"]: s for s in triage.get("suppressed", [])}
    verdicts = {
        v["finding"]: v.get("decision") for v in (outputs.get("Report") or {}).get("verdicts", [])
    }

    rows = []
    for fid in ids:
        d = detail.get(fid)
        if not d:
            continue
        _, asset, host, cve, cvss, epss, kev, zone = d
        zone = (zone or "").rsplit(":", 1)[-1] or None
        n_steps, n_inet = steps.get(fid, (0, 0))
        r = reach.get(fid)
        if r:
            pi, p = on_path[fid] if fid in on_path else (r.get("path_index", 0), None)
            why = _reach_reason(pi, p, fid, crown) if p else (r.get("why") or "On a crown path")
            status = "reachable"
            targets = sorted({p["target"]} if p else set(r.get("targets") or []))
        else:
            targets = []
            if fid in suppressed:
                s = suppressed[fid]
                why, status = (
                    f"Accepted risk until {s.get('expires_date')} ({s.get('approved_by')})",
                    "accepted",
                )
            elif fid in mitigated_by:
                why, status = f"Mitigated by {mitigated_by[fid]}: no attack step", "mitigated"
            elif n_inet:
                why, status = "Reachable from the Internet, but leads to no crown jewel", "dead_end"
            elif n_steps:
                why, status = "An internal hop on no crown-jewel path", "internal"
            else:
                where = f" (zone: {zone})" if zone else ""
                why = f"Not reachable: nothing an attacker can hold leads here{where}"
                status = "unreachable"
        rows.append(
            {
                "finding": fid,
                "asset": asset,
                "hostname": host,
                "cve": cve,
                "cvss": cvss,
                "epss": epss,
                "kev": bool(kev),
                "zone": zone,
                "scanner_rank": scanner_rank.get(fid),
                "reach_rank": r["rank"] if r else None,
                "score": r.get("score") if r else None,
                "status": status,
                "why": why,
                "targets": targets,
                "target_tier": top_tier(targets, jewels),
                "attack_steps": n_steps,
                "verdict": verdicts.get(fid),
                "headline": None,
            }
        )

    # The headline pair: the row that tops Reachable's order, next to the
    # highest-CVSS row that reaches nothing. Among equals, prefer a copy of a
    # reachable CVE sitting in a different zone than its reachable twin: same
    # bug, different place, different answer.
    unreach = [x for x in rows if x["status"] == "unreachable"] or [
        x for x in rows if x["status"] not in ("reachable", "accepted")
    ]
    top = min((x for x in rows if x["reach_rank"]), key=lambda x: x["reach_rank"], default=None)
    if top:
        top["headline"] = "reachable"
        reach_zone = {x["cve"]: x["zone"] for x in rows if x["status"] == "reachable"}
        same_cve = [x for x in unreach if x["cve"] in reachable_cves]
        pick = max(
            same_cve or unreach,
            key=lambda x: (x["cvss"] or 0, x["kev"], x["zone"] != reach_zone.get(x["cve"])),
            default=None,
        )
        if pick:
            pick["headline"] = "unreachable"

    by_sev = sorted(rows, key=lambda x: x["scanner_rank"] or 10**9)
    by_reach = sorted(
        rows,
        key=lambda x: (
            x["reach_rank"] is None,
            x["reach_rank"] or 0,
            x["scanner_rank"] or 10**9,
        ),
    )
    return {
        "graph": graph,
        "run_id": run_id,
        "source": "run" if outputs.get("PathAnalysis") else "live",
        "total_open": len(allf),
        "on_crown_path": len(reach),
        "crown_jewels": [{"id": k, **v} for k, v in jewels.items()],
        "by_severity": [x["finding"] for x in by_sev],
        "by_reachability": [x["finding"] for x in by_reach],
        "findings": {x["finding"]: x for x in rows},
    }


# ---------------------------------------------------------------- subgraph
def _node_props(tools: GraphTools, graph: str, ids: list[str]) -> dict[str, dict]:
    real = [i for i in ids if i != "internet"]
    return {k: v["props"] for k, v in tools._nodes(graph, real, []).items()}


def subgraph(
    tools: GraphTools,
    repo: MemoryRepo,
    graph: str,
    run_id: str,
    *,
    finding: str | None = None,
    target: str | None = None,
    context: bool = False,
    max_nodes: int = MAX_NODES,
) -> dict:
    """The run's attack paths and both min cuts, as Cytoscape elements.

    Nodes carry their kind (internet / asset / identity / secret / datastore),
    a label, whether they are a crown jewel, and which paths cross them. Edges
    are ATTACK_STEPs keyed by step key, labelled with the ATT&CK technique,
    and flagged when their fix token is in the fewest / cheapest cut. A fix
    token that removes steps on more than one path is the "one fix, many
    paths" convergence; `shared` counts the paths through a node or edge.

    finding / target narrow it to the paths through that finding or to that
    crown jewel. Paths are kept most likely first until max_nodes; context
    adds one ATTACK_STEP hop around the kept paths (capped), for a path that
    needs its neighbourhood to make sense."""
    outputs = run_outputs(repo, graph, run_id)
    paths = run_paths(tools, graph, outputs)
    total_paths = len(paths)
    indexed = list(enumerate(paths))
    if finding:
        indexed = [
            (i, p)
            for i, p in indexed
            if any(s.get("fix_token") == finding or finding in s["key"] for s in p["steps"])
        ]
    if target:
        indexed = [(i, p) for i, p in indexed if p["target"] == target]
    cuts = run_cuts(tools, graph, outputs)
    chosen = (outputs.get("FixPlan") or {}).get("chosen")
    drift = outputs.get("Drift") or {}
    new_steps = {k for np in drift.get("new_paths", []) for k in np.get("new_steps", [])}
    new_nodes = {k for np in drift.get("new_paths", []) for k in np.get("new_nodes", [])}

    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}
    kept, truncated = [], False
    for i, p in indexed:
        ids = [n["id"] for n in p["nodes"]]
        fresh = [x for x in ids if x not in nodes]
        if len(nodes) + len(fresh) > max_nodes or len(edges) + len(p["steps"]) > MAX_EDGES:
            truncated = True
            if kept:
                break
            continue  # a single huge path: skip it and try the next
        kept.append(i)
        for n in p["nodes"]:
            node = nodes.setdefault(
                n["id"], {"id": n["id"], "name": n.get("name") or n["id"], "paths": []}
            )
            node["paths"].append(i)
        for j, s in enumerate(p["steps"]):
            e = edges.setdefault(
                s["key"],
                {
                    "id": s["key"],
                    "source": ids[j],
                    "target": ids[j + 1],
                    "technique": s.get("technique"),
                    "rule": s.get("rule"),
                    "likelihood": s.get("likelihood"),
                    "fix_token": s.get("fix_token"),
                    "paths": [],
                    "hop": j,
                },
            )
            e["paths"].append(i)

    if context and nodes:
        rows = _q(
            tools,
            graph,
            """
            MATCH (a)-[e:ATTACK_STEP]->(b)
            WHERE a.id IN $ids OR b.id IN $ids
            RETURN a.id, b.id, e.key, e.technique, e.rule, e.likelihood, e.fix_token,
                   coalesce(a.hostname, a.name, a.kind, a.id),
                   coalesce(b.hostname, b.name, b.kind, b.id)
            LIMIT 400
            """,
            {"ids": list(nodes)},
        )
        added = 0
        for a, b, key, tech, rule, lk, tok, an, bn in rows:
            if key in edges:
                continue
            for nid, name in ((a, an), (b, bn)):
                if nid not in nodes:
                    if added >= CONTEXT_NODES or len(nodes) >= max_nodes + CONTEXT_NODES:
                        break
                    nodes[nid] = {"id": nid, "name": name, "paths": [], "context": True}
                    added += 1
            if a in nodes and b in nodes and len(edges) < MAX_EDGES + CONTEXT_NODES:
                edges[key] = {
                    "id": key,
                    "source": a,
                    "target": b,
                    "technique": tech,
                    "rule": rule,
                    "likelihood": lk,
                    "fix_token": tok,
                    "paths": [],
                    "context": True,
                }

    props = _node_props(tools, graph, list(nodes))
    paths_per_token: dict[str, set[int]] = {}
    for e in edges.values():
        if e["fix_token"]:
            paths_per_token.setdefault(e["fix_token"], set()).update(e["paths"])
    for n in nodes.values():
        label = label_of(n["id"]) or "Asset"
        pr = props.get(n["id"], {})
        crown = bool(pr.get("crown_jewel"))
        n.update(
            kind=KIND.get(label, "asset"),
            crown=crown,
            tier=pr.get("sensitivity") if crown else None,
            sub=pr.get("kind") or pr.get("zone") or pr.get("sensitivity"),
            shared=len(set(n["paths"])),
            new=n["id"] in new_nodes,
            entry=False,
        )
    for e in edges.values():
        tok = e["fix_token"]
        e.update(
            in_fewest=tok in cuts.get("fewest", []),
            in_cheapest=tok in cuts.get("cheapest", []),
            shared=len(set(e["paths"])),
            token_paths=len(paths_per_token.get(tok, ())),
            new=e["id"] in new_steps,
        )
        if e["source"] == "internet":
            nodes[e["target"]]["entry"] = True

    kept_paths = [
        {
            "index": i,
            "target": paths[i]["target"],
            "likelihood": paths[i]["likelihood"],
            "nodes": [n["id"] for n in paths[i]["nodes"]],
            "steps": [s["key"] for s in paths[i]["steps"]],
        }
        for i in kept
    ]
    return {
        "graph": graph,
        "run_id": run_id,
        "source": "run" if outputs.get("PathAnalysis") else "live",
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "paths": kept_paths,
        "total_paths": total_paths,
        "truncated": truncated,
        "cuts": cuts,
        "chosen": chosen,
        "caps": {"max_nodes": max_nodes, "max_edges": MAX_EDGES, "context_nodes": CONTEXT_NODES},
    }


# ---------------------------------------------------------------- fix plans
def _template_ticket(fix: dict) -> dict:
    where = fix.get("hostname") or fix.get("asset") or "the affected identity"
    team = (fix.get("team") or {}).get("name") or "The owning team"
    title = (
        f"Patch {fix['cve']} on {where}" if fix.get("cve") else fix["action"].split(" (")[0][:90]
    )
    body = f"{team}: {fix['action']}. This removes an attack step on a crown-jewel path."
    if fix.get("adrs"):
        a = fix["adrs"][-1]
        body += f" Exposure opened by {a['title']} (approved by {a['approved_by']})."
    return {"title": title, "body": body, "by": "template"}


def fix_plan(
    tools: GraphTools,
    repo: MemoryRepo,
    graph: str,
    run_id: str,
    mode: str,
) -> dict:
    """One fix set (fewest or cheapest) with owners, on-call, the ADR that opened
    the exposure and a drafted ticket per fix. The mode the run chose comes back
    exactly as the Fixer wrote it (its tickets are the model's); the other mode
    is built from the same read-only tools, with template tickets."""
    if mode not in ("fewest", "cheapest"):
        raise ToolError("mode must be fewest or cheapest")
    outputs = run_outputs(repo, graph, run_id)
    fp = outputs.get("FixPlan") or {}
    paths = run_paths(tools, graph, outputs)
    tokens = run_cuts(tools, graph, outputs).get(mode, [])
    reach_before = sorted({p["target"] for p in paths})
    if fp.get("chosen") == mode and fp.get("fixes"):
        fixes = [dict(f) for f in fp["fixes"]]
        source = "run"
    else:
        mc = tools.min_cut(graph, mode=mode).data
        by_token = {f["token"]: f for f in mc.get("fixes", [])}
        as_of = (repo.scan_info(graph) or {}).get("ts")
        fixes = []
        for t in tokens:
            f = dict(by_token.get(t) or describe_fix(t))
            asset = f.get("asset")
            if asset:
                try:
                    own = tools.owners(graph, asset, as_of).data
                    team = next(iter(own.get("teams") or []), None)
                    f["team"] = {"id": team["id"], "name": team["name"]} if team else None
                    f["on_call"] = (team or {}).get("on_call")
                except ToolError:
                    f["team"], f["on_call"] = None, None
                try:
                    dt = tools.decision_trail(graph, asset).data
                    f["adrs"] = [
                        {
                            "adr": d["adr"],
                            "title": d["title"],
                            "approved_by": d["approved_by"]["name"],
                            "role": d["approved_by"]["role"],
                            "date": d["date"],
                        }
                        for d in dt.get("decisions", [])
                    ]
                except ToolError:
                    f["adrs"] = []
            f.setdefault("adrs", [])
            f["ticket"] = _template_ticket(f)
            fixes.append(f)
        source = "tools"
    # How many of the run's paths each fix cuts ("one fix, many paths"), and the
    # crown jewels those paths reach, with the most sensitive tier among them.
    jewels = crown_jewels(tools, graph)
    for f in fixes:
        cut = [p for p in paths if any(s.get("fix_token") == f["token"] for s in p["steps"])]
        f["paths_cut"] = len(cut)
        f["targets"] = sorted({p["target"] for p in cut})
        f["target_tier"] = top_tier(f["targets"], jewels)
    return {
        "graph": graph,
        "run_id": run_id,
        "mode": mode,
        "chosen": fp.get("chosen"),
        "source": source,
        "fix_tokens": tokens,
        "total_effort": sum(int(f.get("effort") or 0) for f in fixes),
        "verified": fp.get("verified") if fp.get("chosen") == mode else None,
        "rationale": fp.get("rationale") if fp.get("chosen") == mode else None,
        "fixes": fixes,
        "paths": len(paths),
        "reachable_before": reach_before,
        "crown_jewels": [{"id": k, **v} for k, v in jewels.items()],
    }
