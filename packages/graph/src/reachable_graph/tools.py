"""The typed, read-only Cypher tool library over the ATTACK_STEP layer.

Every tool:
  * validates `org` against an allowlist and its other inputs with Pydantic
    (bounds = the caps; a request outside them never reaches the database);
  * runs its Cypher through GRAPH.RO_QUERY with a timeout, so the server itself
    refuses any write (simulate_fix is the one exception: it writes only to a
    throwaway GRAPH.COPY of the org, never to the org graph);
  * returns a ToolResult: a one-line summary, structured data, the Evidence
    (node ids / edges / paths that back the answer, all of which exist in the
    graph), every query it ran with params and timing, and a truncated flag.

Tool names are the contract for later sessions (the MCP server and the agent).
"""

from __future__ import annotations

import logging
import math
import re
import time
import uuid
from collections import deque
from typing import Any

from falkordb import Edge, Node, Path

from reachable_core.attack_rules import (
    HOP_CAP,
    NETWORK_VECTORS,
    PRIVESC_MIN_CVSS,
    RULES,
    VulnSignals,
    exploit_likelihood,
)
from reachable_core.db import connect
from reachable_core.schema import THREATINTEL_GRAPH, severity_band
from reachable_core.settings import get_settings

from . import memory
from .company_tools import CompanyToolsMixin, _day
from .models import (
    MAX_BFS_NODES,
    MAX_ROWS,
    QUERY_TIMEOUT_MS,
    AttackPathsInput,
    BlastRadiusInput,
    ChokePointsInput,
    EdgeRef,
    Evidence,
    ExposureInput,
    MinCutInput,
    PlaybooksInput,
    QueryLog,
    RunCypherInput,
    ScanFindingsInput,
    SimulateFixInput,
    ToolResult,
    TriageMemoryInput,
    VulnIntelInput,
    WhyStepInput,
)

log = logging.getLogger("reachable.tools")

SCRATCH_PREFIX = "scratch__"
# scan_findings(view="triage"): Internet-facing findings OFF any crown path get a
# count and this many rows, no more (they are what triage deprioritises).
TRIAGE_OTHERS = 5

# Our node ids look like "<org>:<kind>:<n>"; the kind tells us the label, which
# lets every lookup be an index seek on (:Label {id}) instead of a full scan.
_KIND_LABEL = {
    "asset": "Asset",
    "sw": "Software",
    "vuln": "Vuln",
    "finding": "Finding",
    "ident": "Identity",
    "secret": "Secret",
    "ds": "DataStore",
    "control": "Control",
    "zone": "Zone",
    "scan": "Scan",
    # company layer
    "person": "Person",
    "team": "Team",
    "oncall": "OnCall",
    "adr": "ADR",
    "ticket": "Ticket",
    # memory layer
    "run": "Run",
    "step": "AgentStep",
    "triage": "Triage",
    "verdict": "Verdict",
    "riskacc": "RiskAcceptance",
    "pattern": "Pattern",
    "playbook": "Playbook",
}
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
# Labels the attack layer runs between (helper labels are hidden from output).
ATTACK_LABELS = {"Internet", "Asset", "Identity", "Secret", "DataStore"}
_HIDDEN_LABELS = {"CrownPath"}


class ToolError(ValueError):
    """A request the tools refuse (unknown org, unknown node, bad query)."""


def label_of(node_id: str) -> str | None:
    if node_id == "internet":
        return "Internet"
    if node_id.startswith("fix_in:"):
        return "FixIn"
    if node_id.startswith("fix_out:"):
        return "FixOut"
    if _TECHNIQUE_RE.match(node_id):  # org-local Technique anchor for playbooks
        return "Technique"
    parts = node_id.split(":")
    return _KIND_LABEL.get(parts[1]) if len(parts) >= 3 else None


def _split_pair(rest: str) -> tuple[str, str]:
    """'org_a:asset:1:org_a:secret:2' -> ('org_a:asset:1', 'org_a:secret:2')."""
    p = rest.split(":")
    return ":".join(p[:3]), ":".join(p[3:])


def describe_fix(token: str) -> dict:
    """What a defender actually does to apply a fix token."""
    if not token.startswith("step:"):
        return {"token": token, "kind": "finding", "action": f"Patch or mitigate finding {token}"}
    kind, _, rest = token[len("step:") :].partition(":")
    a, b = _split_pair(rest)
    action = {
        "creds": f"Remove or vault secret {b} stored on {a}",
        "ssh": f"Rotate SSH key {a}; remove it from {b}'s authorized keys",
        "db": f"Rotate DB password {a}; restrict who can log in to {b}",
        "usekey": f"Revoke cloud key {a} (it logs in as {b})",
        "imds": f"Detach role {b} from {a}, or block instance-metadata access",
        "assume": f"Remove {a}'s permission to assume {b}",
        "read": f"Remove {a}'s read permission on {b}",
    }.get(kind, f"Remove step {token}")
    return {"token": token, "kind": kind, "action": action, "from": a, "to": b}


def _clean_labels(labels: list[str]) -> list[str]:
    return [lbl for lbl in labels if lbl not in _HIDDEN_LABELS]


# Projection shared by every query that returns ATTACK_STEP paths.
_PATH_PROJECTION = """
[n IN nodes(path) | {id: n.id, labels: labels(n),
                     name: coalesce(n.hostname, n.name, n.kind, n.id)}] AS nodes,
[e IN relationships(path) | {key: e.key, rule: e.rule, technique: e.technique,
                             likelihood: e.likelihood, fix_token: e.fix_token}] AS steps
"""


class GraphTools(CompanyToolsMixin):
    """The tool library, bound to one FalkorDB connection and an org allowlist.

    The company-layer tools (owners, decision_trail, company_query) live in
    company_tools.py and share this class's read-only query path."""

    def __init__(
        self,
        db=None,
        *,
        allowed_orgs: list[str] | None = None,
        threatintel_graph: str = THREATINTEL_GRAPH,
        timeout_ms: int = QUERY_TIMEOUT_MS,
    ) -> None:
        self.db = db or connect()
        self.allowed = set(allowed_orgs or get_settings().graphs)
        self.threatintel = threatintel_graph
        self.timeout_ms = timeout_ms

    # ------------------------------------------------------------------ core
    def _org(self, org: str) -> str:
        if org not in self.allowed:
            raise ToolError(f"unknown org {org!r}; allowed: {sorted(self.allowed)}")
        return org

    def _q(self, graph: str, cypher: str, params: dict | None, qlog: list[QueryLog]) -> list[list]:
        """Run one read-only query and record it. All tool reads go through here."""
        params = params or {}
        t = time.perf_counter()
        res = self.db.select_graph(graph).ro_query(cypher, params, timeout=self.timeout_ms)
        ms = round((time.perf_counter() - t) * 1000, 2)
        qlog.append(QueryLog(graph=graph, cypher=_squash(cypher), params=params, ms=ms))
        return res.result_set

    def _scratch_write(self, graph: str, cypher: str, params: dict, qlog: list[QueryLog]) -> None:
        """The ONLY write path: refuses anything but a scratch copy."""
        if not graph.startswith(SCRATCH_PREFIX):
            raise ToolError(f"refusing to write to non-scratch graph {graph!r}")
        t = time.perf_counter()
        self.db.select_graph(graph).query(cypher, params, timeout=self.timeout_ms)
        ms = round((time.perf_counter() - t) * 1000, 2)
        qlog.append(QueryLog(graph=graph, cypher=_squash(cypher), params=params, ms=ms))

    def _node(self, graph: str, node_id: str, qlog: list[QueryLog]) -> dict:
        label = label_of(node_id)
        if label is None:
            raise ToolError(f"cannot resolve a label for node id {node_id!r}")
        rows = self._q(
            graph,
            f"MATCH (n:{label} {{id: $id}}) RETURN labels(n), properties(n)",
            {"id": node_id},
            qlog,
        )
        if not rows:
            raise ToolError(f"no node {node_id!r} in {graph}")
        return {"id": node_id, "labels": _clean_labels(rows[0][0]), "props": dict(rows[0][1])}

    def _nodes(self, graph: str, ids: list[str], qlog: list[QueryLog]) -> dict[str, dict]:
        """Resolve many ids, one index-backed lookup per label.

        FalkorDB gotcha: `UNWIND $ids AS x MATCH (n:L {id: x})` is NOT an index
        seek (the planner scans and filters). `MATCH (n:L) WHERE n.id IN $ids`
        is an index scan, ~10x faster here. Every id-list lookup uses that form.
        """
        by_label: dict[str, list[str]] = {}
        for i in dict.fromkeys(ids):
            lbl = label_of(i)
            if lbl:
                by_label.setdefault(lbl, []).append(i)
        out: dict[str, dict] = {}
        for lbl, chunk in by_label.items():
            rows = self._q(
                graph,
                f"MATCH (n:{lbl}) WHERE n.id IN $ids RETURN n.id, labels(n), properties(n)",
                {"ids": chunk},
                qlog,
            )
            for nid, labels, props in rows:
                out[nid] = {"id": nid, "labels": _clean_labels(labels), "props": dict(props)}
        return out

    # ===================================================== exposure_surface
    def exposure_surface(self, org: str, limit: int = 50) -> ToolResult:
        """Internet-exposed assets and the exploitable vulns on them."""
        inp = ExposureInput(org=org, limit=limit)
        g, qlog = self._org(inp.org), []
        # Two FalkorDB gotchas shape this query:
        #  * (f:Finding {id: e.fix_token}) fails with "'e' not defined": an inline
        #    property map can't use a variable bound in the same pattern -> WHERE.
        #  * after a WITH ... collect(), `OPTIONAL MATCH ... WHERE m.asset = a.id
        #    AND bv.av IN $vectors` silently drops the matching rows; so the vector
        #    test moves into the CASE inside collect().
        rows = self._q(
            g,
            """
            MATCH (i:Internet)-[x:EXPOSES]->(a:Asset)
            WITH i, a, collect(DISTINCT x.port) AS ports
            OPTIONAL MATCH (i)-[e:ATTACK_STEP]->(a)<-[:ON]-(f:Finding)-[:OF]->(v:Vuln)
            WHERE f.id = e.fix_token
            WITH a, ports, collect(CASE WHEN e IS NULL THEN NULL ELSE
                 {key: e.key, finding: f.id, vuln: v.id, cve: v.cve, cvss: v.cvss,
                  epss: v.epss, kev: v.kev, likelihood: e.likelihood} END) AS exploitable
            OPTIONAL MATCH (a)-[:RUNS]->(:Software)-[:HAS_VULN]->(bv:Vuln)
                           <-[m:MITIGATES]-(c:Control)
            WHERE m.asset = a.id
            WITH a, ports, exploitable,
                 collect(DISTINCT CASE WHEN c IS NULL OR NOT bv.av IN $network_vectors
                 THEN NULL ELSE
                 {vuln: bv.id, cve: bv.cve, cvss: bv.cvss, control: c.id, control_kind: c.kind}
                 END) AS blocked
            RETURN a.id, a.hostname, a.kind, a.zone, ports, exploitable, blocked
            ORDER BY size(exploitable) DESC, a.id
            LIMIT $limit
            """,
            {"network_vectors": sorted(NETWORK_VECTORS), "limit": inp.limit + 1},
            qlog,
        )
        truncated = len(rows) > inp.limit
        rows = rows[: inp.limit]
        assets, ev = [], Evidence()
        for aid, host, kind, zone, ports, exploitable, blocked in rows:
            exploitable = sorted(exploitable, key=lambda x: -x["likelihood"])
            assets.append(
                {
                    "asset": aid,
                    "hostname": host,
                    "kind": kind,
                    "zone": zone,
                    "ports": sorted(ports),
                    "exploitable": exploitable,
                    "blocked_by_control": blocked,
                }
            )
            ev.node_ids.append(aid)
            ev.edges.append(EdgeRef(src="internet", rel="EXPOSES", dst=aid))
            for x in exploitable:
                ev.node_ids += [x["finding"], x["vuln"]]
                ev.edges.append(EdgeRef(src="internet", rel="ATTACK_STEP", dst=aid, key=x["key"]))
            for b in blocked:
                ev.node_ids += [b["vuln"], b["control"]]
                ev.edges.append(EdgeRef(src=b["control"], rel="MITIGATES", dst=b["vuln"]))
        ev.node_ids = list(dict.fromkeys(["internet", *ev.node_ids]))
        n_expl = sum(1 for a in assets if a["exploitable"])
        n_steps = sum(len(a["exploitable"]) for a in assets)
        n_blocked = sum(1 for a in assets if a["blocked_by_control"] and not a["exploitable"])
        summary = (
            f"{len(assets)} internet-exposed assets{'+' if truncated else ''}; "
            f"{n_expl} have exploitable network vulns ({n_steps} exploit steps); "
            f"{n_blocked} are exposed but fully blocked by a control."
        )
        return ToolResult(
            summary=summary,
            data={"assets": assets},
            evidence=ev,
            queries=qlog,
            truncated=truncated,
        )

    # ========================================================= attack_paths
    def attack_paths(
        self,
        org: str,
        target_id: str | None = None,
        k: int = 5,
        source_id: str | None = None,
        max_hops: int = HOP_CAP,
    ) -> ToolResult:
        """Top-k most likely paths (weighted shortest by cost = -ln likelihood)."""
        inp = AttackPathsInput(
            org=org, target_id=target_id, k=k, source_id=source_id, max_hops=max_hops
        )
        g, qlog = self._org(inp.org), []
        paths, truncated = self._paths(g, inp, qlog)
        return self._paths_result(g, inp, paths, truncated, qlog)

    def _paths(self, graph: str, inp: AttackPathsInput, qlog: list[QueryLog]):
        source = inp.source_id or "internet"
        src_label = label_of(source)
        if src_label not in ATTACK_LABELS:
            raise ToolError(f"{source!r} is not an attack-state node")
        if inp.target_id:
            t_label = label_of(inp.target_id)
            if t_label not in ATTACK_LABELS:
                raise ToolError(f"{inp.target_id!r} is not an attack-state node")
            target_match = f"MATCH (t:{t_label} {{id: $target}})"
        else:
            target_match = "MATCH (t:DataStore {crown_jewel: true})"
        rows = self._q(
            graph,
            f"""
            MATCH (s:{src_label} {{id: $source}})
            {target_match}
            CALL algo.SPpaths({{sourceNode: s, targetNode: t, relTypes: ['ATTACK_STEP'],
                               weightProp: 'cost', pathCount: $k, maxLen: $max_hops}})
            YIELD path, pathWeight
            RETURN t.id AS target, pathWeight, {_PATH_PROJECTION}
            ORDER BY pathWeight ASC, target
            """,
            {"source": source, "target": inp.target_id, "k": inp.k, "max_hops": inp.max_hops},
            qlog,
        )
        per_target: dict[str, int] = {}
        paths = []
        for target, weight, nodes, steps in rows:
            per_target[target] = per_target.get(target, 0) + 1
            paths.append(
                {
                    "target": target,
                    "likelihood": math.exp(-weight),
                    "cost": weight,
                    "nodes": [{**n, "labels": _clean_labels(n["labels"])} for n in nodes],
                    "steps": steps,
                }
            )
        # SPpaths returns at most k per target; hitting k means more may exist.
        truncated = len(paths) > inp.k or any(c >= inp.k for c in per_target.values())
        return paths[: inp.k], truncated

    def _paths_result(self, graph, inp, paths, truncated, qlog) -> ToolResult:
        ev = Evidence()
        for p in paths:
            ids = [n["id"] for n in p["nodes"]]
            ev.paths.append(ids)
            ev.node_ids += ids
            for i, s in enumerate(p["steps"]):
                ev.edges.append(
                    EdgeRef(src=ids[i], rel="ATTACK_STEP", dst=ids[i + 1], key=s["key"])
                )
        ev.node_ids = list(dict.fromkeys(ev.node_ids))
        if paths:
            best = paths[0]
            hops = " -> ".join(n["name"] for n in best["nodes"])
            summary = (
                f"{len(paths)} path(s) to {len({p['target'] for p in paths})} target(s); "
                f"most likely (p={best['likelihood']:.3f}, {len(best['steps'])} steps): {hops}"
            )
        else:
            summary = "No attack path within the hop limit."
        return ToolResult(
            summary=summary,
            data={"paths": paths, "source": inp.source_id or "internet"},
            evidence=ev,
            queries=qlog,
            truncated=truncated,
        )

    # ========================================================= blast_radius
    def blast_radius(self, org: str, asset_id: str, max_depth: int = HOP_CAP) -> ToolResult:
        """Everything reachable over ATTACK_STEP from a compromised node (algo.bfs)."""
        inp = BlastRadiusInput(org=org, asset_id=asset_id, max_depth=max_depth)
        g, qlog = self._org(inp.org), []
        label = label_of(inp.asset_id)
        if label not in ATTACK_LABELS - {"Internet"}:
            raise ToolError(f"{inp.asset_id!r} is not an Asset/Identity/Secret/DataStore id")
        rows = self._q(
            g,
            f"""
            MATCH (a:{label} {{id: $id}})
            CALL algo.bfs(a, $depth, 'ATTACK_STEP') YIELD nodes, edges
            RETURN [n IN nodes | {{id: n.id, labels: labels(n),
                                   crown: coalesce(n.crown_jewel, false),
                                   sensitivity: n.sensitivity}}],
                   [e IN edges | {{src: startNode(e).id, dst: endNode(e).id,
                                   key: e.key, rule: e.rule, fix_token: e.fix_token}}]
            """,
            {"id": inp.asset_id, "depth": inp.max_depth},
            qlog,
        )
        if rows:
            nodes, edges = rows[0]
        else:  # algo.bfs yields no row when the start has no outgoing step
            self._node(g, inp.asset_id, qlog)  # raises if the node doesn't exist
            nodes, edges = [], []
        truncated = len(nodes) > MAX_BFS_NODES
        nodes = nodes[:MAX_BFS_NODES]
        kept = {n["id"] for n in nodes} | {inp.asset_id}
        edges = [e for e in edges if e["src"] in kept and e["dst"] in kept]
        by_label: dict[str, int] = {}
        for n in nodes:
            n["labels"] = _clean_labels(n["labels"])
            for lbl in n["labels"]:
                if lbl in ATTACK_LABELS:
                    by_label[lbl] = by_label.get(lbl, 0) + 1
        crown = [n["id"] for n in nodes if n["crown"]]
        stores = [n["id"] for n in nodes if "DataStore" in n["labels"]]
        ev = Evidence(
            node_ids=[inp.asset_id, *[n["id"] for n in nodes]],
            edges=[
                EdgeRef(src=e["src"], rel="ATTACK_STEP", dst=e["dst"], key=e["key"]) for e in edges
            ],
        )
        summary = (
            f"From {inp.asset_id} an attacker reaches {len(nodes)} node(s) "
            f"{by_label} within {inp.max_depth} steps; "
            + (f"CROWN JEWELS reached: {crown}." if crown else "no crown jewel reached.")
        )
        return ToolResult(
            summary=summary,
            data={
                "start": inp.asset_id,
                "reached": nodes,
                "counts": by_label,
                "datastores": stores,
                "crown_jewels": crown,
                "edges": edges,
            },
            evidence=ev,
            queries=qlog,
            truncated=truncated,
        )

    # ============================================================== min_cut
    def min_cut(
        self,
        org: str,
        target_ids: list[str] | None = None,
        prefer: str = "entry",
        mode: str = "fewest",
    ) -> ToolResult:
        """Minimum set of fix tokens disconnecting the Internet from the targets.

        mode="fewest" uses capacity 1 per fix gate (`cap`): the cut has the fewest
        fixes. mode="cheapest" uses the gate's `effort` (1-5, stamped by derive) as
        capacity: the cut has the lowest total effort. Same algorithm, different
        capacity property; the max-flow value is then |cut| or total effort.

        1. algo.maxFlow on the node-split FLOW layer gives the max-flow value and
           the flow on every edge carrying flow. It does NOT return the cut.
        2. We recover the cut: the residual graph has a forward arc u->v where
           flow < capacity and a backward arc v->u where flow > 0. S = nodes
           reachable from the Internet in it. The min cut is every unit fix edge
           FixIn(t) -> FixOut(t) with FixIn in S and FixOut not in S.
        3. Self-check (max-flow / min-cut theorem): |cut| must equal maxFlow.

        Several minimum cuts can exist (e.g. any one token per disjoint path).
        prefer="entry" returns the one closest to the Internet (S = residual-
        reachable from the source); prefer="crown" the one closest to the
        targets (T = nodes that can still reach a target in the residual graph),
        which is the cut networkx's minimum_cut (the oracle) reports.

        The residual BFS only needs the ancestors of the targets: a node that
        cannot reach a target in the original graph can never be on a residual
        path that matters, because residual back-arcs only exist on edges that
        carry flow (and flow only runs on source->target paths).
        """
        inp = MinCutInput(org=org, target_ids=target_ids, prefer=prefer, mode=mode)
        g, qlog = self._org(inp.org), []
        cap_prop = "cap" if inp.mode == "fewest" else "effort"
        targets = self._targets(g, inp.target_ids, qlog)
        if not targets:
            return ToolResult(summary="No target DataStores.", data={}, queries=qlog)

        rows = self._q(
            g,
            """
            MATCH (s:Internet)
            MATCH (t:DataStore) WHERE t.id IN $targets
            WITH s, collect(t) AS ts
            CALL algo.maxFlow({sourceNodes: [s], targetNodes: ts,
                               capacityProperty: $cap_prop, relationshipTypes: ['FLOW']})
            YIELD edges, edgeFlows, maxFlow
            RETURN maxFlow,
                   [i IN range(0, size(edges) - 1) |
                    [startNode(edges[i]).id, endNode(edges[i]).id, edgeFlows[i]]]
            """,
            {"targets": targets, "cap_prop": cap_prop},
            qlog,
        )
        max_flow = int(round(rows[0][0])) if rows else 0
        flows = {(a, b): f for a, b, f in (rows[0][1] if rows else [])}

        steps = self._ancestor_steps(g, targets, qlog)
        effort = self._gate_efforts(g, sorted({s["fix_token"] for s in steps}), qlog)
        gate_cap = effort if inp.mode == "cheapest" else None
        cut = residual_min_cut(steps, flows, targets, prefer=inp.prefer, gate_cap=gate_cap)
        # Self-check (max-flow / min-cut theorem): the cut's capacity == max flow.
        cut_value = sum(effort[t] for t in cut) if gate_cap else len(cut)
        if cut_value != max_flow:
            raise ToolError(f"min-cut recovery failed: cut={cut_value} != maxFlow={max_flow}")

        fixes = [{**describe_fix(t), "effort": effort.get(t)} for t in cut]
        findings = self._finding_details(g, [t for t in cut if not t.startswith("step:")], qlog)
        for f in fixes:
            if f["kind"] == "finding":
                f.update(findings.get(f["token"], {}))
        total_effort = sum(effort.get(t, 0) for t in cut)
        cut_edges = [s for s in steps if s["fix_token"] in set(cut)]
        ev = Evidence(
            node_ids=list(
                dict.fromkeys(
                    [*targets, *findings, *[x for s in cut_edges for x in (s["src"], s["dst"])]]
                )
            ),
            edges=[
                EdgeRef(src=s["src"], rel="ATTACK_STEP", dst=s["dst"], key=s["key"])
                for s in cut_edges
            ],
        )
        summary = (
            f"{'Fewest' if inp.mode == 'fewest' else 'Cheapest'} fix set: {len(cut)} fix(es), "
            f"total effort {total_effort}, cuts every attack path to {len(targets)} target(s) "
            f"(max flow = {max_flow}): " + "; ".join(f["action"] for f in fixes)
        )
        return ToolResult(
            summary=summary,
            data={
                "targets": targets,
                "max_flow": max_flow,
                "fix_tokens": cut,
                "fixes": fixes,
                "findings": sorted(findings),
                "prefer": inp.prefer,
                "mode": inp.mode,
                "total_effort": total_effort,
                "recovered_by": (
                    "residual-graph reachability from the Internet"
                    if inp.prefer == "entry"
                    else "residual-graph reverse reachability from the targets"
                ),
            },
            evidence=ev,
            queries=qlog,
        )

    def _targets(self, graph: str, target_ids: list[str] | None, qlog) -> list[str]:
        if target_ids:
            bad = [t for t in target_ids if label_of(t) != "DataStore"]
            if bad:
                raise ToolError(f"targets must be DataStore ids: {bad}")
            rows = self._q(
                graph,
                "MATCH (d:DataStore) WHERE d.id IN $ids RETURN d.id",
                {"ids": target_ids},
                qlog,
            )
            missing = set(target_ids) - {r[0] for r in rows}
            if missing:
                raise ToolError(f"unknown DataStore ids: {sorted(missing)}")
            return sorted(set(target_ids))
        rows = self._q(
            graph, "MATCH (d:DataStore {crown_jewel: true}) RETURN d.id ORDER BY d.id", {}, qlog
        )
        return [r[0] for r in rows]

    def _ancestor_steps(self, graph: str, targets: list[str], qlog) -> list[dict]:
        """Every ATTACK_STEP on which some target depends: reverse BFS from the
        targets, one index-backed lookup per label per round."""
        seen = set(targets)
        frontier = list(targets)
        steps: dict[str, dict] = {}
        rounds = 0
        while frontier:
            rounds += 1
            if rounds > 64 or len(seen) > 20_000:
                raise ToolError("attack graph above the targets is too large to cut")
            nxt: list[str] = []
            for label, ids in _group_by_label(frontier).items():
                rows = self._q(
                    graph,
                    f"""
                    MATCH (v:{label}) WHERE v.id IN $ids
                    MATCH (u)-[e:ATTACK_STEP]->(v)
                    RETURN u.id, v.id, e.key, e.fix_token
                    """,
                    {"ids": ids},
                    qlog,
                )
                for u, v, key, tok in rows:
                    steps[key] = {"src": u, "dst": v, "key": key, "fix_token": tok}
                    if u not in seen:
                        seen.add(u)
                        nxt.append(u)
            frontier = nxt
        return list(steps.values())

    def _gate_efforts(self, graph: str, tokens: list[str], qlog) -> dict[str, int]:
        """Effort (1-5) on each token's fix gate, as stamped by derive."""
        if not tokens:
            return {}
        rows = self._q(
            graph,
            """
            MATCH (fi:FixIn) WHERE fi.token IN $tokens
            MATCH (fi)-[g:FLOW]->(:FixOut)
            RETURN fi.token, g.effort
            """,
            {"tokens": tokens},
            qlog,
        )
        return {t: int(e) for t, e in rows if e is not None}

    def _finding_details(self, graph: str, finding_ids: list[str], qlog) -> dict[str, dict]:
        if not finding_ids:
            return {}
        rows = self._q(
            graph,
            """
            MATCH (f:Finding) WHERE f.id IN $ids
            MATCH (f)-[:ON]->(a:Asset), (f)-[:OF]->(v:Vuln)
            RETURN f.id, a.id, a.hostname, v.cve, v.cvss, v.epss, v.kev
            """,
            {"ids": finding_ids},
            qlog,
        )
        return {
            fid: {"asset": a, "hostname": h, "cve": cve, "cvss": cvss, "epss": epss, "kev": kev}
            for fid, a, h, cve, cvss, epss, kev in rows
        }

    # ========================================================= choke_points
    def choke_points(self, org: str, top: int = 10) -> ToolResult:
        """Betweenness over ATTACK_STEP restricted to :CrownPath nodes."""
        inp = ChokePointsInput(org=org, top=top)
        g, qlog = self._org(inp.org), []
        rows = self._q(
            g,
            """
            CALL algo.betweenness({nodeLabels: ['CrownPath'], relationshipTypes: ['ATTACK_STEP'],
                                   samplingSize: 100000, samplingSeed: 42})
            YIELD node, score
            WHERE score > 0
            RETURN node.id, labels(node), coalesce(node.hostname, node.name, node.kind), score
            ORDER BY score DESC, node.id
            LIMIT $top
            """,
            {"top": inp.top + 1},
            qlog,
        )
        truncated = len(rows) > inp.top
        rows = rows[: inp.top]
        ids = [r[0] for r in rows]
        # Share of crown paths through each choke point, and the steps INTO it
        # (their fix tokens are what you would remediate to close the choke).
        share_rows = self._q(
            g,
            f"""
            MATCH path = (:Internet)-[:ATTACK_STEP*1..{HOP_CAP}]->(:DataStore {{crown_jewel: true}})
            WITH collect(path) AS paths
            UNWIND $ids AS x
            RETURN x, size([p IN paths WHERE any(n IN nodes(p) WHERE n.id = x)]), size(paths)
            """,
            {"ids": ids},
            qlog,
        )
        share = {x: (n, total) for x, n, total in share_rows}
        into = self._q(
            g,
            """
            MATCH (n:CrownPath) WHERE n.id IN $ids
            MATCH (u:CrownPath)-[e:ATTACK_STEP]->(n)
            RETURN n.id, collect({src: u.id, key: e.key, rule: e.rule, fix_token: e.fix_token})
            """,
            {"ids": ids},
            qlog,
        )
        steps_into = dict(into)
        points, ev = [], Evidence(node_ids=list(ids))
        for nid, labels, name, score in rows:
            n, total = share.get(nid, (0, 0))
            points.append(
                {
                    "node": nid,
                    "labels": _clean_labels(labels),
                    "name": name,
                    "betweenness": round(score, 4),
                    "crown_paths_through": n,
                    "crown_paths_total": total,
                    "steps_into": steps_into.get(nid, []),
                }
            )
            for s in steps_into.get(nid, []):
                ev.node_ids.append(s["src"])
                ev.edges.append(EdgeRef(src=s["src"], rel="ATTACK_STEP", dst=nid, key=s["key"]))
        ev.node_ids = list(dict.fromkeys(ev.node_ids))
        if points:
            p0 = points[0]
            summary = (
                f"Top choke point {p0['node']} ({p0['name']}): betweenness {p0['betweenness']}, "
                f"on {p0['crown_paths_through']}/{p0['crown_paths_total']} crown-jewel paths."
            )
        else:
            summary = "No choke points: crown-jewel paths share no intermediate node."
        return ToolResult(
            summary=summary,
            data={"choke_points": points},
            evidence=ev,
            queries=qlog,
            truncated=truncated,
        )

    # ============================================================== why_step
    def why_step(self, org: str, edge_key: str) -> ToolResult:
        """The evidence behind one ATTACK_STEP, resolved to readable nodes."""
        inp = WhyStepInput(org=org, edge_key=edge_key)
        g, qlog = self._org(inp.org), []
        rows = self._q(
            g,
            """
            MATCH (a)-[e:ATTACK_STEP {key: $key}]->(b)
            RETURN a.id, b.id, e.rule, e.technique, e.likelihood, e.cost, e.fix_token, e.because
            """,
            {"key": inp.edge_key},
            qlog,
        )
        if not rows:
            raise ToolError(f"no ATTACK_STEP with key {inp.edge_key!r}")
        src, dst, rule, technique, lk, cost, token, because = rows[0]
        nodes = self._nodes(g, [src, dst, *because], qlog)
        # The structural edges among the step's endpoints and its evidence:
        # exactly the facts the rule's MATCH pattern bound.
        ids = list(nodes)
        struct: list[list] = []
        for label, chunk in _group_by_label(ids).items():
            struct += self._q(
                g,
                f"""
                MATCH (p:{label}) WHERE p.id IN $chunk
                MATCH (p)-[r]->(q)
                WHERE q.id IN $ids AND NOT type(r) IN ['ATTACK_STEP', 'FLOW']
                RETURN p.id, type(r), q.id, properties(r)
                """,
                {"chunk": chunk, "ids": ids},
                qlog,
            )
        tech = self._technique(technique, qlog)
        r = RULES[rule]
        ev = Evidence(
            node_ids=ids,
            edges=[EdgeRef(src=src, rel="ATTACK_STEP", dst=dst, key=inp.edge_key)]
            + [EdgeRef(src=p, rel=t, dst=q) for p, t, q, _ in struct],
        )
        summary = (
            f"{rule} ({technique} {tech.get('name', '')}): {src} -> {dst}, "
            f"likelihood {lk:.3f}; removed by fixing {token}. Because: {', '.join(because)}."
        )
        return ToolResult(
            summary=summary,
            data={
                "key": inp.edge_key,
                "src": nodes.get(src),
                "dst": nodes.get(dst),
                "rule": rule,
                "rule_text": r.step,
                "technique": {"id": technique, **tech},
                "likelihood": lk,
                "cost": cost,
                "fix": describe_fix(token),
                "because": [nodes[b] for b in because if b in nodes],
                "structural_edges": [
                    {"src": p, "rel": t, "dst": q, "props": dict(pr)} for p, t, q, pr in struct
                ],
            },
            evidence=ev,
            queries=qlog,
        )

    def _technique(self, tid: str, qlog) -> dict:
        try:
            rows = self._q(
                self.threatintel,
                """
                MATCH (t:Technique {id: $id})
                OPTIONAL MATCH (t)-[:IN_TACTIC]->(ta:Tactic)
                RETURN t.name, t.url, collect(ta.name)
                """,
                {"id": tid},
                qlog,
            )
        except Exception:  # noqa: BLE001 - threatintel graph is optional for this tool
            return {}
        return {"name": rows[0][0], "url": rows[0][1], "tactics": rows[0][2]} if rows else {}

    # ============================================================ vuln_intel
    def vuln_intel(self, cve: str, org: str | None = None) -> ToolResult:
        """CVSS / EPSS / KEV / ransomware / CWE / ATT&CK for one CVE (threatintel)."""
        inp = VulnIntelInput(cve=cve, org=org)
        qlog: list[QueryLog] = []
        rows = self._q(
            self.threatintel,
            """
            MATCH (c:CVE {id: $cve})
            OPTIONAL MATCH (c)-[:HAS_CWE]->(w:CWE)
            OPTIONAL MATCH (c)-[:AFFECTS]->(p:Product)
            RETURN properties(c), collect(DISTINCT w.id), collect(DISTINCT p.id)
            """,
            {"cve": inp.cve},
            qlog,
        )
        if not rows:
            raise ToolError(f"{inp.cve} is not in the threat-intel snapshot")
        props, cwes, products = dict(rows[0][0]), rows[0][1], rows[0][2]
        av = props.get("av", "")
        # Which of OUR attack rules this CVE can power, hence which techniques.
        rules = []
        if av in NETWORK_VECTORS:
            rules = ["exploit_public_facing", "exploit_remote_service"]
        elif av == "LOCAL" and (props.get("cvss") or 0) >= PRIVESC_MIN_CVSS:
            rules = ["local_privesc"]
        techniques = [
            {"rule": r, "id": RULES[r].technique, **self._technique(RULES[r].technique, qlog)}
            for r in rules
        ]
        likelihood = exploit_likelihood(
            VulnSignals(
                av=av,
                pr=props.get("pr") or "NONE",
                ui=props.get("ui") or "NONE",
                epss=props.get("epss") or 0.0,
                kev=bool(props.get("kev")),
                cvss=props.get("cvss") or 0.0,
            )
        )
        data: dict[str, Any] = {
            "cve": inp.cve,
            "cvss": props.get("cvss"),
            "severity": props.get("severity"),
            "vector": props.get("vector"),
            "epss": props.get("epss"),
            "epss_percentile": props.get("epss_percentile"),
            "kev": props.get("kev"),
            "ransomware": props.get("kev_ransomware"),
            "cwes": sorted(cwes),
            "products": sorted(products),
            "attack_rules": rules,
            "techniques": techniques,
            "step_likelihood": round(likelihood, 4),
        }
        ev = Evidence()
        if inp.org:
            g = self._org(inp.org)
            occ = self._q(
                g,
                """
                MATCH (f:Finding)-[:OF]->(v:Vuln {cve: $cve}), (f)-[:ON]->(a:Asset)
                OPTIONAL MATCH ()-[e:ATTACK_STEP {fix_token: f.id}]->()
                RETURN f.id, a.id, count(e) AS steps
                ORDER BY steps DESC, f.id LIMIT $limit
                """,
                {"cve": inp.cve, "limit": MAX_ROWS},
                qlog,
            )
            data["in_org"] = {
                "org": g,
                "findings": [{"finding": f, "asset": a, "attack_steps": n} for f, a, n in occ],
                "findings_enabling_steps": sum(1 for *_, n in occ if n),
            }
            ev.node_ids = [x for f, a, _ in occ for x in (f, a)]
        summary = (
            f"{inp.cve}: CVSS {data['cvss']} ({av}), EPSS {data['epss']}, "
            f"KEV {'yes' if data['kev'] else 'no'}"
            f"{' (ransomware)' if data['ransomware'] else ''}; "
            f"step likelihood {data['step_likelihood']}; techniques "
            f"{[t['id'] for t in techniques] or 'none'}."
        )
        if inp.org:
            io = data["in_org"]
            summary += (
                f" In {g}: {len(io['findings'])} finding(s), "
                f"{io['findings_enabling_steps']} enable an attack step."
            )
        return ToolResult(summary=summary, data=data, evidence=ev, queries=qlog)

    # ========================================================== simulate_fix
    def simulate_fix(self, org: str, fix_tokens: list[str], k: int = 5) -> ToolResult:
        """Apply fixes in a throwaway GRAPH.COPY and re-run attack_paths there.

        Why COPY rather than tag-and-rollback: SPpaths cannot filter edges by a
        property, so "disable" really means DELETE. Doing that on the live org
        graph (then re-creating the edges) would show half-fixed state to any
        concurrent reader and lose edges if we crashed mid-way. GRAPH.COPY is
        one server-side command (~0.3 s at scale 1), the org graph is never
        written, and the scratch copy is always deleted in `finally`.
        """
        inp = SimulateFixInput(org=org, fix_tokens=fix_tokens, k=k)
        g, qlog = self._org(inp.org), []
        tokens = sorted(set(inp.fix_tokens))
        known = {
            r[0]
            for r in self._q(
                g,
                """
                MATCH ()-[e:ATTACK_STEP]->()
                WHERE e.fix_token IN $tokens
                RETURN DISTINCT e.fix_token
                """,
                {"tokens": tokens},
                qlog,
            )
        }
        unknown = [t for t in tokens if t not in known]
        paths_in = AttackPathsInput(org=g, k=inp.k)
        before, _ = self._paths(g, AttackPathsInput(org=g, k=1), qlog)
        crown = self._targets(g, None, qlog)
        reach_before = sorted({p["target"] for p in before})

        scratch = f"{SCRATCH_PREFIX}{g}__{uuid.uuid4().hex[:8]}"
        t = time.perf_counter()
        self.db.select_graph(g).copy(scratch)
        qlog.append(
            QueryLog(
                graph=g,
                cypher=f"GRAPH.COPY {g} {scratch}",
                params={},
                ms=round((time.perf_counter() - t) * 1000, 2),
            )
        )
        try:
            removed_rows = self._q(
                scratch,
                "MATCH (a)-[e:ATTACK_STEP]->(b) WHERE e.fix_token IN $tokens "
                "RETURN a.id, b.id, e.key",
                {"tokens": tokens},
                qlog,
            )
            self._scratch_write(
                scratch,
                "MATCH ()-[e:ATTACK_STEP]->() WHERE e.fix_token IN $tokens DELETE e",
                {"tokens": tokens},
                qlog,
            )
            after, truncated = self._paths(scratch, paths_in, qlog)
        finally:
            self.db.select_graph(scratch).delete()
        reach_after = sorted({p["target"] for p in after})
        now_safe = sorted(set(reach_before) - set(reach_after))
        ev = Evidence(
            node_ids=list(dict.fromkeys([x for a, b, _ in removed_rows for x in (a, b)])),
            edges=[EdgeRef(src=a, rel="ATTACK_STEP", dst=b, key=key) for a, b, key in removed_rows],
        )
        all_safe = not reach_after
        summary = (
            f"Applying {len(tokens)} fix(es) removes {len(removed_rows)} attack step(s). "
            + (
                f"ALL {len(crown)} crown jewel(s) now unreachable from the Internet."
                if all_safe
                else f"Still reachable: {reach_after}; newly unreachable: {now_safe}."
            )
            + (f" Unknown tokens ignored: {unknown}." if unknown else "")
        )
        return ToolResult(
            summary=summary,
            data={
                "fix_tokens": tokens,
                "unknown_tokens": unknown,
                "removed_steps": len(removed_rows),
                "crown_jewels": crown,
                "reachable_before": reach_before,
                "reachable_after": reach_after,
                "now_unreachable": now_safe,
                "all_crown_jewels_disconnected": all_safe,
                "remaining_paths": after,
            },
            evidence=ev,
            queries=qlog,
            truncated=truncated,
        )

    # ==================================================== run_cypher_readonly
    def run_cypher_readonly(
        self, org: str, query: str, params: dict | None = None, limit: int = 50
    ) -> ToolResult:
        """Escape hatch: arbitrary READ-ONLY Cypher, forced LIMIT, timeout, logged."""
        inp = RunCypherInput(org=org, query=query, params=params or {}, limit=limit)
        g, qlog = self._org(inp.org), []
        cypher = force_limit(inp.query, inp.limit + 1)
        t = time.perf_counter()
        try:
            res = self.db.select_graph(g).ro_query(cypher, inp.params, timeout=self.timeout_ms)
        except Exception as exc:
            log.warning("run_cypher_readonly rejected org=%s err=%s query=%r", g, exc, cypher)
            raise ToolError(f"query rejected: {exc}") from exc
        ms = round((time.perf_counter() - t) * 1000, 2)
        qlog.append(QueryLog(graph=g, cypher=cypher, params=inp.params, ms=ms))
        rows = res.result_set
        truncated = len(rows) > inp.limit
        rows = rows[: inp.limit]
        header = [h[1] if isinstance(h, list | tuple) else h for h in (res.header or [])]
        ev = Evidence()
        out = [[_jsonable(v, ev) for v in row] for row in rows]
        ev.node_ids = list(dict.fromkeys(ev.node_ids))
        log.info("run_cypher_readonly org=%s rows=%d ms=%s query=%r", g, len(out), ms, cypher)
        return ToolResult(
            summary=f"{len(out)} row(s){' (truncated)' if truncated else ''} in {ms} ms.",
            data={"columns": header, "rows": out, "executed": cypher},
            evidence=ev,
            queries=qlog,
            truncated=truncated,
        )

    # ========================================================= triage_memory
    def triage_memory(
        self, org: str, finding_ids: list[str], as_of: int | None = None
    ) -> ToolResult:
        """What memory says about these findings: LIVE risk acceptances (expired ones
        listed but not suppressing), past verdicts, and patterns that reach them.
        Read-only: the writes live in memory.MemoryRepo."""
        inp = TriageMemoryInput(org=org, finding_ids=finding_ids, as_of=as_of)
        g, qlog = self._org(inp.org), []
        return memory.triage_memory(
            lambda c, p: self._q(g, c, p, qlog), g, inp.finding_ids, now=inp.as_of, qlog=qlog
        )

    # ========================================================= scan_findings
    def scan_findings(self, org: str, limit: int = 30, view: str = "ranked") -> ToolResult:
        """The scan at a glance: which scan and when, the crown jewels, and the open
        findings ranked by what they enable in the ATTACK_STEP layer.

        A finding matters to an attacker only if it is the fix_token of some
        ATTACK_STEP. So rank: on a crown-jewel path (both step endpoints are
        :CrownPath), then reachable straight from the Internet, then KEV, step
        likelihood, CVSS. Separately list the most severe open findings that
        enable NO step: high scores, no way in (the classic false alarm).

        view="triage" is the lean form Triage starts from (S5): the aggregates
        (counts by technique, severity band and exposure) and per-finding detail
        ONLY for the candidates, the findings that enable a step straight from the
        Internet. Everything else is a count, not a row."""
        inp = ScanFindingsInput(org=org, limit=limit, view=view)
        g, qlog = self._org(inp.org), []
        scan = self._q(
            g, "MATCH (s:Scan) RETURN s.id, s.version, s.ts ORDER BY s.ts DESC", {}, qlog
        )
        status = dict(self._q(g, "MATCH (f:Finding) RETURN f.status, count(f)", {}, qlog))
        crown = self._q(
            g,
            "MATCH (d:DataStore {crown_jewel: true}) "
            "RETURN d.id, d.kind, d.sensitivity ORDER BY d.id",
            {},
            qlog,
        )
        # Every finding that enables at least one step (step:* tokens are not
        # scanner findings): its techniques and best step likelihood.
        enabling = self._q(
            g,
            """
            MATCH (a)-[e:ATTACK_STEP]->(b)
            WHERE NOT e.fix_token STARTS WITH 'step:'
            RETURN e.fix_token, count(e), collect(DISTINCT e.technique), max(e.likelihood),
                   max(CASE WHEN a:CrownPath AND b:CrownPath THEN 1 ELSE 0 END),
                   max(CASE WHEN a:Internet THEN 1 ELSE 0 END)
            """,
            {},
            qlog,
        )
        # The vuln signals the ranking needs, for every open finding, joined in
        # Python. FalkorDB gotcha: joining in Cypher (WITH tok MATCH (f:Finding
        # {id: tok})) is a per-row scan, not an index seek: 3.6 s vs ~0.1 s here.
        # Passing the ~3k ids as a parameter instead would also bloat the query log.
        signals = {
            fid: (bool(kev), cvss or 0.0)
            for fid, kev, cvss in self._q(
                g,
                "MATCH (f:Finding {status: 'open'})-[:OF]->(v:Vuln) RETURN f.id, v.kev, v.cvss",
                {},
                qlog,
            )
        }
        enabling = [
            (*row, *signals.get(row[0], (False, 0.0))) for row in enabling if row[0] in signals
        ]
        steps = {
            tok: {
                "attack_steps": n,
                "techniques": sorted(techs),
                "best_likelihood": round(lk, 4),
                "on_crown_path": bool(cp),
                "from_internet": bool(inet),
                "_rank": (-cp, -inet, -int(kev), -lk, -cvss, tok),
            }
            for tok, n, techs, lk, cp, inet, kev, cvss in enabling
        }
        ranked = sorted(steps, key=lambda t: steps[t]["_rank"])
        aggregates = _scan_aggregates(signals, steps)
        triage = inp.view == "triage"
        other_inet: list[str] = []
        if triage:  # candidates: a way in straight from the Internet, crown path first
            inet = [t for t in ranked if steps[t]["from_internet"]]
            ranked = [t for t in inet if steps[t]["on_crown_path"]]
            other_inet = [t for t in inet if not steps[t]["on_crown_path"]]
        truncated = len(ranked) > inp.limit
        # The most severe open findings that enable nothing: the top criticals,
        # minus any that do enable a step.
        severe = [
            r[0]
            for r in self._q(
                g,
                """
                MATCH (f:Finding {status: 'open'})-[:OF]->(v:Vuln) WHERE v.cvss >= 9.0
                RETURN f.id ORDER BY v.kev DESC, v.cvss DESC, v.epss DESC, f.id LIMIT 60
                """,
                {},
                qlog,
            )
            if r[0] not in steps
        ][:10]
        # Open findings someone already decided about (a risk acceptance or a
        # verdict ON them): triage must look at their memory even when they
        # enable no step, or a live acceptance would go unnoticed.
        prior: dict[str, dict] = {}
        for kind, cypher in (
            (
                "risk_acceptances",
                "MATCH (m:RiskAcceptance)-[:ON]->(f:Finding {status: 'open'}) "
                "RETURN f.id, count(m), max(m.created)",
            ),
            (
                "verdicts",
                "MATCH (m:Verdict)-[:ON]->(f:Finding {status: 'open'}) "
                "RETURN f.id, count(m), max(m.ts)",
            ),
        ):
            for fid, n, last in self._q(g, cypher, {}, qlog):
                p = prior.setdefault(
                    fid, {"finding": fid, "risk_acceptances": 0, "verdicts": 0, "last": 0}
                )
                p[kind], p["last"] = n, max(p["last"], last or 0)
        decided = sorted(
            prior.values(), key=lambda p: (-p["risk_acceptances"], -p["last"], p["finding"])
        )[:20]
        for p in decided:
            p["enables_attack_step"] = p["finding"] in steps
            p.pop("last")
        others = other_inet[:TRIAGE_OTHERS]
        details = self._finding_details(g, [*ranked[: inp.limit], *others, *severe], qlog)

        def row(f: str) -> dict:
            return {
                "finding": f,
                **details[f],
                **{k: v for k, v in steps[f].items() if k != "_rank"},
            }

        findings = [row(f) for f in ranked[: inp.limit] if f in details]
        others_rows = [row(f) for f in others if f in details]
        unreachable = [
            {"finding": f, **details[f], "attack_steps": 0} for f in severe if f in details
        ]
        ev = Evidence(
            node_ids=[
                *(s[0] for s in scan[:1]),
                *(c[0] for c in crown),
                *(
                    x
                    for f in findings + others_rows + unreachable
                    for x in (f["finding"], f["asset"])
                ),
                *(p["finding"] for p in decided),
            ]
        )
        ev.node_ids = list(dict.fromkeys(ev.node_ids))
        if triage:  # the same facts, minus what triage never reads
            for f in findings + others_rows:
                for k in ("epss", "from_internet", "attack_steps"):
                    f.pop(k, None)
            for f in unreachable:
                for k in ("asset", "epss", "attack_steps"):
                    f.pop(k, None)
        on_crown = sum(1 for s in steps.values() if s["on_crown_path"])
        sid, version, ts = scan[0] if scan else (None, None, None)
        summary = (
            f"Scan {version or '?'} ({_day(ts)}): {status.get('open', 0)} open findings; "
            f"{len(steps)} enable an attack step, {on_crown} on a crown-jewel path; "
            f"{len(unreachable)} critical finding(s) enable no step at all; "
            f"{len(prior)} carry an earlier decision (check triage_memory). "
            f"Crown jewels: {[c[0] for c in crown]}."
            + (
                f" Triage view: {len(findings)} Internet-facing candidate(s) on a crown-jewel "
                f"path, {len(other_inet)} more Internet-facing off any crown path."
                if triage
                else ""
            )
        )
        data = {
            "scan": {"id": sid, "version": version, "ts": ts, "date": _day(ts)},
            "counts": {
                "open": status.get("open", 0),
                "fixed": status.get("fixed", 0),
                "enabling_attack_steps": len(steps),
                "on_crown_path": on_crown,
            },
            "crown_jewels": [{"id": i, "kind": k, "sensitivity": s} for i, k, s in crown],
            "view": inp.view,
            "aggregates": aggregates,
            "findings": findings,
            "critical_without_attack_step": unreachable,
            "previously_decided": decided,
        }
        if triage:
            data["other_internet_facing"] = {"count": len(other_inet), "top": others_rows}
            data["previously_decided"] = [p["finding"] for p in decided]
        return ToolResult(
            summary=summary, data=data, evidence=ev, queries=qlog, truncated=truncated
        )

    # ============================================================= playbooks
    def playbooks(self, org: str, techniques: list[str], as_of: int | None = None) -> ToolResult:
        """The playbook version in force for each technique at `as_of` (procedural
        memory): the newest version published at or before then. Without as_of,
        the version nothing supersedes."""
        inp = PlaybooksInput(org=org, techniques=techniques, as_of=as_of)
        g, qlog = self._org(inp.org), []
        out, ev = [], Evidence()
        for tech in dict.fromkeys(inp.techniques):
            rows = [
                {"id": i, "version": v, "body": b, "ts": ts, "supersedes": old}
                for i, _, v, b, ts, old in self._q(
                    g, memory.READ_PLAYBOOK_HISTORY, {"technique": tech}, qlog
                )
            ]
            if inp.as_of is None:
                superseded = {r["supersedes"] for r in rows}
                live = [r for r in rows if r["id"] not in superseded]
            else:
                live = [r for r in rows if r["ts"] <= inp.as_of]
            cur = max(live, key=lambda r: r["version"]) if live else None
            out.append(
                {
                    "technique": tech,
                    "current": cur,
                    "versions": [
                        {"id": r["id"], "version": r["version"], "date": _day(r["ts"])}
                        for r in rows
                    ],
                }
            )
            if cur:
                ev.node_ids += [tech, cur["id"]]
                ev.edges.append(EdgeRef(src=tech, rel="HANDLED_BY", dst=cur["id"]))
        have = [p["technique"] for p in out if p["current"]]
        missing = [p["technique"] for p in out if not p["current"]]
        summary = (
            "Playbooks in force"
            + (f" at {_day(inp.as_of)}" if inp.as_of is not None else "")
            + ": "
            + (
                ", ".join(
                    f"{p['technique']} v{p['current']['version']}" for p in out if p["current"]
                )
                or "none"
            )
            + (f"; no playbook for {missing}" if missing else "")
            + "."
        )
        return ToolResult(
            summary=summary,
            data={"as_of": inp.as_of, "playbooks": out, "covered": have, "missing": missing},
            evidence=ev,
            queries=qlog,
        )

    # ============================================================ S5 stubs
    def exposure_drift(self, org: str) -> ToolResult:
        """TODO(S5): what changed between scan v1 and v2 (graphs <org> and <org>_v2)."""
        raise NotImplementedError("exposure_drift arrives in S5 (Sentinel / drift)")


# ---------------------------------------------------------------- helpers
def _scan_aggregates(signals: dict[str, tuple[bool, float]], steps: dict[str, dict]) -> dict:
    """Counts a triager reasons from before looking at any single finding: open
    findings by CVSS band (and how many of each enable an attack step), by the
    ATT&CK technique they enable, and by exposure."""
    by_sev: dict[str, dict[str, int]] = {}
    for fid, (_, cvss) in signals.items():
        b = by_sev.setdefault(severity_band(cvss), {"open": 0, "enable_steps": 0})
        b["open"] += 1
        b["enable_steps"] += fid in steps
    by_tech: dict[str, int] = {}
    for s in steps.values():
        for t in s["techniques"]:
            by_tech[t] = by_tech.get(t, 0) + 1
    inet = sum(1 for s in steps.values() if s["from_internet"])
    return {
        "by_severity": dict(sorted(by_sev.items())),
        "by_technique": dict(sorted(by_tech.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_exposure": {
            "from_internet": inet,
            "on_crown_path": sum(1 for s in steps.values() if s["on_crown_path"]),
            "internal_steps_only": len(steps) - inet,
            "no_attack_step": len(signals) - len(steps),
        },
    }


def residual_min_cut(
    steps: list[dict],
    flows: dict[tuple[str, str], float],
    targets: list[str],
    prefer: str = "entry",
    gate_cap: dict[str, int] | None = None,
) -> list[str]:
    """Recover the min-cut fix tokens from max-flow edge flows (pure function).

    `steps`: ATTACK_STEP edges {src, dst, fix_token} above the targets.
    `flows`: (start id, end id) -> flow for FLOW edges carrying positive flow
             (exactly what algo.maxFlow yields).
    Rebuilds the node-split network (same shape as derive.BUILD_FLOW), forms the
    residual graph, and returns the tokens whose unit gate crosses the cut:
      entry: S = BFS from 'internet' over residual arcs; cut = FixIn in S, FixOut not.
      crown: T = reverse BFS from the targets; cut = FixIn not in T, FixOut in T.
    `gate_cap` gives each token's gate capacity (its effort, mode="cheapest");
    without it every gate has capacity 1 (mode="fewest").
    """
    big = math.inf
    cap: dict[tuple[str, str], float] = {}
    for s in steps:
        t = s["fix_token"]
        fi, fo = f"fix_in:{t}", f"fix_out:{t}"
        cap[(fi, fo)] = gate_cap.get(t, 1) if gate_cap else 1
        cap[(s["src"], fi)] = big
        cap[(fo, s["dst"])] = big
    residual: dict[str, list[str]] = {}
    for (a, b), c in cap.items():
        f = flows.get((a, b), 0)
        if f < c:
            residual.setdefault(a, []).append(b)
        if f > 0:
            residual.setdefault(b, []).append(a)
    tokens = {s["fix_token"] for s in steps}
    if prefer == "crown":
        reverse: dict[str, list[str]] = {}
        for a, outs in residual.items():
            for b in outs:
                reverse.setdefault(b, []).append(a)
        t_side = _bfs(reverse, targets)
        return sorted(t for t in tokens if f"fix_in:{t}" not in t_side and f"fix_out:{t}" in t_side)
    s_side = _bfs(residual, ["internet"])
    return sorted(t for t in tokens if f"fix_in:{t}" in s_side and f"fix_out:{t}" not in s_side)


def _bfs(adj: dict[str, list[str]], starts: list[str]) -> set[str]:
    seen = set(starts)
    q = deque(starts)
    while q:
        n = q.popleft()
        for m in adj.get(n, []):
            if m not in seen:
                seen.add(m)
                q.append(m)
    return seen


def _group_by_label(ids: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for i in ids:
        lbl = label_of(i)
        if lbl:
            out.setdefault(lbl, []).append(i)
    return out


_LIMIT_TAIL = re.compile(r"\bLIMIT\s+(\d+)\s*;?\s*$", re.IGNORECASE)


def force_limit(query: str, cap: int) -> str:
    """Clamp a trailing LIMIT to `cap`, or append one."""
    q = query.strip().rstrip(";").rstrip()
    m = _LIMIT_TAIL.search(q)
    if m:
        n = min(int(m.group(1)), cap)
        return q[: m.start()] + f"LIMIT {n}"
    return f"{q}\nLIMIT {cap}"


def _jsonable(v: Any, ev: Evidence) -> Any:
    """Make a FalkorDB value JSON-safe, harvesting node ids into evidence."""
    if isinstance(v, Node):
        nid = v.properties.get("id")
        if nid:
            ev.node_ids.append(nid)
        return {"labels": _clean_labels(list(v.labels or [])), "properties": dict(v.properties)}
    if isinstance(v, Edge):
        return {"type": v.relation, "properties": dict(v.properties)}
    if isinstance(v, Path):
        return {
            "nodes": [_jsonable(n, ev) for n in v.nodes()],
            "edges": [_jsonable(e, ev) for e in v.edges()],
        }
    if isinstance(v, list):
        return [_jsonable(x, ev) for x in v]
    if isinstance(v, dict):
        return {k: _jsonable(x, ev) for k, x in v.items()}
    return v


def _squash(cypher: str) -> str:
    """One-line form for logs. Drops // comments first: joined onto one line,
    a comment would swallow the rest of the query."""
    lines = [ln.split("//", 1)[0] for ln in cypher.splitlines()]
    return " ".join(" ".join(lines).split())


# The tool names are the contract with the MCP server and the S4 agent.
TOOL_NAMES = [
    "exposure_surface",
    "attack_paths",
    "blast_radius",
    "min_cut",
    "choke_points",
    "why_step",
    "vuln_intel",
    "simulate_fix",
    "run_cypher_readonly",
    # company layer (S3)
    "owners",
    "decision_trail",
    "company_query",
    # memory layer (S3)
    "triage_memory",
    # agent layer (S4): the scan's findings, and procedural memory
    "scan_findings",
    "playbooks",
]
