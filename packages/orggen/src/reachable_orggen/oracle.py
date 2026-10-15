"""The independent ground-truth oracle.

Builds the attack graph in pure Python + networkx, straight from a Dataset,
applying exactly the rules in reachable_core.attack_rules. It never touches
FalkorDB — that is the point: it is the independent check that S2's Cypher
derivation (and the planter) are correct.

It computes:
  * all simple attack paths from the Internet to each crown-jewel DataStore,
    with a hop cap;
  * the minimum fix set (min cut) that disconnects the Internet from every
    crown jewel, via node-splitting so each unit cut is a finding/step;
  * a priority score per Finding: high if it lies on true paths, weighted by
    how many paths run through it and how sensitive the target; ~0 otherwise.

Attack-graph state nodes (strings):
    internet | asset:<id> | priv:<id> | secret:<id> | ident:<id> | ds:<id>
Each attack edge carries (rule, technique, likelihood, fix) where `fix` is the
token a defender would remediate — a Finding id for exploit steps, or a
synthetic step token for credential/identity steps. The min cut is taken over
fix tokens, so cutting one fix removes every edge it enables.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import networkx as nx

from reachable_core.attack_rules import (
    HOP_CAP,
    OPEN_STATUS,
    PRIVESC_MIN_CVSS,
    READ_ACTIONS,
    RULES,
    VulnSignals,
    exploit_likelihood,
)
from reachable_intel.products import PRODUCTS_BY_ID

from .model import Dataset

INF = 10**9
SENSITIVITY_WEIGHT = {"crown": 1.0, "high": 0.6, "medium": 0.3, "low": 0.1}


@dataclass
class Hop:
    rule: str
    technique: str
    src: str
    dst: str
    fix: str
    likelihood: float


@dataclass
class OracleResult:
    attack_graph: nx.DiGraph
    crown_nodes: list[str]
    paths: dict[str, list[list[Hop]]]  # crown ds node -> list of hop-paths
    min_cut: list[str]  # fix tokens
    finding_priority: dict[str, float]  # finding id -> 0..1 priority
    edges_by_fix: dict[str, list[tuple[str, str]]] = field(default_factory=dict)


class _Index:
    """Flat lookup tables over a Dataset's edges, built once."""

    def __init__(self, ds: Dataset) -> None:
        self.ds = ds
        self.exposes: list[str] = []  # asset ids the Internet exposes
        self.can_reach: dict[str, list[tuple[str, int]]] = {}
        self.runs: dict[str, list[str]] = {}  # asset -> software ids
        self.has_vuln: dict[str, list[str]] = {}  # software -> vuln ids
        self.holds: dict[str, list[str]] = {}  # asset -> secret ids
        self.unlocks: dict[str, list[str]] = {}  # secret -> target ids
        self.assumes: dict[str, list[str]] = {}  # asset -> role ids
        self.can: dict[str, list[tuple[str, str]]] = {}  # ident -> (target, action)
        self.can_assume: dict[str, list[str]] = {}  # ident -> role ids
        self.mitigated: set[tuple[str, str]] = set()  # (vuln id, asset id) blocked
        self.finding_on: dict[str, str] = {}  # finding -> asset
        self.finding_of: dict[str, str] = {}  # finding -> vuln
        self.finding_by: dict[tuple[str, str], str] = {}  # (asset, vuln) -> finding

        for e in ds.edges:
            t = e.type
            if t == "EXPOSES":
                self.exposes.append(e.dst)
            elif t == "CAN_REACH":
                self.can_reach.setdefault(e.src, []).append((e.dst, e.props.get("port", 0)))
            elif t == "RUNS":
                self.runs.setdefault(e.src, []).append(e.dst)
            elif t == "HAS_VULN":
                self.has_vuln.setdefault(e.src, []).append(e.dst)
            elif t == "HOLDS":
                self.holds.setdefault(e.src, []).append(e.dst)
            elif t == "UNLOCKS":
                self.unlocks.setdefault(e.src, []).append(e.dst)
            elif t == "ASSUMES":
                self.assumes.setdefault(e.src, []).append(e.dst)
            elif t == "CAN":
                self.can.setdefault(e.src, []).append((e.dst, e.props.get("action", "")))
            elif t == "CAN_ASSUME":
                self.can_assume.setdefault(e.src, []).append(e.dst)
            elif t == "MITIGATES":
                self.mitigated.add((e.dst, e.props.get("asset", "")))
            elif t == "ON":
                self.finding_on[e.src] = e.dst
            elif t == "OF":
                self.finding_of[e.src] = e.dst

        # Only OPEN findings count: a fixed finding no longer enables a step.
        status = {f.id: f.status for f in ds.findings}
        for fid in self.finding_on:
            a = self.finding_on.get(fid)
            v = self.finding_of.get(fid)
            if a and v and status.get(fid) == OPEN_STATUS:
                self.finding_by[(a, v)] = fid

        self.vuln_by_id = {v.id: v for v in ds.vulns}
        self.sw_by_id = {s.id: s for s in ds.software}
        self.secret_by_id = {s.id: s for s in ds.secrets}
        self.ds_by_id = {d.id: d for d in ds.datastores}

    def finding_for(self, asset: str, vuln: str) -> str | None:
        """The open Finding reporting `vuln` on `asset`, or None. Exploit steps
        need one (same as the Cypher pattern `(f:Finding)-[:ON]->(a), (f)-[:OF]->(v)`)."""
        return self.finding_by.get((asset, vuln))

    def software_ports(self, sw_id: str) -> tuple[int, ...]:
        sw = self.sw_by_id[sw_id]
        spec = PRODUCTS_BY_ID.get(f"{sw.vendor}:{sw.product}")
        return spec.ports if spec else ()


def build_attack_graph(ds: Dataset) -> tuple[nx.DiGraph, _Index]:
    idx = _Index(ds)
    g = nx.DiGraph()
    g.add_node("internet")
    asset_ids = {a.id for a in ds.assets}

    def add(src: str, dst: str, rule_name: str, fix: str, likelihood: float) -> None:
        r = RULES[rule_name]
        g.add_edge(src, dst, rule=rule_name, technique=r.technique, fix=fix, likelihood=likelihood)

    def asset_network_vuln(asset_id: str, port: int | None) -> tuple[str, float] | None:
        """Return (finding_id, likelihood) for a network-exploitable, unblocked
        vuln on the asset, optionally matching a reachable port."""
        best: tuple[str, float] | None = None
        for sw_id in idx.runs.get(asset_id, []):
            if port is not None:
                ports = idx.software_ports(sw_id)
                if ports and port not in ports:
                    continue
            for vid in idx.has_vuln.get(sw_id, []):
                v = idx.vuln_by_id[vid]
                if v.av not in ("NETWORK", "ADJACENT_NETWORK"):
                    continue
                if (vid, asset_id) in idx.mitigated:
                    continue
                fid = idx.finding_for(asset_id, vid)
                if fid is None:
                    continue
                lk = exploit_likelihood(_sig(v))
                if best is None or lk > best[1]:
                    best = (fid, lk)
        return best

    # --- exploit_public_facing: internet -> exposed asset ---
    for asset_id in idx.exposes:
        hit = asset_network_vuln(asset_id, None)
        if hit:
            add("internet", f"asset:{asset_id}", "exploit_public_facing", hit[0], hit[1])

    # --- exploit_remote_service: asset -> reachable vulnerable asset ---
    for a_id, targets in idx.can_reach.items():
        for b_id, port in targets:
            hit = asset_network_vuln(b_id, port)
            if hit:
                add(f"asset:{a_id}", f"asset:{b_id}", "exploit_remote_service", hit[0], hit[1])

    # --- local_privesc: asset -> priv:asset ---
    for a in ds.assets:
        for sw_id in idx.runs.get(a.id, []):
            for vid in idx.has_vuln.get(sw_id, []):
                v = idx.vuln_by_id[vid]
                fid = idx.finding_for(a.id, vid)
                if (
                    v.av == "LOCAL"
                    and v.cvss >= PRIVESC_MIN_CVSS
                    and (vid, a.id) not in idx.mitigated
                    and fid is not None
                ):
                    add(
                        f"asset:{a.id}",
                        f"priv:{a.id}",
                        "local_privesc",
                        fid,
                        exploit_likelihood(_sig(v)),
                    )

    # --- creds_in_files: (asset|priv) -> secret ---
    for a_id, secret_ids in idx.holds.items():
        for s_id in secret_ids:
            s = idx.secret_by_id[s_id]
            src = f"priv:{a_id}" if s.requires_priv else f"asset:{a_id}"
            add(src, f"secret:{s_id}", "creds_in_files", f"step:creds:{a_id}:{s_id}", 0.9)

    # --- secret-driven steps ---
    for s_id, targets in idx.unlocks.items():
        s = idx.secret_by_id[s_id]
        for t_id in targets:
            if s.kind == "ssh_key" and t_id in asset_ids:  # unlocks an asset
                add(
                    f"secret:{s_id}",
                    f"asset:{t_id}",
                    "ssh_with_stolen_key",
                    f"step:ssh:{s_id}:{t_id}",
                    0.95,
                )
            elif s.kind == "db_password" and t_id in idx.ds_by_id:
                add(
                    f"secret:{s_id}",
                    f"ds:{t_id}",
                    "db_with_password",
                    f"step:db:{s_id}:{t_id}",
                    0.95,
                )
            elif s.kind == "cloud_key":  # unlocks an identity
                add(
                    f"secret:{s_id}",
                    f"ident:{t_id}",
                    "use_cloud_account",
                    f"step:usekey:{s_id}:{t_id}",
                    0.95,
                )

    # --- instance_metadata: cloud asset -> its role ---
    asset_by_id = {a.id: a for a in ds.assets}
    for a_id, roles in idx.assumes.items():
        if asset_by_id.get(a_id) and asset_by_id[a_id].cloud:
            for r_id in roles:
                add(
                    f"asset:{a_id}",
                    f"ident:{r_id}",
                    "instance_metadata",
                    f"step:imds:{a_id}:{r_id}",
                    0.9,
                )

    # --- identity permissions: use_cloud_account (assume) + read_cloud_storage ---
    for i_id, roles in idx.can_assume.items():
        for r_id in roles:
            add(
                f"ident:{i_id}",
                f"ident:{r_id}",
                "use_cloud_account",
                f"step:assume:{i_id}:{r_id}",
                0.95,
            )
    for i_id, perms in idx.can.items():
        for t_id, action in perms:
            if t_id in idx.ds_by_id and action in READ_ACTIONS:
                add(
                    f"ident:{i_id}",
                    f"ds:{t_id}",
                    "read_cloud_storage",
                    f"step:read:{i_id}:{t_id}",
                    0.95,
                )

    return g, idx


def _sig(v) -> VulnSignals:
    return VulnSignals(av=v.av, pr=v.pr, ui=v.ui, epss=v.epss, kev=v.kev, cvss=v.cvss)


def _ancestors_subgraph(g: nx.DiGraph, target: str) -> set[str]:
    """Nodes that can reach `target` (reverse BFS), plus the target itself.

    This keeps path enumeration tiny: only the (planted) structure that can
    actually reach a crown jewel is explored, never the whole org.
    """
    seen = {target}
    q = deque([target])
    rev = g.reverse(copy=False)
    while q:
        n = q.popleft()
        for pred in rev.neighbors(n):
            if pred not in seen:
                seen.add(pred)
                q.append(pred)
    return seen


def simple_paths(g: nx.DiGraph, target: str, hop_cap: int) -> list[list[Hop]]:
    if "internet" not in g or target not in g:
        return []
    sub_nodes = _ancestors_subgraph(g, target)
    if "internet" not in sub_nodes:
        return []
    sub = g.subgraph(sub_nodes)
    out: list[list[Hop]] = []
    for node_path in nx.all_simple_paths(sub, "internet", target, cutoff=hop_cap):
        hops: list[Hop] = []
        for u, v in zip(node_path, node_path[1:], strict=False):
            e = g.edges[u, v]
            hops.append(Hop(e["rule"], e["technique"], u, v, e["fix"], e["likelihood"]))
        out.append(hops)
    return out


def min_cut_fixes(g: nx.DiGraph, crown_nodes: list[str]) -> list[str]:
    """Minimum set of fix tokens disconnecting internet from all crown jewels.

    Node-splitting: every fix token t becomes an edge t#in -> t#out with
    capacity 1; the attack edges that the fix enables feed t#in and leave t#out
    with infinite capacity. A min cut on this flow network can only cut the
    capacity-1 fix edges, so the cut *is* a set of fixes, and cutting a fix that
    several attack edges share removes all of them at once.
    """
    flow = nx.DiGraph()
    flow.add_node("internet")
    flow.add_node("SINK")
    seen_fix: set[str] = set()
    for u, v, data in g.edges(data=True):
        fix = data["fix"]
        fin, fout = f"{fix}#in", f"{fix}#out"
        if fix not in seen_fix:
            flow.add_edge(fin, fout, capacity=1)
            seen_fix.add(fix)
        flow.add_edge(u, fin, capacity=INF)
        flow.add_edge(fout, v, capacity=INF)
    for c in crown_nodes:
        if c in flow:
            flow.add_edge(c, "SINK", capacity=INF)

    if "internet" not in flow or not any(c in flow for c in crown_nodes):
        return []
    try:
        _, (reach, _) = nx.minimum_cut(flow, "internet", "SINK")
    except nx.NetworkXUnbounded:
        return []
    cut = []
    for fix in seen_fix:
        if f"{fix}#in" in reach and f"{fix}#out" not in reach:
            cut.append(fix)
    return sorted(cut)


def paths_exist_after_removal(ds: Dataset, cutset: set[str], hop_cap: int) -> bool:
    """Rebuild the graph, drop every edge whose fix is in cutset, and check
    whether any crown jewel is still reachable. Used by the min-cut test."""
    g, idx = build_attack_graph(ds)
    to_drop = [(u, v) for u, v, d in g.edges(data=True) if d["fix"] in cutset]
    g.remove_edges_from(to_drop)
    crown = [f"ds:{d.id}" for d in ds.datastores if d.crown_jewel]
    return any(simple_paths(g, c, hop_cap) for c in crown)


def run_oracle(ds: Dataset, *, hop_cap: int = HOP_CAP) -> OracleResult:
    g, idx = build_attack_graph(ds)
    crown = [f"ds:{d.id}" for d in ds.datastores if d.crown_jewel]

    paths: dict[str, list[list[Hop]]] = {}
    for c in crown:
        p = simple_paths(g, c, hop_cap)
        if p:
            paths[c] = p

    cut = min_cut_fixes(g, crown)

    # Finding priority: for each crown path, every exploit hop references a
    # Finding id (its fix). Weight by the target DataStore's sensitivity and sum
    # across paths, then normalise so the top finding is ~1.0.
    raw: dict[str, float] = {}
    for c, plist in paths.items():
        d = idx.ds_by_id[c[len("ds:") :]]
        weight = SENSITIVITY_WEIGHT.get(d.sensitivity, 0.3)
        for hops in plist:
            for h in hops:
                if h.fix in idx.finding_on:  # it's a real Finding (exploit step)
                    raw[h.fix] = raw.get(h.fix, 0.0) + weight
    top = max(raw.values(), default=1.0)
    priority = {f.id: 0.0 for f in ds.findings}
    for fid, val in raw.items():
        priority[fid] = round(val / top, 4)

    edges_by_fix: dict[str, list[tuple[str, str]]] = {}
    for u, v, data in g.edges(data=True):
        edges_by_fix.setdefault(data["fix"], []).append((u, v))

    return OracleResult(
        attack_graph=g,
        crown_nodes=crown,
        paths=paths,
        min_cut=cut,
        finding_priority=priority,
        edges_by_fix=edges_by_fix,
    )
