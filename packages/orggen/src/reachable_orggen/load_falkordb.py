"""Load a Dataset into its FalkorDB graph (org_a / org_b / org_c).

All writes are parameterised batched UNWIND + MERGE, so loading is idempotent
and `make reset` can drop + reload cleanly. Every MATCH is label-qualified so
it is backed by the id index (we create those first). Relationship *types* and
node *labels* are baked into the query string from our own enums (never user
input), because Cypher cannot parameterise a label or a rel-type.
"""

from __future__ import annotations

from falkordb import FalkorDB

from reachable_core.attack_rules import VulnSignals, exploit_likelihood
from reachable_core.db import create_range_index, drop_graph, memory_usage_mb, run_batched
from reachable_core.schema import IDENTITY_KINDS, ORG_INDEXES
from reachable_intel.products import PRODUCTS_BY_ID

from .model import Dataset

# Which dataclass list maps to which node label, and the id->label lookup for
# resolving edge endpoints to index-backed MATCHes.
_NODE_LABEL = {
    "Asset": lambda ds: ds.assets,
    "Software": lambda ds: ds.software,
    "Vuln": lambda ds: ds.vulns,
    "Finding": lambda ds: ds.findings,
    "Identity": lambda ds: ds.identities,
    "Secret": lambda ds: ds.secrets,
    "DataStore": lambda ds: ds.datastores,
    "Control": lambda ds: ds.controls,
    "Zone": lambda ds: ds.zones,
    "Person": lambda ds: ds.persons,
    "Team": lambda ds: ds.teams,
    "OnCall": lambda ds: ds.oncalls,
    "ADR": lambda ds: ds.adrs,
    "Ticket": lambda ds: ds.tickets,
}


def _label_map(ds: Dataset) -> dict[str, str]:
    m: dict[str, str] = {ds.internet_id: "Internet"}
    for label, getter in _NODE_LABEL.items():
        for obj in getter(ds):
            m[obj.id] = label
    return m


def load_org(db: FalkorDB, ds: Dataset, *, fresh: bool = True) -> dict:
    if fresh:
        drop_graph(db, ds.org)
    g = db.select_graph(ds.org)

    for label, prop in ORG_INDEXES.items():
        create_range_index(g, label, prop)
    # decision_trail / company_query accept a hostname ("why is gw-01 exposed?").
    create_range_index(g, "Asset", "hostname")

    # --- Internet (one node) ---
    g.query("MERGE (:Internet {id: $id})", {"id": ds.internet_id})

    # --- Zones ---
    run_batched(
        g,
        "UNWIND $rows AS r MERGE (z:Zone {id: r.id}) SET z.name = r.name, z.trust = r.trust",
        [{"id": z.id, "name": z.name, "trust": z.trust} for z in ds.zones],
    )

    # --- Assets ---
    run_batched(
        g,
        """
        UNWIND $rows AS r MERGE (a:Asset {id: r.id})
        SET a.kind = r.kind, a.zone = r.zone, a.env = r.env,
            a.hostname = r.hostname, a.cloud = r.cloud
        """,
        [vars(a) for a in ds.assets],
    )

    # --- Software ---
    # `ports` is stamped from the product catalog: the exploit_remote_service
    # rule needs "does this software listen on the CAN_REACH port?" inside one
    # Cypher pattern, so the listening ports must live on the node. [] means
    # "unknown ports" and, as in the oracle, matches any port.
    run_batched(
        g,
        """
        UNWIND $rows AS r MERGE (s:Software {id: r.id})
        SET s.vendor = r.vendor, s.product = r.product, s.version = r.version, s.cpe = r.cpe,
            s.ports = r.ports
        """,
        [{**vars(s), "ports": _ports(s)} for s in ds.software],
    )

    # --- Vuln (denormalised CVE copy) ---
    # `likelihood` is stamped with attack_rules.exploit_likelihood, the ONE place
    # the formula lives. The S2 Cypher derivation reads it instead of
    # re-implementing the formula, so the oracle and the graph cannot drift.
    run_batched(
        g,
        """
        UNWIND $rows AS r MERGE (v:Vuln {id: r.id})
        SET v.cve = r.cve, v.cvss = r.cvss, v.av = r.av, v.pr = r.pr, v.ui = r.ui,
            v.epss = r.epss, v.kev = r.kev, v.ransomware = r.ransomware,
            v.likelihood = r.likelihood
        """,
        [{**vars(v), "likelihood": _likelihood(v)} for v in ds.vulns],
    )

    # --- Finding ---
    run_batched(
        g,
        """
        UNWIND $rows AS r MERGE (f:Finding {id: r.id})
        SET f.scanner = r.scanner, f.first_seen = r.first_seen, f.status = r.status
        """,
        [vars(f) for f in ds.findings],
    )

    # --- Identity (+ User/Role/ServiceAccount sub-label) ---
    run_batched(
        g,
        """
        UNWIND $rows AS r MERGE (i:Identity {id: r.id})
        SET i.kind = r.kind, i.name = r.name, i.over_broad = r.over_broad
        """,
        [vars(i) for i in ds.identities],
    )
    for kind in IDENTITY_KINDS:
        ids = [{"id": i.id} for i in ds.identities if i.kind == kind]
        if ids:
            # `SET i:<kind>` adds the sub-label; kind is from our enum, not input.
            run_batched(g, f"UNWIND $rows AS r MATCH (i:Identity {{id: r.id}}) SET i:{kind}", ids)

    # --- Secret / DataStore / Control ---
    run_batched(
        g,
        "UNWIND $rows AS r MERGE (s:Secret {id: r.id}) "
        "SET s.kind = r.kind, s.requires_priv = r.requires_priv",
        [vars(s) for s in ds.secrets],
    )
    run_batched(
        g,
        """
        UNWIND $rows AS r MERGE (d:DataStore {id: r.id})
        SET d.kind = r.kind, d.crown_jewel = r.crown_jewel, d.sensitivity = r.sensitivity
        """,
        [vars(d) for d in ds.datastores],
    )
    run_batched(
        g,
        "UNWIND $rows AS r MERGE (c:Control {id: r.id}) SET c.kind = r.kind",
        [vars(c) for c in ds.controls],
    )

    # --- Company layer: people, teams, rotations, decisions, tickets ---
    # Plain property bags, loaded the same way: `SET n += r` copies every field.
    # A None field (an ADR without a port, an open ticket's `closed`) is simply
    # not stored, because FalkorDB drops properties set to null.
    for label in ("Person", "Team", "OnCall", "ADR", "Ticket"):
        rows = [vars(o) for o in _NODE_LABEL[label](ds)]
        if rows:
            run_batched(g, f"UNWIND $rows AS r MERGE (n:{label} {{id: r.id}}) SET n += r", rows)

    # --- Edges, grouped by (type, src label, dst label) for index-backed MATCH ---
    label = _label_map(ds)
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for e in ds.edges:
        src_l, dst_l = label.get(e.src), label.get(e.dst)
        if not src_l or not dst_l:
            continue
        groups.setdefault((e.type, src_l, dst_l), []).append(
            {"src": e.src, "dst": e.dst, "props": e.props}
        )

    for (etype, src_l, dst_l), rows in groups.items():
        # MERGE on the edge's KEY property (if any) so parallel edges that
        # differ by that property survive — e.g. two CAN_REACH on different
        # ports are two edges, not one. Without this, MERGE would collapse them.
        key = EDGE_KEY.get(etype)
        key_pat = f" {{{key}: r.props.{key}}}" if key else ""
        run_batched(
            g,
            f"""
            UNWIND $rows AS r
            MATCH (a:{src_l} {{id: r.src}}), (b:{dst_l} {{id: r.dst}})
            MERGE (a)-[rel:{etype}{key_pat}]->(b)
            SET rel += r.props
            """,
            rows,
        )

    return _counts(db, g, ds)


def _ports(sw) -> list[int]:
    spec = PRODUCTS_BY_ID.get(f"{sw.vendor}:{sw.product}")
    return list(spec.ports) if spec else []


def _likelihood(v) -> float:
    return exploit_likelihood(
        VulnSignals(av=v.av, pr=v.pr, ui=v.ui, epss=v.epss, kev=v.kev, cvss=v.cvss)
    )


# The property that makes two edges of a type distinct (for MERGE + counts).
EDGE_KEY = {
    "EXPOSES": "port",
    "CAN_REACH": "port",
    "CAN": "action",
    "MITIGATES": "asset",
}


def canonical_edge_count(ds: Dataset) -> int:
    """How many edges the FalkorDB load will contain after MERGE dedup.

    Two edges collapse iff they share (type, src, dst) and the same key
    property. This is what the 'FalkorDB counts match generator' test compares
    against, so the test is exact rather than approximate.
    """
    seen: set[tuple] = set()
    label = _label_map(ds)
    for e in ds.edges:
        if e.src not in label or e.dst not in label:
            continue
        key = EDGE_KEY.get(e.type)
        keyval = e.props.get(key) if key else None
        seen.add((e.type, e.src, e.dst, keyval))
    return len(seen)


def _counts(db: FalkorDB, g, ds: Dataset) -> dict:
    def count(q: str) -> int:
        res = g.query(q)
        return int(res.result_set[0][0]) if res.result_set else 0

    nodes = count("MATCH (n) RETURN count(n)")
    edges = count("MATCH ()-[r]->() RETURN count(r)")
    return {
        "org": ds.org,
        "assets": count("MATCH (a:Asset) RETURN count(a)"),
        "findings": count("MATCH (f:Finding) RETURN count(f)"),
        "criticals": count("MATCH (v:Vuln) WHERE v.cvss >= 9.0 RETURN count(v)"),
        "exposed": count("MATCH (:Internet)-[:EXPOSES]->(a:Asset) RETURN count(DISTINCT a)"),
        "nodes": nodes,
        "edges": edges,
        "memory_mb": memory_usage_mb(db, ds.org),
    }
