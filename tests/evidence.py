"""Evidence validity check shared by the company / memory tool tests: every node
id and every edge a ToolResult cites must exist in the graph."""

from __future__ import annotations

from reachable_graph.models import Evidence
from reachable_graph.tools import label_of


def missing_evidence(graph, ev: Evidence) -> list[str]:
    missing: list[str] = []
    ids = set(ev.node_ids) | {i for p in ev.paths for i in p}
    ids |= {x for e in ev.edges for x in (e.src, e.dst)}
    for nid in sorted(ids):
        label = label_of(nid)
        if label is None:
            missing.append(f"unlabelled id {nid}")
            continue
        if not graph.ro_query(f"MATCH (n:{label} {{id: $id}}) RETURN 1", {"id": nid}).result_set:
            missing.append(nid)
    for e in ev.edges:
        ls, ld = label_of(e.src), label_of(e.dst)
        if e.key:
            q = f"MATCH (:{ls} {{id: $s}})-[r:{e.rel} {{key: $k}}]->(:{ld} {{id: $d}}) RETURN 1"
        else:
            q = f"MATCH (:{ls} {{id: $s}})-[r:{e.rel}]->(:{ld} {{id: $d}}) RETURN 1"
        if not graph.ro_query(q, {"s": e.src, "d": e.dst, "k": e.key}).result_set:
            missing.append(f"{e.src}-[{e.rel}]->{e.dst}")
    return missing
