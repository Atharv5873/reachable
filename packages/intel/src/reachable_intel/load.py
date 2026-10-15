"""Load the committed snapshot into the FalkorDB graph `threatintel`.

Nodes: CVE, CWE, Product, Technique, Tactic.
Edges: (CVE)-[:HAS_CWE]->(CWE), (CVE)-[:AFFECTS]->(Product),
       (Technique)-[:IN_TACTIC]->(Tactic).

All writes are parameterised batched UNWIND + MERGE, so the load is idempotent:
running it twice leaves the same graph. Indexes on every id are created first,
so the MERGEs are index-backed rather than full scans.
"""

from __future__ import annotations

import json

from falkordb import FalkorDB

from reachable_core.db import create_range_index, drop_graph, memory_usage_mb, run_batched
from reachable_core.schema import THREATINTEL_GRAPH, THREATINTEL_INDEXES
from reachable_core.settings import Settings, get_settings

from .normalise import snapshot_dir


def load_threatintel(db: FalkorDB, settings: Settings | None = None, *, fresh: bool = True) -> dict:
    s = settings or get_settings()
    snap = snapshot_dir(s)
    cves = json.loads((snap / "cves.json").read_text(encoding="utf-8"))
    attack = json.loads((snap / "attack.json").read_text(encoding="utf-8"))

    if fresh:
        drop_graph(db, THREATINTEL_GRAPH)
    g = db.select_graph(THREATINTEL_GRAPH)

    # Indexes first so every MERGE below is index-backed.
    for label, prop in THREATINTEL_INDEXES.items():
        create_range_index(g, label, prop)

    # --- CVE nodes ---
    run_batched(
        g,
        """
        UNWIND $rows AS row
        MERGE (c:CVE {id: row.id})
        SET c.cvss = row.cvss, c.severity = row.severity, c.vector = row.vector,
            c.av = row.av, c.pr = row.pr, c.ui = row.ui, c.scope = row.scope,
            c.published = row.published, c.kev = row.kev,
            c.kev_ransomware = row.kev_ransomware,
            c.epss = row.epss, c.epss_percentile = row.epss_percentile
        """,
        cves,
    )

    # --- CWE nodes + HAS_CWE edges ---
    cwe_rows = [{"cve": c["id"], "cwe": w} for c in cves for w in c["cwes"]]
    run_batched(
        g,
        """
        UNWIND $rows AS row
        MATCH (c:CVE {id: row.cve})
        MERGE (w:CWE {id: row.cwe})
        MERGE (c)-[:HAS_CWE]->(w)
        """,
        cwe_rows,
    )

    # --- Product nodes + AFFECTS edges ---
    prod_rows = []
    for c in cves:
        for pid in c["products"]:
            vendor, _, product = pid.partition(":")
            prod_rows.append({"cve": c["id"], "pid": pid, "vendor": vendor, "product": product})
    run_batched(
        g,
        """
        UNWIND $rows AS row
        MATCH (c:CVE {id: row.cve})
        MERGE (p:Product {id: row.pid})
        SET p.vendor = row.vendor, p.product = row.product
        MERGE (c)-[:AFFECTS]->(p)
        """,
        prod_rows,
    )

    # --- Tactic nodes ---
    run_batched(
        g,
        """
        UNWIND $rows AS row
        MERGE (a:Tactic {id: row.id})
        SET a.name = row.name, a.shortname = row.shortname, a.url = row.url
        """,
        attack["tactics"],
    )

    # --- Technique nodes ---
    run_batched(
        g,
        """
        UNWIND $rows AS row
        MERGE (t:Technique {id: row.id})
        SET t.name = row.name, t.url = row.url
        """,
        attack["techniques"],
    )

    # --- Technique-[:IN_TACTIC]->Tactic edges ---
    tactic_edges = [
        {"tech": t["id"], "tactic": tid} for t in attack["techniques"] for tid in t["tactics"]
    ]
    run_batched(
        g,
        """
        UNWIND $rows AS row
        MATCH (t:Technique {id: row.tech}), (a:Tactic {id: row.tactic})
        MERGE (t)-[:IN_TACTIC]->(a)
        """,
        tactic_edges,
    )

    # Counts for the report. int() casts the float FalkorDB returns for counts.
    def count(q: str) -> int:
        res = g.query(q)
        return int(res.result_set[0][0]) if res.result_set else 0

    stats = {
        "cve": count("MATCH (c:CVE) RETURN count(c)"),
        "cwe": count("MATCH (w:CWE) RETURN count(w)"),
        "product": count("MATCH (p:Product) RETURN count(p)"),
        "technique": count("MATCH (t:Technique) RETURN count(t)"),
        "tactic": count("MATCH (a:Tactic) RETURN count(a)"),
        "affects": count("MATCH ()-[r:AFFECTS]->() RETURN count(r)"),
        "has_cwe": count("MATCH ()-[r:HAS_CWE]->() RETURN count(r)"),
        "memory_mb": memory_usage_mb(db, THREATINTEL_GRAPH),
    }
    return stats
