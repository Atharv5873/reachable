"""Postgres mirror of an org, one schema per org (org_a / org_b / org_c).

BASELINE ONLY. FalkorDB is the primary store; this relational copy exists so S7
can compare graph traversal against SQL recursive joins on identical data. The
shape is deliberately simple: one table per node type plus a generic `edges`
table (src, dst, type, props jsonb), which is all the baseline needs.
"""

from __future__ import annotations

import json

import psycopg

from reachable_core.settings import Settings, get_settings

from .model import Dataset

_NODE_TABLES = {
    "zones": lambda ds: [(z.id, z.name, z.trust) for z in ds.zones],
    "assets": lambda ds: [(a.id, a.kind, a.zone, a.env, a.hostname, a.cloud) for a in ds.assets],
    "software": lambda ds: [(s.id, s.vendor, s.product, s.version, s.cpe) for s in ds.software],
    "vulns": lambda ds: [
        (v.id, v.cve, v.cvss, v.av, v.pr, v.ui, v.epss, v.kev, v.ransomware) for v in ds.vulns
    ],
    "findings": lambda ds: [(f.id, f.scanner, f.first_seen, f.status) for f in ds.findings],
    "identities": lambda ds: [(i.id, i.kind, i.name, i.over_broad) for i in ds.identities],
    "secrets": lambda ds: [(s.id, s.kind, s.requires_priv) for s in ds.secrets],
    "datastores": lambda ds: [(d.id, d.kind, d.crown_jewel, d.sensitivity) for d in ds.datastores],
    "controls": lambda ds: [(c.id, c.kind) for c in ds.controls],
    "persons": lambda ds: [(p.id, p.name, p.role) for p in ds.persons],
    "teams": lambda ds: [(t.id, t.name, t.change_effort) for t in ds.teams],
    "oncalls": lambda ds: [(o.id, o.window, o.start, o.end, o.current) for o in ds.oncalls],
    "adrs": lambda ds: [
        (a.id, a.title, a.decision, a.date, a.status, a.port, a.cidr) for a in ds.adrs
    ],
    "tickets": lambda ds: [(t.id, t.title, t.status, t.opened, t.closed) for t in ds.tickets],
}

_DDL = {
    "zones": "id text primary key, name text, trust int",
    "assets": "id text primary key, kind text, zone text, env text, hostname text, cloud bool",
    "software": "id text primary key, vendor text, product text, version text, cpe text",
    "vulns": (
        "id text primary key, cve text, cvss real, av text, pr text, "
        "ui text, epss real, kev bool, ransomware bool"
    ),
    "findings": "id text primary key, scanner text, first_seen bigint, status text",
    "identities": "id text primary key, kind text, name text, over_broad bool",
    "secrets": "id text primary key, kind text, requires_priv bool",
    "datastores": "id text primary key, kind text, crown_jewel bool, sensitivity text",
    "controls": "id text primary key, kind text",
    "persons": "id text primary key, name text, role text",
    "teams": "id text primary key, name text, change_effort int",
    "oncalls": (
        "id text primary key, time_window text, start_ts bigint, end_ts bigint, current bool"
    ),
    "adrs": (
        "id text primary key, title text, decision text, date bigint, status text, "
        "port int, cidr text"
    ),
    "tickets": "id text primary key, title text, status text, opened bigint, closed bigint",
}

_COLS = {
    "zones": "(id, name, trust)",
    "assets": "(id, kind, zone, env, hostname, cloud)",
    "software": "(id, vendor, product, version, cpe)",
    "vulns": "(id, cve, cvss, av, pr, ui, epss, kev, ransomware)",
    "findings": "(id, scanner, first_seen, status)",
    "identities": "(id, kind, name, over_broad)",
    "secrets": "(id, kind, requires_priv)",
    "datastores": "(id, kind, crown_jewel, sensitivity)",
    "controls": "(id, kind)",
    "persons": "(id, name, role)",
    "teams": "(id, name, change_effort)",
    "oncalls": "(id, time_window, start_ts, end_ts, current)",
    "adrs": "(id, title, decision, date, status, port, cidr)",
    "tickets": "(id, title, status, opened, closed)",
}


def load_org_postgres(ds: Dataset, settings: Settings | None = None) -> dict:
    s = settings or get_settings()
    schema = ds.org
    with psycopg.connect(s.postgres_dsn) as conn, conn.cursor() as cur:
        cur.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        cur.execute(f"CREATE SCHEMA {schema}")
        for table, cols in _DDL.items():
            cur.execute(f"CREATE TABLE {schema}.{table} ({cols})")
        cur.execute(f"CREATE TABLE {schema}.edges (src text, dst text, type text, props jsonb)")

        for table, getter in _NODE_TABLES.items():
            rows = getter(ds)
            if not rows:
                continue
            placeholders = ", ".join(["%s"] * len(rows[0]))
            cur.executemany(
                f"INSERT INTO {schema}.{table} {_COLS[table]} VALUES ({placeholders})", rows
            )

        edge_rows = [(e.src, e.dst, e.type, json.dumps(e.props)) for e in ds.edges]
        cur.executemany(
            f"INSERT INTO {schema}.edges (src, dst, type, props) VALUES (%s, %s, %s, %s)",
            edge_rows,
        )
        cur.execute(f"CREATE INDEX ON {schema}.edges (src)")
        cur.execute(f"CREATE INDEX ON {schema}.edges (dst)")
        cur.execute(f"CREATE INDEX ON {schema}.edges (type)")
        conn.commit()
    return {"schema": schema, "edge_rows": len(ds.edges)}


def drop_org_postgres(org: str, settings: Settings | None = None) -> None:
    s = settings or get_settings()
    with psycopg.connect(s.postgres_dsn) as conn, conn.cursor() as cur:
        cur.execute(f"DROP SCHEMA IF EXISTS {org} CASCADE")
        conn.commit()
