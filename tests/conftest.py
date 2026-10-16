"""Shared fixtures. Unit tests need only the committed snapshot; integration
tests (marked) need a running FalkorDB and skip if it is down."""

from __future__ import annotations

import json

import pytest

from reachable_core.db import connect, ping
from reachable_core.settings import get_settings
from reachable_orggen.build import generate_org
from reachable_orggen.generate import GenConfig

ORGS = ["org_a", "org_b", "org_c"]
TEST_SCALE = 0.05
TEST_SEED = 42


@pytest.fixture(scope="session")
def builds():
    """All three orgs built once at a small, fast scale."""
    cfg = GenConfig(scale=TEST_SCALE)
    return {org: generate_org(org, TEST_SEED, cfg) for org in ORGS}


@pytest.fixture(scope="session")
def snapshot_cves():
    snap = get_settings().threatintel_dir / "snapshot" / "cves.json"
    recs = json.loads(snap.read_text(encoding="utf-8"))
    return {r["id"]: r for r in recs}


@pytest.fixture(scope="session")
def snapshot_attack():
    snap = get_settings().threatintel_dir / "snapshot" / "attack.json"
    return json.loads(snap.read_text(encoding="utf-8"))


def load_scans(db, org: str, base: str, *, scale: float = TEST_SCALE):
    """Scan v1 of `org` into graph `base` and its week-later rescan v2 into
    `base`_v2 (the naming exposure_drift / the Sentinel expect), both derived.
    Returns (v1 build, v2 build, the planted new path)."""
    from reachable_graph.derive import derive
    from reachable_orggen.build import drift_org
    from reachable_orggen.load_falkordb import load_org

    cfg = GenConfig(scale=scale)
    ob1 = generate_org(org, TEST_SEED, cfg)
    ob1.dataset.org = base
    load_org(db, ob1.dataset)
    derive(db.select_graph(base))
    ob2, new_path = drift_org(org, TEST_SEED, cfg)
    ob2.dataset.org = f"{base}_v2"
    load_org(db, ob2.dataset)
    derive(db.select_graph(f"{base}_v2"))
    return ob1, ob2, new_path


def drop(db, *names: str) -> None:
    for n in names:
        if n in db.list_graphs():
            db.select_graph(n).delete()


@pytest.fixture(scope="session")
def db():
    try:
        conn = connect()
        ping(conn)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"FalkorDB not reachable (run `make up`): {exc}")
    return conn


EVAL_GRAPH = "test_eval"


@pytest.fixture(scope="session")
def eval_env(db):
    """S7: one org at test scale as graph AND Postgres mirror `test_eval` (derived,
    with its eval views), the in-process MCP server pointed at it, and its truth
    from the generator's own labels. Skips if Postgres is down."""
    import psycopg

    import reachable_mcp.server as mcp_server
    from reachable_eval.scoring import truth_from_labels
    from reachable_eval.store import ScanRef, ensure_eval_views, load_scan
    from reachable_graph.derive import derive
    from reachable_graph.tools import GraphTools
    from reachable_orggen.labels import labels_payload
    from reachable_orggen.load_falkordb import load_org
    from reachable_orggen.load_postgres import drop_org_postgres, load_org_postgres

    s = get_settings()
    try:
        psycopg.connect(s.postgres_dsn, connect_timeout=3).close()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Postgres not reachable (run `make up`): {exc}")
    ob = generate_org("org_a", TEST_SEED, GenConfig(scale=TEST_SCALE))
    labels = labels_payload(ob)
    ob.dataset.org = EVAL_GRAPH
    load_org(db, ob.dataset)
    derive(db.select_graph(EVAL_GRAPH))
    load_org_postgres(ob.dataset, s)
    ensure_eval_views(EVAL_GRAPH, s)
    # Session-scoped: the patched server outlives the eval tests, so keep every
    # configured org allowed too (harmless since S8: test_mcp points the server at
    # its own graphs for its module and restores this one after).
    tools = GraphTools(db, allowed_orgs=[*s.graphs, EVAL_GRAPH])
    ref = ScanRef("org_a", "v1", EVAL_GRAPH)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(mcp_server, "_tools", lambda: tools)
        yield {
            "ref": ref,
            "data": load_scan(ref, s),
            "truth": truth_from_labels(labels),
            "labels": labels,
            "db": db,
        }
    drop(db, EVAL_GRAPH)
    for schema in (EVAL_GRAPH, f"eval_{EVAL_GRAPH}", f"rag_{EVAL_GRAPH}"):
        drop_org_postgres(schema, s)
