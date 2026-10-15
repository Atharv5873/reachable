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


@pytest.fixture(scope="session")
def db():
    try:
        conn = connect()
        ping(conn)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"FalkorDB not reachable (run `make up`): {exc}")
    return conn
