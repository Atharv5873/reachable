"""Integration: load an org into FalkorDB and check counts match the generator."""

from __future__ import annotations

import pytest
from conftest import TEST_SCALE, TEST_SEED

from reachable_orggen.build import generate_org
from reachable_orggen.generate import GenConfig
from reachable_orggen.load_falkordb import canonical_edge_count, load_org

pytestmark = pytest.mark.integration


def test_falkordb_counts_match_generator(db):
    ob = generate_org("org_a", TEST_SEED, GenConfig(scale=TEST_SCALE))
    ds = ob.dataset
    graph_name = "test_org_a"
    # Load into a throwaway graph so we never touch the real org_a.
    ds.org = graph_name
    try:
        stats = load_org(db, ds)
        assert stats["assets"] == len(ds.assets)
        assert stats["findings"] == len(ds.findings)
        assert stats["edges"] == canonical_edge_count(ds)
        node_total = (
            len(ds.assets)
            + len(ds.software)
            + len(ds.vulns)
            + len(ds.findings)
            + len(ds.identities)
            + len(ds.secrets)
            + len(ds.datastores)
            + len(ds.controls)
            + len(ds.zones)
            + 1  # +1 Internet
        )
        assert stats["nodes"] == node_total
    finally:
        db.select_graph(graph_name).delete()


def test_threatintel_graph_present(db):
    """The committed snapshot should be loaded (run `make intel`)."""
    if "threatintel" not in db.list_graphs():
        pytest.skip("threatintel graph not loaded (run `make intel`)")
    g = db.select_graph("threatintel")
    n = int(g.query("MATCH (c:CVE) RETURN count(c)").result_set[0][0])
    assert n > 1000
