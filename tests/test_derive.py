"""Integration: the Cypher ATTACK_STEP derivation agrees with the networkx oracle.

This is the correctness anchor for every S2 tool: if the Internet -> crown-jewel
paths over ATTACK_STEP edges equal the oracle's paths (same hops, same rules,
same fix tokens), then attack_paths / min_cut / simulate_fix are computing over
the right graph.
"""

from __future__ import annotations

import json

import pytest
from conftest import ORGS, TEST_SCALE, TEST_SEED

from reachable_core.attack_rules import HOP_CAP
from reachable_core.settings import get_settings
from reachable_graph.compat import graph_path_to_chops, oracle_path_set, planted_node_sequence
from reachable_graph.derive import derive, edge_signature
from reachable_orggen.build import drift_org, generate_org
from reachable_orggen.generate import GenConfig
from reachable_orggen.load_falkordb import load_org

pytestmark = pytest.mark.integration

ALL_CROWN_PATHS = f"""
MATCH p = (:Internet)-[:ATTACK_STEP*1..{HOP_CAP}]->(:DataStore {{crown_jewel: true}})
RETURN [n IN nodes(p) | {{id: n.id, labels: labels(n)}}],
       [e IN relationships(p) | {{rule: e.rule, fix_token: e.fix_token}}]
"""


def _derived_paths(graph) -> set:
    return {graph_path_to_chops(n, s) for n, s in graph.ro_query(ALL_CROWN_PATHS).result_set}


@pytest.fixture(scope="module")
def derived_small(db):
    """Each org at test scale, loaded into a throwaway graph and derived."""
    out = {}
    for org in ORGS:
        ob = generate_org(org, TEST_SEED, GenConfig(scale=TEST_SCALE))
        name = f"test_derive_{org}"
        ob.dataset.org = name
        load_org(db, ob.dataset)
        g = db.select_graph(name)
        out[org] = (ob, g, derive(g))
    yield out
    for _, g, _ in out.values():
        g.delete()


@pytest.mark.parametrize("org", ORGS)
def test_derived_paths_equal_oracle_paths(derived_small, org):
    ob, g, _ = derived_small[org]
    want = oracle_path_set(ob.oracle.paths)
    got = _derived_paths(g)
    assert want, f"{org}: oracle found no paths"
    assert got == want, f"{org}: derived != oracle\n missing={want - got}\n extra={got - want}"


@pytest.fixture(scope="module")
def derived_v2(db):
    """Scan v2 (some findings fixed, one new path) of each org, derived."""
    out = {}
    for org in ORGS:
        ob, new_path = drift_org(org, TEST_SEED, GenConfig(scale=TEST_SCALE))
        name = f"test_derive_{org}_v2"
        ob.dataset.org = name
        load_org(db, ob.dataset)
        g = db.select_graph(name)
        derive(g)
        out[org] = (ob, new_path, g)
    yield out
    for _, _, g in out.values():
        g.delete()


@pytest.mark.parametrize("org", ORGS)
def test_status_filter_v1_unchanged_v2_shrinks(derived_small, derived_v2, org):
    """Only OPEN findings create steps. v1 (every planted finding open) keeps
    every planted path; in v2 the paths through a fixed finding vanish and the
    one path opened by the config change appears, in Cypher exactly as in the oracle."""
    ob1, g1, _ = derived_small[org]
    ob2, new_path, g2 = derived_v2[org]
    v1, v2 = _derived_paths(g1), _derived_paths(g2)
    assert len(v1) == len(ob1.ground_truth.paths)
    assert v2 == oracle_path_set(ob2.oracle.paths)

    fixed = set(ob2.ground_truth.fixed_findings)
    survivors = {p for p in v1 if not {h.fix for h in p} & fixed}
    assert len(survivors) < len(v1)
    new = v2 - survivors
    assert len(new) == 1 and survivors <= v2
    (p,) = new
    assert (p[0].src, *[h.dst for h in p]) == tuple(new_path.node_sequence())
    # No step anywhere is powered by a fixed finding.
    leaked = g2.ro_query(
        "MATCH ()-[e:ATTACK_STEP]->() MATCH (f:Finding) WHERE f.id = e.fix_token "
        "AND f.status <> 'open' RETURN count(e)"
    ).result_set[0][0]
    assert leaked == 0


@pytest.mark.parametrize("org", ORGS)
def test_every_planted_path_is_derived(derived_small, org):
    ob, g, _ = derived_small[org]
    seqs = {tuple([p[0].src] + [h.dst for h in p]) for p in _derived_paths(g)}
    for p in ob.ground_truth.paths:
        hops = [{"from": h.src, "to": h.dst, "rule": h.rule} for h in p.hops]
        assert planted_node_sequence({"hops": hops}) in seqs, f"{org}: {p.name} not derived"


def test_derive_is_idempotent(derived_small):
    _, g, _ = derived_small["org_a"]
    before = edge_signature(g)
    stats = derive(g)
    assert stats["swept_stale"] == 0
    assert edge_signature(g) == before


def test_sweep_removes_steps_whose_precondition_vanished(derived_small):
    """Delete one HOLDS edge; re-derive must drop the creds step it justified."""
    _, g, _ = derived_small["org_b"]
    row = g.ro_query(
        "MATCH (a:Asset)-[:HOLDS]->(s:Secret {requires_priv: false}) RETURN a.id, s.id LIMIT 1"
    ).result_set[0]
    token = f"step:creds:{row[0]}:{row[1]}"
    g.query(
        "MATCH (a:Asset {id: $a})-[h:HOLDS]->(s:Secret {id: $s}) DELETE h",
        {"a": row[0], "s": row[1]},
    )
    stats = derive(g)
    assert stats["swept_stale"] >= 1
    left = g.ro_query(
        "MATCH ()-[e:ATTACK_STEP {fix_token: $t}]->() RETURN count(e)", {"t": token}
    ).result_set[0][0]
    assert left == 0


def test_flow_layer_is_a_simple_graph(derived_small):
    """algo.maxFlow rejects multi-edges; node splitting must never create any."""
    _, g, _ = derived_small["org_a"]
    dup = g.ro_query(
        "MATCH (a)-[f:FLOW]->(b) WITH a, b, count(f) AS c WHERE c > 1 RETURN count(*)"
    ).result_set[0][0]
    assert dup == 0


@pytest.mark.parametrize("org", ORGS)
def test_live_org_graph_matches_oracle(db, org):
    """The seeded org graphs (make seed && make derive) match the oracle too."""
    labels_path = get_settings().orgs_dir / org / "labels.json"
    if org not in db.list_graphs() or not labels_path.exists():
        pytest.skip("org not seeded (run `make seed derive`)")
    g = db.select_graph(org)
    if not g.ro_query("MATCH ()-[e:ATTACK_STEP]->() RETURN count(e)").result_set[0][0]:
        pytest.skip("org not derived (run `make derive`)")
    labels = json.loads(labels_path.read_text("utf-8"))
    ob = generate_org(org, labels["seed"], GenConfig(scale=labels["scale"]))
    assert _derived_paths(g) == oracle_path_set(ob.oracle.paths)
