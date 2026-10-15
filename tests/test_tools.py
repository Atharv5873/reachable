"""Per-tool unit tests on the tiny hand-built graph (answers worked out in tiny_graph.py)."""

from __future__ import annotations

import math

import pytest
import tiny_graph as T
from pydantic import ValidationError

from reachable_graph.derive import derive
from reachable_graph.tools import GraphTools, ToolError, force_limit, residual_min_cut

pytestmark = pytest.mark.integration

P1 = ["internet", T.WEB1, T.DBHOST, T.S1, T.DS1]
P2 = ["internet", T.WEB2, T.DBHOST, T.S1, T.DS1]
P3 = ["internet", T.WEB1, T.S2, T.BOX, T.S3, T.DS1]


@pytest.fixture(scope="module")
def tools(db):
    g = T.build(db)
    derive(g)
    yield GraphTools(db, allowed_orgs=[T.ORG])
    g.delete()


def _seqs(result):
    return [[n["id"] for n in p["nodes"]] for p in result.data["paths"]]


def test_org_allowlist(tools):
    with pytest.raises(ToolError):
        tools.attack_paths("org_zzz")


def test_derive_on_tiny(tools, db):
    rules = dict(
        db.select_graph(T.ORG)
        .ro_query("MATCH ()-[e:ATTACK_STEP]->() RETURN e.rule, count(e)")
        .result_set
    )
    # web1+web2 public (web3 mitigated), web1->db and web2->db (port 22 adds nothing),
    # 1 folded privesc, creds s1 + s3, ssh s2, db s1 + s3.
    assert rules == {
        "exploit_public_facing": 2,
        "exploit_remote_service": 2,
        "local_privesc": 1,
        "creds_in_files": 2,
        "ssh_with_stolen_key": 1,
        "db_with_password": 2,
    }


def test_exposure_surface(tools):
    r = tools.exposure_surface(T.ORG)
    by = {a["asset"]: a for a in r.data["assets"]}
    assert set(by) == {T.WEB1, T.WEB2, T.WEB3}
    assert [x["finding"] for x in by[T.WEB1]["exploitable"]] == [T.F1]
    assert by[T.WEB3]["exploitable"] == []
    assert by[T.WEB3]["blocked_by_control"][0]["control_kind"] == "waf"


def test_attack_paths_ranked_by_likelihood(tools):
    r = tools.attack_paths(T.ORG, k=10)
    assert _seqs(r) == [P1, P3, P2]
    lk = [p["likelihood"] for p in r.data["paths"]]
    assert lk[0] == pytest.approx(0.9 * 0.8 * 0.9 * 0.95, rel=1e-6)
    assert lk[1] == pytest.approx(0.9 * 0.6 * 0.9 * 0.95 * 0.9 * 0.95, rel=1e-6)
    assert lk[2] == pytest.approx(0.5 * 0.8 * 0.9 * 0.95, rel=1e-6)
    # The folded privesc hop carries the privesc finding as its fix token.
    p3 = r.data["paths"][1]["steps"]
    assert (p3[1]["rule"], p3[1]["fix_token"]) == ("local_privesc", T.F5)
    assert r.truncated is False


def test_attack_paths_k_and_source(tools):
    r = tools.attack_paths(T.ORG, k=1)
    assert _seqs(r) == [P1] and r.truncated is True
    r = tools.attack_paths(T.ORG, source_id=T.WEB2, k=5)
    assert _seqs(r) == [P2[1:]]
    assert tools.attack_paths(T.ORG, target_id=T.DS2).data["paths"] == []


def test_blast_radius(tools):
    r = tools.blast_radius(T.ORG, T.WEB2)
    assert {n["id"] for n in r.data["reached"]} == {T.DBHOST, T.S1, T.DS1}
    assert r.data["crown_jewels"] == [T.DS1]
    assert tools.blast_radius(T.ORG, T.WEB3).data["reached"] == []


def test_min_cut_entry_and_crown(tools):
    r = tools.min_cut(T.ORG)
    assert r.data["max_flow"] == 2
    assert r.data["fix_tokens"] == sorted([T.F1, T.F2])
    assert r.data["findings"] == sorted([T.F1, T.F2])
    c = tools.min_cut(T.ORG, prefer="crown")
    assert c.data["fix_tokens"] == sorted([f"step:db:{T.S1}:{T.DS1}", f"step:db:{T.S3}:{T.DS1}"])


def test_residual_recovery_picks_cut_not_just_saturated_edges():
    """Two unit gates in series on one path are BOTH saturated; only one is the cut."""
    steps = [
        {"src": "internet", "dst": "a", "fix_token": "t1"},
        {"src": "a", "dst": "z", "fix_token": "t2"},
    ]
    flows = {
        ("internet", "fix_in:t1"): 1,
        ("fix_in:t1", "fix_out:t1"): 1,
        ("fix_out:t1", "a"): 1,
        ("a", "fix_in:t2"): 1,
        ("fix_in:t2", "fix_out:t2"): 1,
        ("fix_out:t2", "z"): 1,
    }
    assert residual_min_cut(steps, flows, ["z"]) == ["t1"]
    assert residual_min_cut(steps, flows, ["z"], prefer="crown") == ["t2"]


def test_choke_points(tools):
    r = tools.choke_points(T.ORG)
    top = r.data["choke_points"][0]
    assert top["node"] in {T.WEB1, T.DBHOST, T.S1}
    assert top["crown_paths_through"] == 2 and top["crown_paths_total"] == 3


def test_why_step_folded_privesc(tools, db):
    key = (
        db.select_graph(T.ORG)
        .ro_query("MATCH ()-[e:ATTACK_STEP {rule: 'local_privesc'}]->() RETURN e.key")
        .result_set[0][0]
    )
    r = tools.why_step(T.ORG, key)
    assert r.data["fix"]["token"] == T.F5
    assert {b["id"] for b in r.data["because"]} == {T.F5, T.nid("vuln", 5), T.nid("sw", 5), T.S2}
    rels = {(e["src"], e["rel"], e["dst"]) for e in r.data["structural_edges"]}
    assert (T.WEB1, "HOLDS", T.S2) in rels and (T.F5, "ON", T.WEB1) in rels
    with pytest.raises(ToolError):
        tools.why_step(T.ORG, "no|such|key")


def test_simulate_fix(tools, db):
    r = tools.simulate_fix(T.ORG, [T.F1, T.F2])
    assert r.data["all_crown_jewels_disconnected"] is True
    r = tools.simulate_fix(T.ORG, [T.F4])
    assert r.data["reachable_after"] == [T.DS1]
    assert [[n["id"] for n in p["nodes"]] for p in r.data["remaining_paths"]] == [P3]
    r = tools.simulate_fix(T.ORG, ["tiny:finding:99999"])
    assert r.data["unknown_tokens"] == ["tiny:finding:99999"]
    # the org graph itself is untouched and no scratch copy is left behind
    assert len(tools.attack_paths(T.ORG, k=10).data["paths"]) == 3
    assert not [g for g in db.list_graphs() if g.startswith("scratch__")]


def test_vuln_intel(tools, db):
    if "threatintel" not in db.list_graphs():
        pytest.skip("threatintel not loaded")
    r = tools.vuln_intel("CVE-2021-44228")
    assert r.data["kev"] is True and r.data["cvss"] == 10.0
    assert [t["id"] for t in r.data["techniques"]] == ["T1190", "T1210"]
    with pytest.raises(ValidationError):
        tools.vuln_intel("not-a-cve")


def test_run_cypher_readonly(tools):
    r = tools.run_cypher_readonly(T.ORG, "MATCH (a:Asset) RETURN a.id ORDER BY a.id", limit=2)
    assert len(r.data["rows"]) == 2 and r.truncated is True
    assert r.data["executed"].endswith("LIMIT 3")
    with pytest.raises(ToolError):
        tools.run_cypher_readonly(T.ORG, "CREATE (:Pwned)")
    with pytest.raises(ToolError):
        tools.run_cypher_readonly(T.ORG, "MATCH (n) DETACH DELETE n")


def test_force_limit():
    assert force_limit("MATCH (n) RETURN n", 10).endswith("LIMIT 10")
    assert force_limit("MATCH (n) RETURN n LIMIT 5000;", 10).endswith("LIMIT 10")
    assert force_limit("MATCH (n) RETURN n limit 3", 10).endswith("LIMIT 3")


def test_stubs_are_typed_todos(tools):
    for fn in (tools.owners, tools.triage_memory):
        with pytest.raises(NotImplementedError):
            fn(T.ORG, "x")
    with pytest.raises(NotImplementedError):
        tools.exposure_drift(T.ORG)


def test_path_likelihood_is_exp_minus_cost(tools):
    for p in tools.attack_paths(T.ORG, k=10).data["paths"]:
        assert p["likelihood"] == pytest.approx(math.exp(-p["cost"]), rel=1e-5)
        assert p["likelihood"] == pytest.approx(
            math.prod(s["likelihood"] for s in p["steps"]), rel=1e-6
        )
