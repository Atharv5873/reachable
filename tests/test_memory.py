"""Memory repositories (Track 02): round trips, expiry, versioning, and the
guarantee that memory writes never touch the infrastructure part of the graph.

Runs on a generated org loaded into a throwaway graph, so it starts with the
seeded prior memory, which these tests also read back through the repository.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from conftest import TEST_SCALE, TEST_SEED
from evidence import missing_evidence

from reachable_core.schema import MEMORY_INDEXES
from reachable_graph.derive import derive
from reachable_graph.memory import (
    WRITE_QUERIES,
    MemoryError_,
    MemoryRepo,
    input_hash,
)
from reachable_graph.tools import GraphTools
from reachable_orggen.build import generate_org
from reachable_orggen.generate import NOW, GenConfig
from reachable_orggen.load_falkordb import load_org
from reachable_orggen.memory_seed import LIVE_UNTIL

pytestmark = pytest.mark.integration

GRAPH = "test_memory_org_a"
DAY = 86400
MEMORY_LABELS = set(MEMORY_INDEXES)


@pytest.fixture(scope="module")
def env(db):
    ob = generate_org("org_a", TEST_SEED, GenConfig(scale=TEST_SCALE))
    ob.dataset.org = GRAPH
    load_org(db, ob.dataset)
    g = db.select_graph(GRAPH)
    derive(g)
    repo = MemoryRepo(db, allowed_orgs=[GRAPH])
    yield ob, g, repo, GraphTools(db, allowed_orgs=[GRAPH])
    g.delete()


def infra_fingerprint(g) -> str:
    """Hash of every non-memory node (labels + properties) and every edge whose
    endpoints are both non-memory nodes. Memory writes must leave it unchanged."""
    nodes = g.ro_query("MATCH (n) RETURN labels(n), properties(n)").result_set
    edges = g.ro_query(
        "MATCH (a)-[r]->(b) RETURN labels(a), a.id, type(r), properties(r), labels(b), b.id"
    ).result_set
    keep_n = sorted(
        json.dumps([sorted(lbl), props], sort_keys=True, default=str)
        for lbl, props in nodes
        if not MEMORY_LABELS & set(lbl)
    )
    keep_e = sorted(
        json.dumps([a, t, p, b], sort_keys=True, default=str)
        for la, a, t, p, lb, b in edges
        if not MEMORY_LABELS & (set(la) | set(lb))
    )
    return hashlib.sha256(json.dumps([keep_n, keep_e]).encode()).hexdigest()


def finding_ids(ob, n=3):
    return [f.id for f in ob.dataset.findings if f.status == "open"][:n]


def test_run_round_trip_keeps_step_order(env):
    _, _, repo, _ = env
    steps = [
        ("exposure_surface", {"org": GRAPH, "limit": 50}),
        ("attack_paths", {"org": GRAPH, "k": 5}),
        ("min_cut", {"org": GRAPH, "prefer": "entry"}),
    ]
    run = repo.record_run(GRAPH, "triage", steps)
    assert [s.tool for s in run.steps] == [t for t, _ in steps]
    assert [s.seq for s in run.steps] == [0, 1, 2]
    assert run.chain_ok
    assert run.steps[1].input_hash == input_hash({"k": 5, "org": GRAPH})  # key order irrelevant
    # A second agent continues the SAME run (the handoff): order is preserved.
    repo.append_step(GRAPH, run.id, "simulate_fix", {"fix_tokens": ["x"]})
    again = repo.get_run(GRAPH, run.id)
    assert [s.seq for s in again.steps] == [0, 1, 2, 3] and again.chain_ok
    with pytest.raises(MemoryError_):
        repo.append_step(GRAPH, f"{GRAPH}:run:nope", "x", {})


def test_verdicts_round_trip(env):
    ob, _, repo, _ = env
    f1, f2, _ = finding_ids(ob)
    t = repo.start_triage(GRAPH)
    repo.record_verdict(GRAPH, f1, "schedule", "not on a crown path", triage_id=t, ts=NOW)
    repo.record_verdict(GRAPH, f1, "fix_now", "new path opened", triage_id=t, ts=NOW + DAY)
    got = repo.verdicts(GRAPH, [f1, f2])
    assert [(v.finding, v.decision) for v in got] == [(f1, "fix_now"), (f1, "schedule")]
    with pytest.raises(MemoryError_):
        repo.record_verdict(GRAPH, f"{GRAPH}:finding:99999", "fix_now", "x")


def test_risk_acceptance_expiry_is_honoured(env):
    ob, _, repo, tools = env
    f1, f2, f3 = finding_ids(ob)
    person = ob.dataset.persons[0].id
    live = repo.record_risk_acceptance(
        GRAPH, [f1, f2], "compensating control", person, expires=NOW + 30 * DAY, created=NOW
    )
    repo.record_risk_acceptance(
        GRAPH, [f3], "short window", person, expires=NOW + DAY, created=NOW - 10 * DAY
    )
    at = NOW + 2 * DAY  # after the second one expired
    assert [r.id for r in repo.risk_acceptances(GRAPH, [f1, f3], now=at)] == [live.id]
    both = repo.risk_acceptances(GRAPH, [f1, f3], now=at, include_expired=True)
    assert {r.live for r in both} == {True, False}

    mem = tools.triage_memory(GRAPH, [f1, f3], as_of=at)
    by = {x["finding"]: x for x in mem.data["findings"]}
    assert by[f1]["suppressed"] is True
    assert by[f3]["suppressed"] is False and by[f3]["expired_acceptances"]
    # Earlier, while it was still in force, the same acceptance DID suppress f3.
    earlier = tools.triage_memory(GRAPH, [f3], as_of=NOW)
    assert earlier.data["findings"][0]["suppressed"] is True
    with pytest.raises(MemoryError_):
        repo.record_risk_acceptance(GRAPH, [f1], "x", person, expires=NOW, created=NOW)


def test_pattern_upsert_is_idempotent_and_listable(env):
    ob, _, repo, _ = env
    sw = ob.dataset.software[0].id
    vulns = [e.dst for e in ob.dataset.edges if e.type == "HAS_VULN" and e.src == sw][:1]
    t = repo.start_triage(GRAPH)
    p1 = repo.upsert_pattern(GRAPH, "recurring_cve", "first wording", [sw, *vulns], seen_in=t)
    p2 = repo.upsert_pattern(GRAPH, "recurring_cve", "better wording", [*vulns, sw])
    assert p1.id == p2.id and p2.description == "better wording"
    assert p2.about == sorted([sw, *vulns]) and p2.seen_in == [t]
    assert p1.id in [p.id for p in repo.patterns_about(GRAPH, [sw])]
    with pytest.raises(MemoryError_):  # a Pattern is about Asset/Software/Vuln only
        repo.upsert_pattern(GRAPH, "x", "y", [ob.dataset.findings[0].id])


def test_playbook_versioning_keeps_history(env):
    _, g, repo, _ = env
    tech = "T1078"
    v1 = repo.add_playbook_version(GRAPH, tech, "rotate the credential", ts=NOW)
    v2 = repo.add_playbook_version(GRAPH, tech, "rotate + check sessions", ts=NOW + 10 * DAY)
    assert (v1.version, v2.version, v2.supersedes) == (1, 2, v1.id)
    assert repo.current_playbook(GRAPH, tech).id == v2.id
    assert [p.version for p in repo.playbook_history(GRAPH, tech)] == [2, 1]
    assert repo.playbook_at(GRAPH, tech, NOW + DAY).id == v1.id  # what was true then
    assert repo.playbook_at(GRAPH, tech, NOW - DAY) is None
    n = g.ro_query(
        "MATCH (:Playbook {id: $n})-[:SUPERSEDES]->(:Playbook {id: $o}) RETURN count(*)",
        {"n": v2.id, "o": v1.id},
    ).result_set[0][0]
    assert n == 1


def test_playbook_version_race_is_detected(env, monkeypatch):
    """Two writers that both read v1 as current cannot both publish a v2."""
    _, _, repo, _ = env
    v1 = repo.add_playbook_version(GRAPH, "T1530", "remove the read grant", ts=NOW)
    repo.add_playbook_version(GRAPH, "T1530", "writer A", ts=NOW + DAY)
    monkeypatch.setattr(repo, "current_playbook", lambda org, tech: v1)  # writer B's stale read
    with pytest.raises(MemoryError_, match="already exists"):
        repo.add_playbook_version(GRAPH, "T1530", "writer B", ts=NOW + DAY)
    monkeypatch.undo()
    assert repo.current_playbook(GRAPH, "T1530").body == "writer A"


def test_seeded_memory_reads_back_through_the_repo(env):
    """The generator's seed and the repository share one schema."""
    ob, g, repo, tools = env
    ds = ob.dataset
    live, expired = sorted(ds.risk_acceptances, key=lambda r: -r.expires)
    assert live.expires == LIVE_UNTIL and expired.expires < NOW
    on = {e.src: e.dst for e in ds.edges if e.type == "ON" and e.src.split(":")[1] == "riskacc"}
    mem = tools.triage_memory(GRAPH, [on[live.id], on[expired.id]], as_of=NOW)
    by = {x["finding"]: x for x in mem.data["findings"]}
    assert by[on[live.id]]["suppressed"] is True
    assert by[on[expired.id]]["suppressed"] is False  # expired: on a crown path, not hidden
    assert len(by[on[live.id]]["verdicts"]) == 1  # the seeded accept_risk verdict
    assert missing_evidence(g, mem.evidence) == []

    assert repo.current_playbook(GRAPH, "T1190").version == 2
    assert repo.current_playbook(GRAPH, "T1190").supersedes.endswith(":T1190:v1")
    assert [p.version for p in repo.playbook_history(GRAPH, "T1190")] == [2, 1]
    assert repo.current_playbook(GRAPH, "T1210").version == 1
    run = repo.get_run(GRAPH, ds.runs[0].id)
    assert run.chain_ok and len(run.steps) == 3

    # The pattern reaches a finding on ANY vuln with its CVE (not only the ones
    # it is wired to): that is the "keeps reintroducing CVE-X" generalisation.
    pat = ds.patterns[0]
    cve = next(
        v.cve
        for v in ds.vulns
        if v.id in {e.dst for e in ds.edges if e.src == pat.id and e.type == "ABOUT"}
    )
    vuln_ids = {v.id for v in ds.vulns if v.cve == cve}
    f_any = next(e.src for e in ds.edges if e.type == "OF" and e.dst in vuln_ids)
    reach = tools.triage_memory(GRAPH, [f_any]).data["findings"][0]["patterns"]
    assert pat.id in reach


def test_memory_writes_never_touch_infrastructure(env):
    ob, g, repo, _ = env
    before = infra_fingerprint(g)
    f1, f2, _ = finding_ids(ob)
    rid = repo.start_run(GRAPH, "triage")
    repo.append_step(GRAPH, rid, "attack_paths", {"k": 3})
    t = repo.start_triage(GRAPH, run_id=rid)
    repo.record_verdict(GRAPH, f1, "fix_now", "x", triage_id=t)
    repo.record_risk_acceptance(GRAPH, [f2], "y", ob.dataset.persons[1].id, expires=LIVE_UNTIL)
    repo.upsert_pattern(GRAPH, "k", "d", [ob.dataset.assets[0].id], seen_in=t)
    repo.add_playbook_version(GRAPH, "T1021.004", "rotate keys")
    assert infra_fingerprint(g) == before


def test_repo_refuses_unknown_orgs_and_foreign_writes(env):
    _, _, repo, _ = env
    with pytest.raises(MemoryError_):
        repo.start_run("org_zzz", "triage")
    with pytest.raises(MemoryError_):
        repo._w(GRAPH, "MATCH (n:Asset) DETACH DELETE n", {})
    assert all("DELETE" not in q.upper() for q in WRITE_QUERIES)
