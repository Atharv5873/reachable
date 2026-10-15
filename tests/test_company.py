"""Company-layer tools (Track 03) on a generated org whose answers we know.

The expectations are computed from the generator's Dataset (the source the
graph was loaded from), never from the graph itself, so a wrong traversal
cannot agree with itself.
"""

from __future__ import annotations

import pytest
from conftest import TEST_SCALE, TEST_SEED
from evidence import missing_evidence
from pydantic import ValidationError

from reachable_graph.derive import derive
from reachable_graph.tools import GraphTools, ToolError
from reachable_orggen.build import generate_org
from reachable_orggen.generate import GenConfig
from reachable_orggen.load_falkordb import load_org

pytestmark = pytest.mark.integration

ORGS = ["org_a", "org_c"]


class Expect:
    """Answers read straight off the Dataset."""

    def __init__(self, ob):
        self.ob, ds = ob, ob.dataset
        self.ds = ds
        self.edges = ds.edges
        self.person = {p.id: p for p in ds.persons}
        self.team = {t.id: t for t in ds.teams}
        self.asset = {a.id: a for a in ds.assets}

    def out(self, src, typ):
        return [e.dst for e in self.edges if e.src == src and e.type == typ]

    def into(self, dst, typ):
        return [e.src for e in self.edges if e.dst == dst and e.type == typ]

    def owners(self, aid):
        return sorted(self.into(aid, "OWNS"))

    def members(self, tid):
        return sorted(self.into(tid, "MEMBER_OF"))

    def on_call(self, tid):
        cur = [o for o in self.ds.oncalls if o.current and tid in self.out(o.id, "FOR")]
        return [p for o in cur for p in self.into(o.id, "ON_CALL")]

    def adrs(self, aid):
        return [a for a in self.ds.adrs if aid in self.out(a.id, "CHANGED")]

    def entries(self):
        return list(
            dict.fromkeys(p.hops[0].dst.split(":", 1)[1] for p in self.ob.ground_truth.paths)
        )


@pytest.fixture(scope="module")
def company(db):
    out = {}
    for org in ORGS:
        ob = generate_org(org, TEST_SEED, GenConfig(scale=TEST_SCALE))
        name = f"test_company_{org}"
        ob.dataset.org = name
        load_org(db, ob.dataset)
        g = db.select_graph(name)
        derive(g)
        out[org] = (Expect(ob), g, GraphTools(db, allowed_orgs=[name]))
    yield out
    for _, g, _ in out.values():
        g.delete()


@pytest.mark.parametrize("org", ORGS)
def test_owners_matches_dataset(company, org):
    x, g, tools = company[org]
    for aid in x.entries() + [s.node.split(":", 1)[1] for s in x.ob.ground_truth.shared_infra]:
        r = tools.owners(g.name, aid)
        assert [t["id"] for t in r.data["teams"]] == x.owners(aid)
        for t in r.data["teams"]:
            assert sorted(m["id"] for m in t["members"]) == x.members(t["id"])
            assert [t["on_call"]["person"]] == x.on_call(t["id"])
        assert missing_evidence(g, r.evidence) == []
    crown = next(d for d in x.ds.datastores if d.crown_jewel)
    r = tools.owners(g.name, crown.id)  # data stores have owners too
    assert [t["id"] for t in r.data["teams"]] == x.owners(crown.id)


@pytest.mark.parametrize("org", ORGS)
def test_every_planted_entry_has_a_decision_trail(company, org):
    """The Track 03 demo question: why is this exposed, and who approved it?"""
    x, g, tools = company[org]
    for aid in x.entries():
        want = x.adrs(aid)
        assert want, f"{org}: generator planted no ADR for entry {aid}"
        r = tools.decision_trail(g.name, asset_id=aid, port=443)
        got = r.data["decisions"]
        assert [d["adr"] for d in got] == [
            a.id for a in sorted(want, key=lambda a: a.date) if a.port == 443
        ]
        for d in got:
            assert [d["approved_by"]["id"]] == x.out(d["adr"], "APPROVED_BY")
        assert r.data["exposed_ports"] == [443]
        assert r.data["internet_attack_steps"], "entry should be exploitable from the Internet"
        assert "approved by" in r.summary
        assert missing_evidence(g, r.evidence) == []
        # Same answer by hostname.
        by_host = tools.decision_trail(g.name, hostname=x.asset[aid].hostname, port=443)
        assert by_host.data["decisions"] == got


def test_undocumented_exposure_is_called_out(company):
    x, g, tools = company["org_a"]
    exposed = {e.dst for e in x.edges if e.type == "EXPOSES"}
    undocumented = sorted(a for a in exposed if not x.adrs(a))
    r = tools.decision_trail(g.name, asset_id=undocumented[0])
    assert r.data["decisions"] == [] and "No recorded decision" in r.summary


@pytest.mark.parametrize("org", ORGS)
def test_company_query_intents(company, org):
    x, g, tools = company[org]
    entry = x.entries()[0]
    host = x.asset[entry].hostname
    team = x.owners(entry)[0]

    r = tools.company_query(g.name, "who_owns", {"asset_id": entry})
    assert r.data["answer"] == x.team[team].name

    r = tools.company_query(g.name, "who_is_on_call", {"team_id": team})
    (pid,) = x.on_call(team)
    assert r.data["on_call"][0]["person"] == pid and x.person[pid].name in r.data["answer"]
    r2 = tools.company_query(g.name, "who_is_on_call", {"asset_id": entry})
    assert r2.data["on_call"][0]["person"] == pid

    adr = x.adrs(entry)[0]
    r = tools.company_query(g.name, "why_exposed", {"hostname": host, "port": 443})
    assert r.data["answer"].startswith(adr.id) and adr.decision in r.data["answer"]

    r = tools.company_query(g.name, "who_approved", {"asset_id": entry})
    (approver,) = x.out(adr.id, "APPROVED_BY")
    assert x.person[approver].name in r.data["answer"]

    for res in (r, r2):
        assert missing_evidence(g, res.evidence) == []


@pytest.mark.parametrize("org", ORGS)
def test_fix_history(company, org):
    x, g, tools = company[org]
    ticket_finding = {t.id: x.out(t.id, "FIXES")[0] for t in x.ds.tickets}
    on = {e.src: e.dst for e in x.edges if e.type == "ON"}
    status = {f.id: f.status for f in x.ds.findings}
    closed = [t for t in x.ds.tickets if t.status == "closed"]
    assert len(closed) == 4 and all(status[ticket_finding[t.id]] == "fixed" for t in closed)
    for t in x.ds.tickets:
        aid = on[ticket_finding[t.id]]
        r = tools.company_query(g.name, "fix_history", {"asset_id": aid})
        got = {row["ticket"]: row for row in r.data["tickets"]}
        assert got[t.id]["status"] == t.status
        assert got[t.id]["finding_status"] == status[ticket_finding[t.id]]
        assert missing_evidence(g, r.evidence) == []


def test_company_query_is_a_fixed_intent_set(company):
    _, g, tools = company["org_a"]
    with pytest.raises(ValidationError):
        tools.company_query(g.name, "free_text", {"q": "MATCH (n) DETACH DELETE n"})
    with pytest.raises(ValidationError):  # unknown parameter for the intent
        tools.company_query(g.name, "who_owns", {"asset_id": "org_a:asset:00001", "x": 1})
    with pytest.raises(ValidationError):  # exactly one of asset_id / hostname
        tools.company_query(g.name, "why_exposed", {})
    with pytest.raises(ToolError, match="not an Asset or DataStore"):
        tools.owners(g.name, "org_a:finding:00001")
