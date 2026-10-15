"""The company layer (Track 03): teams, people, on-call, decisions and tickets.

A security finding is only half an answer. The other half is organisational:
who owns the box, who is on call tonight, why the port is open, who signed off
on it, and whether someone already fixed something like it. In real companies
that knowledge lives in documents (ADRs, tickets, a rotation spreadsheet, a
CODEOWNERS file). Here each document becomes nodes and edges in the SAME org
graph as the infrastructure, so "trace this exposure to the decision behind it"
is a traversal, not a search:

    (Team)-[:OWNS]->(Asset|DataStore)        ownership routing
    (Person)-[:MEMBER_OF]->(Team)
    (OnCall)-[:FOR]->(Team), (Person)-[:ON_CALL]->(OnCall)
    (ADR)-[:CHANGED]->(Asset), (ADR)-[:APPROVED_BY]->(Person)
    (Ticket)-[:FIXES]->(Finding)

Planted on purpose:
  * a decision trail for EVERY planted path's internet-facing entry point (an
    ADR explaining why it is exposed, approved by a named person), and for each
    shared-infrastructure funnel;
  * history: closed tickets that fixed earlier findings (those findings are
    status 'fixed', so they enable no attack step), plus open tickets on two
    live findings;
  * ownership that is mostly by zone but not entirely (about 1 asset in 7 is
    owned by another team), so routing a fix is a real lookup.

Everything is fictional. Uses its own RNG stream so adding the company layer
does not perturb the infrastructure the planters already built.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime

from .generate import NOW, WEEK, Builder
from .ground_truth import GroundTruth
from .model import ADR, OnCall, Person, Team, Ticket
from .names import PARTNERS, person_names

DAY = 24 * 3600

# Per org: (team name, zones it owns by default, change_effort). The first team
# whose zones include "*" owns anything unmatched (e.g. the quarantine zone).
TEAMS: dict[str, list[tuple[str, tuple[str, ...], int]]] = {
    "org_a": [
        ("Edge & Ingress", ("edge",), 0),
        ("Platform", ("k8s",), 0),
        ("Build & Release", ("ci",), 1),  # change freeze on CI: fixes there cost more
        ("Data Platform", ("data",), 0),
        ("Security Engineering", ("vault", "*"), 0),
    ],
    "org_b": [
        ("Storefront", ("dmz",), 0),
        ("Commerce Services", ("app",), 0),
        ("Database Operations", ("data",), 0),
        ("IT Administration", ("admin", "*"), 1),
    ],
    "org_c": [
        ("Network Operations", ("vpn",), 0),
        ("Workplace IT", ("corp",), 0),
        ("Infrastructure", ("mgmt", "onprem"), 0),
        ("Data Services", ("data",), 0),
        ("Security Office", ("*",), 0),
    ],
}

ROLES = ["Engineering Manager", "Senior SRE", "SRE", "Software Engineer"]
SECURITY_LEAD = "Head of Security"

REASONS_WEB = [
    "the {p} checkout integration",
    "{p} webhook callbacks",
    "the public partner API used by {p}",
    "the {p} single sign-on pilot",
    "a campaign microsite built with {p}",
]
REASONS_VPN = ["remote vendor support by {p}", "site-to-site access for {p}"]


def _date(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d")


class CompanyPlanter:
    def __init__(self, b: Builder, gt: GroundTruth) -> None:
        self.b, self.gt, self.ds = b, gt, b.ds
        self.rng = random.Random(f"{b.org}:{b.ds.seed}:company")
        self.team_of_zone: dict[str, Team] = {}
        self.fallback: Team | None = None
        self.lead: dict[str, Person] = {}  # team id -> its Engineering Manager
        self.security_lead: Person | None = None
        self.owner: dict[str, str] = {}  # asset/datastore id -> team id

    # --- people and teams -------------------------------------------------
    def teams_and_people(self) -> None:
        spec = TEAMS[self.b.org]
        names = iter(person_names(self.rng, 4 * len(spec) + 1))
        for name, zones, effort in spec:
            t = Team(id=self.b._id("team"), name=name, change_effort=effort)
            self.ds.teams.append(t)
            for z in zones:
                if z == "*":
                    self.fallback = self.fallback or t
                else:
                    self.team_of_zone[z] = t
            for i, role in enumerate(ROLES):
                p = Person(id=self.b._id("person"), name=next(names), role=role)
                self.ds.persons.append(p)
                self.ds.add_edge(p.id, t.id, "MEMBER_OF")
                if i == 0:
                    self.lead[t.id] = p
        # One security lead, member of the fallback (security) team, who signs
        # off on internet exposure alongside the owning team's manager.
        assert self.fallback is not None
        self.security_lead = Person(id=self.b._id("person"), name=next(names), role=SECURITY_LEAD)
        self.ds.persons.append(self.security_lead)
        self.ds.add_edge(self.security_lead.id, self.fallback.id, "MEMBER_OF")

    def rotations(self) -> None:
        """Two weekly on-call slots per team: last week's and the current one."""
        members: dict[str, list[str]] = {}
        for e in self.ds.edges:
            if e.type == "MEMBER_OF":
                members.setdefault(e.dst, []).append(e.src)
        for t in self.ds.teams:
            people = self.rng.sample(members[t.id], 2)
            for start, person, current in ((NOW - WEEK, people[0], False), (NOW, people[1], True)):
                oc = OnCall(
                    id=self.b._id("oncall"),
                    window=f"{_date(start)}/{_date(start + WEEK)}",
                    start=start,
                    end=start + WEEK,
                    current=current,
                )
                self.ds.oncalls.append(oc)
                self.ds.add_edge(oc.id, t.id, "FOR")
                self.ds.add_edge(person, oc.id, "ON_CALL")

    # --- ownership ----------------------------------------------------------
    def ownership(self) -> None:
        pinned = {s.node.split(":", 1)[1] for s in self.gt.shared_infra}
        teams = self.ds.teams
        for a in self.ds.assets:
            zone = a.zone.split("zone:")[1]
            team = self.team_of_zone.get(zone, self.fallback)
            # ~1 in 7 assets belongs to another team (an app team's own box in
            # a shared zone). Shared funnels stay with their zone's team.
            if a.id not in pinned and self.rng.random() < 0.15:
                team = self.rng.choice(teams)
            self.owner[a.id] = team.id
            self.ds.add_edge(team.id, a.id, "OWNS")
        data_team = self.team_of_zone.get("data", self.fallback)
        for d in self.ds.datastores:
            team = data_team if d.crown_jewel else self.rng.choice(teams)
            self.owner[d.id] = team.id
            self.ds.add_edge(team.id, d.id, "OWNS")

    # --- decision trails ----------------------------------------------------
    def _adr(self, asset_id: str, title: str, decision: str, approver: Person, **kw) -> ADR:
        n = len(self.ds.adrs) + 1
        adr = ADR(
            id=self.b._id("adr"),
            title=f"ADR-{n:03d}: {title}",
            decision=decision,
            date=NOW - self.rng.randint(60, 720) * DAY,
            **kw,
        )
        self.ds.adrs.append(adr)
        self.ds.add_edge(adr.id, asset_id, "CHANGED")
        self.ds.add_edge(adr.id, approver.id, "APPROVED_BY")
        return adr

    def decision_trails(self) -> None:
        exposed_port = {
            e.dst: e.props.get("port", 443) for e in self.ds.edges if e.type == "EXPOSES"
        }
        entries = list(dict.fromkeys(p.hops[0].dst.split(":", 1)[1] for p in self.gt.paths))
        for aid in entries:
            a = self.b.by_id[aid]
            port = exposed_port.get(aid, 443)
            pool = REASONS_VPN if a.kind == "gateway" else REASONS_WEB
            reason = self.rng.choice(pool).format(p=self.rng.choice(PARTNERS))
            # Exposure is signed off by the owning team's manager, or by the
            # security lead when the owner is a non-product team.
            approver = self.rng.choice([self.lead[self.owner[aid]], self.security_lead])
            self._adr(
                aid,
                f"Expose {a.hostname} on tcp/{port} to the Internet",
                f"Open 0.0.0.0/0 -> {a.hostname}:{port} ({a.kind}) for {reason}. "
                f"Accepted as internet-facing; revisit after the integration ships.",
                approver,
                port=port,
                cidr="0.0.0.0/0",
            )
        for s in self.gt.shared_infra:
            aid = s.node.split(":", 1)[1]
            a = self.b.by_id[aid]
            lead = self.lead[self.owner[aid]]
            if s.kind == "ci_runner":
                port = next(
                    e.props["port"] for e in self.ds.edges if e.type == "CAN_REACH" and e.dst == aid
                )
                self._adr(
                    aid,
                    f"Let service subnets call the shared CI runner {a.hostname}",
                    f"Allow every service to reach {a.hostname}:{port} for build hooks instead "
                    "of running one runner per team. The runner keeps the deploy cloud key.",
                    lead,
                    port=port,
                )
            elif s.kind == "jump_host":
                self._adr(
                    aid,
                    f"Keep legacy jump host {a.hostname} reachable from the DMZ",
                    "Decommissioning slipped; a WAF rule on the admin panel is the "
                    "compensating control until the migration completes.",
                    self.security_lead,
                )
            elif s.kind == "vpn_gateway":
                self._adr(
                    aid,
                    f"Store the vendor-support SSH key on {a.hostname}",
                    "Break-glass access for the vendor: their SSH key lives on the gateway "
                    "so support does not need a separate bastion.",
                    lead,
                )

    # --- history ------------------------------------------------------------
    def tickets(self) -> None:
        """Closed tickets that fixed earlier findings, and open tickets on two
        live findings (one on a planted path, one on the severity decoy)."""
        planted_assets = {
            x.split(":", 1)[1] for p in self.gt.paths for x in p.node_sequence() if ":" in x
        }
        runs: dict[str, list[str]] = {}
        for e in self.ds.edges:
            if e.type == "RUNS":
                runs.setdefault(e.src, []).append(e.dst)
        sw_by_id = {s.id: s for s in self.ds.software}
        bg = [a for a in self.ds.assets if a.id not in planted_assets and runs.get(a.id)]
        made = 0
        for a in self.rng.sample(bg, min(40, len(bg))):
            if made == 4:
                break
            sw = sw_by_id[self.rng.choice(runs[a.id])]
            rec = self.b.catalog.pick(self.rng, f"{sw.vendor}:{sw.product}")
            if rec is None or f"{sw.id}:{rec.id}" in self.b._vulns:
                continue
            vuln = self.b.add_vuln(sw, rec)
            f = self.b.add_finding(a, vuln, status="fixed")
            f.first_seen -= 200 * DAY  # found well before the current scan window
            opened = f.first_seen + self.rng.randint(1, 5) * DAY
            self._ticket(
                f.id,
                f"Patch {rec.id} on {a.hostname}",
                "closed",
                opened,
                opened + self.rng.randint(3, 30) * DAY,
            )
            made += 1

        on = {e.src: e.dst for e in self.ds.edges if e.type == "ON"}
        of = {e.src: e.dst for e in self.ds.edges if e.type == "OF"}
        cve = {v.id: v.cve for v in self.ds.vulns}
        medium = next(p for p in self.gt.paths if p.name == "medium_start_web_db")
        entry = medium.hops[0].dst.split(":", 1)[1]
        live = [fid for fid, aid in on.items() if aid == entry]
        severity = next(d for d in self.gt.decoys if d.kind == "severity").finding_ids
        for fid in live[:1] + severity[:1]:
            host = self.b.by_id[on[fid]].hostname
            self._ticket(
                fid,
                f"Upgrade to fix {cve[of[fid]]} on {host}",
                "open",
                NOW - self.rng.randint(2, 20) * DAY,
                None,
            )

    def _ticket(self, finding_id: str, title: str, status: str, opened: int, closed) -> None:
        t = Ticket(
            id=self.b._id("ticket"), title=title, status=status, opened=opened, closed=closed
        )
        self.ds.tickets.append(t)
        self.ds.add_edge(t.id, finding_id, "FIXES")


def plant_company(b: Builder, gt: GroundTruth) -> None:
    c = CompanyPlanter(b, gt)
    c.teams_and_people()
    c.rotations()
    c.ownership()
    c.decision_trails()
    c.tickets()
