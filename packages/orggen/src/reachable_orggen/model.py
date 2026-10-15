"""In-memory model of one synthetic org, before it is loaded into FalkorDB.

These dataclasses mirror the graph schema exactly (node per dataclass, edge per
tuple). The generator fills a Dataset; loaders (FalkorDB, Postgres) and the
networkx oracle all consume this same object, so the graph, the relational
mirror and the ground-truth oracle can never describe different worlds.

Everything is plain data + ids. No behaviour lives here.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# --- Nodes -----------------------------------------------------------------
@dataclass
class Asset:
    id: str
    kind: str  # server | k8s_node | workstation | gateway | ci_runner | managed_db ...
    zone: str  # zone id
    env: str  # prod | staging | corp
    hostname: str
    cloud: bool = False  # cloud asset => can carry an instance Role


@dataclass
class Software:
    id: str
    vendor: str
    product: str
    version: str
    cpe: str


@dataclass
class Vuln:
    """Denormalised copy of a threatintel CVE, scoped to this org's graph.

    WHY denormalise instead of linking across to the `threatintel` graph:
    FalkorDB (like Redis) keeps each graph separate; a Cypher query cannot JOIN
    two graphs. Attack-path queries need CVSS/EPSS/KEV/vector right next to the
    Software they sit on, in the SAME graph, or every hop would need an
    out-of-band lookup. So we copy the handful of fields the attack rules read
    (cvss, av, pr, ui, epss, kev, ransomware) onto a Vuln node inside the org
    graph. `cve` keeps the link back to the canonical CVE in `threatintel`.
    """

    id: str
    cve: str
    cvss: float
    av: str
    pr: str
    ui: str
    epss: float
    kev: bool
    ransomware: bool


@dataclass
class Finding:
    id: str
    scanner: str
    first_seen: int  # epoch seconds (int: FalkorDB timestamp gotcha)
    status: str  # open | fixed


@dataclass
class Identity:
    id: str
    kind: str  # User | Role | ServiceAccount (becomes the node's extra label)
    name: str
    over_broad: bool = False  # flagged over-permissive role (realism target)


@dataclass
class Secret:
    id: str
    kind: str  # ssh_key | db_password | cloud_key | api_token
    # Root-owned secret: reading it off a host needs privilege first, so the
    # creds_in_files step requires a prior local_privesc (priv:<asset>) rather
    # than mere compromise of the asset. Drives the "hard path" requirement.
    requires_priv: bool = False


@dataclass
class DataStore:
    id: str
    kind: str  # bucket | managed_db | warehouse | fileshare
    crown_jewel: bool
    sensitivity: str  # low | medium | high | crown


@dataclass
class Control:
    id: str
    kind: str  # waf | patch | network_acl | mfa | edr


@dataclass
class Zone:
    id: str
    name: str
    trust: int  # 0 (internet) .. higher = more trusted/internal


# --- Company layer (Track 03): who owns what, who decided what ------------
@dataclass
class Person:
    id: str
    name: str  # invented, see names.person_name
    role: str  # job title, e.g. "Engineering Manager"


@dataclass
class Team:
    id: str
    name: str
    # 0 normally, 1 for a team under a change freeze / heavy change process.
    # Feeds the effort estimate of fixes on assets the team owns.
    change_effort: int = 0


@dataclass
class OnCall:
    """One slot of a team's on-call rotation. `current` marks the live slot, so
    "who is on call now" does not depend on the reader's wall clock."""

    id: str
    window: str  # "2023-12-25/2024-01-01"
    start: int  # epoch seconds
    end: int
    current: bool


@dataclass
class ADR:
    """Architecture Decision Record: why something is the way it is."""

    id: str
    title: str
    decision: str
    date: int  # epoch seconds
    status: str = "accepted"
    port: int | None = None  # the exposure it decided, when it is about one
    cidr: str | None = None


@dataclass
class Ticket:
    id: str
    title: str
    status: str  # open | closed
    opened: int  # epoch seconds
    closed: int | None = None


# --- Memory layer (Track 02): what agents remember, in the org graph -------
# The runtime reads and writes these through reachable_graph.memory. The
# generator seeds a little clearly-synthetic prior memory with the same schema.
@dataclass
class Run:
    """One agent run. Steps hang off it, so a handoff between agents is just
    'continue Run X' and the whole run can be replayed in order."""

    id: str
    started: int  # epoch seconds
    kind: str  # triage | remediation | drift | ...


@dataclass
class AgentStep:
    id: str
    tool: str
    input_hash: str  # sha256 of the canonical JSON input: replay / dedup key
    ts: int
    seq: int  # 0-based order within its Run


@dataclass
class Triage:
    """One triage session (inside a Run, or a human's)."""

    id: str
    ts: int


@dataclass
class Verdict:
    id: str
    decision: str  # fix_now | schedule | not_reachable | false_positive | accept_risk
    reason: str
    ts: int


@dataclass
class RiskAcceptance:
    """A signed-off decision to live with a finding until `expires`. After that
    it no longer suppresses the finding (temporal validity on the node)."""

    id: str
    reason: str
    approved_by: str  # Person id (also an APPROVED_BY edge)
    created: int
    expires: int


@dataclass
class Pattern:
    """Semantic memory: a generalisation learned across triages."""

    id: str
    kind: str  # recurring_cve | ...
    description: str
    ts: int


@dataclass
class Technique:
    """Org-local copy of an ATT&CK technique id, the anchor for playbooks (the
    canonical record is in the threatintel graph; graphs cannot be joined)."""

    id: str  # e.g. "T1190"
    name: str


@dataclass
class Playbook:
    """Procedural memory: how we handle a technique. Versioned: a new version
    SUPERSEDES the old one, which stays for history."""

    id: str
    technique: str
    version: int
    body: str
    ts: int


# --- Edges (typed tuples of ids + a small property dict) -------------------
@dataclass
class Edge:
    src: str
    dst: str
    type: str
    props: dict = field(default_factory=dict)


# --- Firewall / security-group rules, modelled as DATA -----------------
@dataclass
class ReachRule:
    """A zone-to-zone (or internet-to-zone) allow rule.

    WHY model rules as data: CAN_REACH edges between assets are *derived* from
    these rules, not hand-placed. That mirrors reality (you write firewall /
    security-group rules, the reachability falls out) and lets a reviewer see
    exactly why asset X can reach asset Y: because a rule allows
    src_zone -> dst_zone on this port. The derivation lives in generate.py.
    """

    src_zone: str  # "internet" or a zone id
    dst_zone: str
    port: int
    protocol: str = "tcp"


@dataclass
class Dataset:
    org: str
    seed: int
    scale: float
    zones: list[Zone] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    software: list[Software] = field(default_factory=list)
    vulns: list[Vuln] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    identities: list[Identity] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    datastores: list[DataStore] = field(default_factory=list)
    controls: list[Control] = field(default_factory=list)
    reach_rules: list[ReachRule] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    internet_id: str = "internet"
    # Which scan this dataset is (v1, or the week-later v2) and when it ran.
    scan: str = "v1"
    scan_ts: int = 0
    # Company layer
    persons: list[Person] = field(default_factory=list)
    teams: list[Team] = field(default_factory=list)
    oncalls: list[OnCall] = field(default_factory=list)
    adrs: list[ADR] = field(default_factory=list)
    tickets: list[Ticket] = field(default_factory=list)
    # Memory layer (seeded prior memory)
    runs: list[Run] = field(default_factory=list)
    steps: list[AgentStep] = field(default_factory=list)
    triages: list[Triage] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)
    risk_acceptances: list[RiskAcceptance] = field(default_factory=list)
    patterns: list[Pattern] = field(default_factory=list)
    techniques: list[Technique] = field(default_factory=list)
    playbooks: list[Playbook] = field(default_factory=list)

    def add_edge(self, src: str, dst: str, type: str, **props) -> None:
        self.edges.append(Edge(src, dst, type, props))
