"""What the baselines may see, and the one door they see it through.

The Postgres mirror (`<org>` / `<org>_v2` schemas, loaded by `make seed` from the
same Dataset as the FalkorDB graph) holds more than infrastructure: the company
layer (teams, people, ADRs, tickets) and the edges of the synthetic agent memory
(verdicts and risk acceptances ON findings, seeded from the ground truth). None
of that is "which findings exist and what connects to what", and some of it is
correlated with the answer key. So the baselines never read the mirror itself.

For each scan we build `eval_<graph>`: views over the mirror's infrastructure
tables, and over `edges` filtered to infrastructure edge types (the ON edges of
memory nodes are dropped). A dedicated LOGIN role, `reachable_eval_ro`, gets
USAGE + SELECT on those views and nothing else, with
default_transaction_read_only and a statement timeout set on the role. Every
baseline (severity_sort, smart_score, the CONTEXT all three LLM prioritisers get,
the RAG documents, the SQL agent's tool) connects as that role. A test proves it
cannot read the raw schemas or any label/path field.

Nothing here touches labels.json or the derived ATTACK_STEP layer: those exist
only in FalkorDB and in scoring.py.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

import psycopg
from psycopg import sql

from reachable_core.settings import Settings, get_settings

RO_ROLE = "reachable_eval_ro"
STATEMENT_TIMEOUT_MS = 5_000

# Node tables the baselines may read (all of their columns): infrastructure,
# software and vulnerabilities, findings, identities, secrets, data stores and
# controls. NOT persons, teams, oncalls, adrs, tickets (the company layer).
INFRA_TABLES = (
    "zones",
    "assets",
    "software",
    "vulns",
    "findings",
    "identities",
    "secrets",
    "datastores",
    "controls",
)
# Columns of those tables the views leave out (S9). A crown jewel's sensitivity tier
# is a graph property reachable may use; no baseline sees it. Baselines still see
# which data stores are crown jewels (datastores.crown_jewel).
HIDDEN_COLUMNS = {"datastores": ("sensitivity",)}
# Edge types that describe the infrastructure. NOT the company layer (OWNS,
# MEMBER_OF, ON_CALL, APPROVED_BY, CHANGED, FOR, FIXES) nor memory (HAS_STEP,
# NEXT, HAS_TRIAGE, HAS_VERDICT, ABOUT, SEEN_IN, HANDLED_BY, SUPERSEDES).
INFRA_EDGES = (
    "EXPOSES",
    "CAN_REACH",
    "RUNS",
    "HAS_VULN",
    "ON",
    "OF",
    "IN_ZONE",
    "HOLDS",
    "UNLOCKS",
    "ASSUMES",
    "CAN",
    "CAN_ASSUME",
    "MITIGATES",
)


def ro_password(s: Settings) -> str:
    """The read-only role's password, derived from the admin password: stable, so
    several eval processes (the matrix, the ablation, the tests) agree on it. A
    random one per process re-set the role under the others' feet (S7 gotcha)."""
    key = s.postgres_password.encode()
    return hmac.new(key, f"{RO_ROLE}:{s.postgres_db}".encode(), hashlib.sha256).hexdigest()[:32]


def eval_schema(graph: str) -> str:
    return f"eval_{graph}"


@dataclass(frozen=True)
class ScanRef:
    """One scan of one org: the FalkorDB graph, the Postgres mirror schema (same
    name), and where its labels live (only scoring.py opens that)."""

    org: str
    scan: str  # v1 | v2
    graph: str  # FalkorDB graph and Postgres schema: <org> or <org>_v2

    @classmethod
    def of(cls, org: str, scan: str, settings: Settings | None = None) -> ScanRef:
        s = settings or get_settings()
        return cls(org, scan, s.scan_graph(org, scan))

    @property
    def schema(self) -> str:
        return eval_schema(self.graph)

    @property
    def key(self) -> str:
        return self.graph


def _admin(s: Settings) -> psycopg.Connection:
    return psycopg.connect(s.postgres_dsn, autocommit=True)


def ensure_eval_views(graph: str, settings: Settings | None = None) -> None:
    """(Re)create eval_<graph> and grant it (only it) to the read-only role.
    Idempotent; cheap (views only)."""
    s = settings or get_settings()
    src, dst = sql.Identifier(graph), sql.Identifier(eval_schema(graph))
    role = sql.Identifier(RO_ROLE)
    with _admin(s) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM information_schema.schemata WHERE schema_name = %s", (graph,))
        if not cur.fetchone():
            raise RuntimeError(f"no Postgres mirror schema {graph!r}: run `make seed`")
        cur.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(dst))
        cur.execute(sql.SQL("CREATE SCHEMA {}").format(dst))
        for t in INFRA_TABLES:
            cur.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
                (graph, t),
            )
            hidden = HIDDEN_COLUMNS.get(t, ())
            cols = sql.SQL(", ").join(
                sql.Identifier(c) for (c,) in cur.fetchall() if c not in hidden
            )
            cur.execute(
                sql.SQL("CREATE VIEW {}.{} AS SELECT {} FROM {}.{}").format(
                    dst, sql.Identifier(t), cols, src, sql.Identifier(t)
                )
            )
        # ON edges come from Findings (scanner) and from memory nodes (Verdict,
        # RiskAcceptance): keep the scanner's only.
        types = sql.SQL(", ").join(sql.Literal(t) for t in INFRA_EDGES)  # DDL: no bind params
        cur.execute(
            sql.SQL(
                "CREATE VIEW {}.edges AS SELECT src, dst, type, props FROM {}.edges "
                "WHERE type IN ({}) AND (type <> 'ON' OR src IN (SELECT id FROM {}.findings))"
            ).format(dst, src, types, src)
        )
        cur.execute(  # RO_ROLE is a constant, not input
            f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{RO_ROLE}') "
            f"THEN CREATE ROLE {RO_ROLE} LOGIN; END IF; END $$"
        )
        cur.execute(
            sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(role, sql.Literal(ro_password(s)))
        )
        cur.execute(sql.SQL("ALTER ROLE {} SET default_transaction_read_only = on").format(role))
        cur.execute(
            sql.SQL("ALTER ROLE {} SET statement_timeout = {}").format(
                role, sql.Literal(STATEMENT_TIMEOUT_MS)
            )
        )
        cur.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(dst, role))
        cur.execute(sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}").format(dst, role))


def ro_connect(graph: str, settings: Settings | None = None) -> psycopg.Connection:
    """A connection as the read-only role, search_path = eval_<graph> only (the
    views must exist: ensure_eval_views)."""
    s = settings or get_settings()
    return psycopg.connect(
        host=s.postgres_host,
        port=s.postgres_port,
        dbname=s.postgres_db,
        user=RO_ROLE,
        password=ro_password(s),
        options=f"-c search_path={eval_schema(graph)} -c statement_timeout={STATEMENT_TIMEOUT_MS}",
        connect_timeout=10,
    )


# ------------------------------------------------------------- the scan data
def tiebreak(finding_id: str) -> str:
    """Ties (thousands of findings share CVSS 9.8) are broken by a hash of the id,
    not the id itself: planted findings were generated last and have the highest
    ids, so id order would quietly push them up or down."""
    return hashlib.sha256(finding_id.encode()).hexdigest()


@dataclass
class FindingRow:
    id: str
    cve: str | None
    cvss: float
    epss: float
    kev: bool
    ransomware: bool
    av: str | None
    asset: str | None
    hostname: str | None
    kind: str | None
    zone: str | None
    env: str | None
    product: str | None
    internet_facing: bool
    mitigated_by: str | None  # a Control kind that MITIGATES this vuln on this asset


@dataclass
class ScanData:
    """Everything a non-graph prioritiser knows about one scan."""

    ref: ScanRef
    findings: list[FindingRow]
    crown_jewels: list[dict]
    n_assets: int
    n_exposed_assets: int
    by_id: dict[str, FindingRow] = field(init=False)

    def __post_init__(self) -> None:
        self.by_id = {f.id: f for f in self.findings}

    @property
    def universe(self) -> list[str]:
        """The scan's open findings: every prioritiser ranks exactly these."""
        return [f.id for f in self.findings]

    def universe_hash(self) -> str:
        return hashlib.sha256("\n".join(sorted(self.universe)).encode()).hexdigest()[:16]


FINDINGS_SQL = """
SELECT f.id, v.cve, v.cvss, v.epss, v.kev, v.ransomware, v.av, v.id,
       a.id, a.hostname, a.kind, z.name, a.env, s.vendor || ' ' || s.product || ' ' || s.version
FROM findings f
LEFT JOIN edges o ON o.src = f.id AND o.type = 'OF'
LEFT JOIN vulns v ON v.id = o.dst
LEFT JOIN edges n ON n.src = f.id AND n.type = 'ON'
LEFT JOIN assets a ON a.id = n.dst
LEFT JOIN zones z ON z.id = a.zone
LEFT JOIN edges hv ON hv.dst = v.id AND hv.type = 'HAS_VULN'
LEFT JOIN software s ON s.id = hv.src
WHERE f.status = 'open'
"""


def load_scan(ref: ScanRef, settings: Settings | None = None) -> ScanData:
    with ro_connect(ref.graph, settings) as conn, conn.cursor() as cur:
        cur.execute("SELECT dst FROM edges WHERE type = 'EXPOSES' AND src = 'internet'")
        exposed = {r[0] for r in cur.fetchall()}
        cur.execute(
            "SELECT e.dst, e.props->>'asset', c.kind FROM edges e JOIN controls c ON c.id = e.src "
            "WHERE e.type = 'MITIGATES'"
        )
        mitigated = {(v, a): k for v, a, k in cur.fetchall()}
        cur.execute(FINDINGS_SQL)
        rows: dict[str, FindingRow] = {}
        for fid, cve, cvss, epss, kev, rw, av, vid, aid, host, kind, zone, env, prod in cur:
            if fid in rows:  # one row per finding (a vuln sits on one software)
                continue
            rows[fid] = FindingRow(
                id=fid,
                cve=cve,
                cvss=float(cvss or 0.0),
                epss=float(epss or 0.0),
                kev=bool(kev),
                ransomware=bool(rw),
                av=av,
                asset=aid,
                hostname=host,
                kind=kind,
                zone=zone,
                env=env,
                product=prod,
                internet_facing=aid in exposed,
                mitigated_by=mitigated.get((vid, aid)),
            )
        cur.execute("SELECT id, kind FROM datastores WHERE crown_jewel ORDER BY id")
        crown = [{"id": i, "kind": k} for i, k in cur.fetchall()]
        cur.execute("SELECT count(*) FROM assets")
        n_assets = cur.fetchone()[0]
    findings = sorted(rows.values(), key=lambda f: tiebreak(f.id))  # no id-order signal
    return ScanData(ref, findings, crown, n_assets, len(exposed))
