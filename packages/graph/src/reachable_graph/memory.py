"""Agent memory (Track 02): repositories over the org graph.

This module holds the ONLY runtime writes into an org graph. The tool layer
(tools.py, company_tools.py) stays read-only; memory is the sanctioned
exception, and it is narrow on purpose:

  * every write is one of the fixed Cypher constants in WRITE_QUERIES (no
    caller-supplied Cypher, values only ever as parameters);
  * writes only CREATE/MERGE memory nodes (Run, AgentStep, Triage, Verdict,
    RiskAcceptance, Pattern, Playbook, Technique) and edges from them; they
    never SET a property on, or delete, an infrastructure node;
  * the org must be on the allowlist, like every tool.

Three kinds of memory, all as nodes next to the facts they are about:

  episodic    what happened: Run -[:HAS_STEP]-> AgentStep -[:NEXT]-> AgentStep,
              Triage -[:HAS_VERDICT]-> Verdict -[:ON]-> Finding,
              RiskAcceptance -[:ON]-> Finding, -[:APPROVED_BY]-> Person
  semantic    what we learned: Pattern -[:ABOUT]-> Asset|Software|Vuln,
              Pattern -[:SEEN_IN]-> Triage
  procedural  how we handle it: Technique -[:HANDLED_BY]-> Playbook,
              Playbook -[:SUPERSEDES]-> Playbook (old versions stay)

Time: every node carries epoch-second timestamps. A RiskAcceptance is only in
force while now < expires; the current Playbook is the one nothing supersedes;
"what was true at T" is answered by filtering on those timestamps.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, Field

from reachable_core.db import connect, create_range_index
from reachable_core.schema import MEMORY_INDEXES
from reachable_core.settings import get_settings

from .models import QUERY_TIMEOUT_MS, EdgeRef, Evidence, QueryLog, ToolResult

Decision = Literal["fix_now", "schedule", "not_reachable", "false_positive", "accept_risk"]
PATTERN_TARGETS = {"Asset", "Software", "Vuln"}  # what a Pattern may be ABOUT

Reader = Callable[[str, dict], list[list]]


class MemoryError_(ValueError):  # noqa: N801 - avoid shadowing the builtin MemoryError
    """A memory request we refuse (unknown org, missing node, version conflict)."""


def now_ts() -> int:
    return int(time.time())


def input_hash(tool_input: Any) -> str:
    """sha256 of the canonical JSON form: the same input always hashes the same,
    so a replay can be checked and repeated tool calls spotted."""
    blob = json.dumps(tool_input, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


# --------------------------------------------------------------------- records
class AgentStepRec(BaseModel):
    id: str
    tool: str
    input_hash: str
    ts: int
    seq: int


class RunRec(BaseModel):
    id: str
    kind: str
    started: int
    steps: list[AgentStepRec] = Field(default_factory=list)
    chain_ok: bool = True  # NEXT edges link the steps exactly in seq order


class VerdictRec(BaseModel):
    id: str
    finding: str
    decision: str
    reason: str
    ts: int


class RiskAcceptanceRec(BaseModel):
    id: str
    findings: list[str]
    reason: str
    approved_by: str
    approver_name: str | None = None
    created: int
    expires: int
    live: bool  # expires > the `now` it was read at


class PatternRec(BaseModel):
    id: str
    kind: str
    description: str
    ts: int
    about: list[str] = Field(default_factory=list)
    seen_in: list[str] = Field(default_factory=list)


class PlaybookRec(BaseModel):
    id: str
    technique: str
    version: int
    body: str
    ts: int
    supersedes: str | None = None


# ---------------------------------------------------------------- write queries
CREATE_RUN = """
MERGE (r:Run {id: $id})
ON CREATE SET r.started = $started, r.kind = $kind
RETURN r.id
"""

# Append one step: its seq is one past the run's last step, and the last step
# gets a NEXT edge to it. FOREACH over a 0-or-1 element list is the Cypher idiom
# for "create this edge only if there is a previous step".
APPEND_STEP = """
MATCH (r:Run {id: $run})
OPTIONAL MATCH (r)-[:HAS_STEP]->(prev:AgentStep)
WITH r, prev ORDER BY prev.seq DESC LIMIT 1
CREATE (r)-[:HAS_STEP]->(s:AgentStep {id: $id, tool: $tool, input_hash: $hash, ts: $ts,
                                      seq: coalesce(prev.seq, -1) + 1})
FOREACH (p IN CASE WHEN prev IS NULL THEN [] ELSE [prev] END | CREATE (p)-[:NEXT]->(s))
RETURN s.seq
"""

CREATE_TRIAGE = "CREATE (t:Triage {id: $id, ts: $ts}) RETURN t.id"
LINK_TRIAGE_TO_RUN = """
MATCH (r:Run {id: $run}), (t:Triage {id: $triage})
MERGE (r)-[:HAS_TRIAGE]->(t)
"""

CREATE_VERDICT = """
MATCH (f:Finding {id: $finding})
CREATE (v:Verdict {id: $id, decision: $decision, reason: $reason, ts: $ts})-[:ON]->(f)
RETURN v.id
"""
LINK_VERDICT_TO_TRIAGE = """
MATCH (t:Triage {id: $triage}), (v:Verdict {id: $verdict})
MERGE (t)-[:HAS_VERDICT]->(v)
"""

CREATE_RISK_ACCEPTANCE = """
MATCH (p:Person {id: $person})
CREATE (ra:RiskAcceptance {id: $id, reason: $reason, approved_by: $person,
                           created: $created, expires: $expires})-[:APPROVED_BY]->(p)
WITH ra
MATCH (f:Finding) WHERE f.id IN $findings
CREATE (ra)-[:ON]->(f)
RETURN count(f)
"""

UPSERT_PATTERN = """
MERGE (p:Pattern {id: $id})
ON CREATE SET p.kind = $kind, p.first_seen = $ts
SET p.description = $description, p.ts = $ts
RETURN p.id
"""
# One per allowed target label; the label comes from PATTERN_TARGETS, never input.
LINK_PATTERN_ABOUT = {
    label: f"""
MATCH (p:Pattern {{id: $id}})
MATCH (x:{label}) WHERE x.id IN $ids
MERGE (p)-[:ABOUT]->(x)
RETURN count(x)
"""
    for label in sorted(PATTERN_TARGETS)
}
LINK_PATTERN_SEEN_IN = """
MATCH (p:Pattern {id: $id}), (t:Triage {id: $triage})
MERGE (p)-[:SEEN_IN]->(t)
"""

ENSURE_TECHNIQUE = "MERGE (t:Technique {id: $technique})"
# A version's id is deterministic (<org>:playbook:<technique>:v<n>), so two
# writers racing to publish the same version collide on MERGE instead of
# silently producing two "v2"s; the loser sees nodes_created == 0.
CREATE_PLAYBOOK = """
MATCH (t:Technique {id: $technique})
MERGE (p:Playbook {id: $id})
ON CREATE SET p.technique = $technique, p.version = $version, p.body = $body, p.ts = $ts
MERGE (t)-[:HANDLED_BY]->(p)
RETURN p.version
"""
LINK_SUPERSEDES = """
MATCH (n:Playbook {id: $new}), (o:Playbook {id: $old})
MERGE (n)-[:SUPERSEDES]->(o)
"""

WRITE_QUERIES = frozenset(
    {
        CREATE_RUN,
        APPEND_STEP,
        CREATE_TRIAGE,
        LINK_TRIAGE_TO_RUN,
        CREATE_VERDICT,
        LINK_VERDICT_TO_TRIAGE,
        CREATE_RISK_ACCEPTANCE,
        UPSERT_PATTERN,
        *LINK_PATTERN_ABOUT.values(),
        LINK_PATTERN_SEEN_IN,
        ENSURE_TECHNIQUE,
        CREATE_PLAYBOOK,
        LINK_SUPERSEDES,
    }
)

# ----------------------------------------------------------------- read queries
READ_RUN = "MATCH (r:Run {id: $id}) RETURN r.kind, r.started"
READ_STEPS = """
MATCH (r:Run {id: $id})-[:HAS_STEP]->(s:AgentStep)
RETURN s.id, s.tool, s.input_hash, s.ts, s.seq ORDER BY s.seq
"""
READ_NEXT = """
MATCH (r:Run {id: $id})-[:HAS_STEP]->(a:AgentStep)-[:NEXT]->(b:AgentStep)
RETURN a.seq, b.seq
"""
READ_VERDICTS = """
MATCH (f:Finding) WHERE f.id IN $ids
MATCH (v:Verdict)-[:ON]->(f)
RETURN v.id, f.id, v.decision, v.reason, v.ts ORDER BY v.ts DESC, v.id
"""
# `ra.expires > $now` is computed in the query so "live" means one thing everywhere.
READ_RISK_ACCEPTANCES = """
MATCH (f:Finding) WHERE f.id IN $ids
MATCH (ra:RiskAcceptance)-[:ON]->(f)
OPTIONAL MATCH (ra)-[:APPROVED_BY]->(p:Person)
RETURN ra.id, collect(DISTINCT f.id), ra.reason, ra.approved_by, p.name,
       ra.created, ra.expires, ra.expires > $now
ORDER BY ra.created DESC, ra.id
"""
# What a finding is about: its asset, its vuln (+ CVE) and the software carrying it.
READ_FINDING_CONTEXT = """
MATCH (f:Finding) WHERE f.id IN $ids
MATCH (f)-[:ON]->(a:Asset), (f)-[:OF]->(v:Vuln)
MATCH (s:Software)-[:HAS_VULN]->(v)
RETURN f.id, a.id, v.id, v.cve, s.id, s.cpe
"""
# A pattern's reach: patterns ABOUT the finding's asset, ABOUT any Software with
# the same CPE (same image/build), or ABOUT any Vuln with the same CVE.
READ_PATTERNS_BY_CONTEXT = """
MATCH (p:Pattern)-[:ABOUT]->(x)
WHERE (x:Asset AND x.id IN $assets)
   OR (x:Software AND x.cpe IN $cpes)
   OR (x:Vuln AND x.cve IN $cves)
RETURN DISTINCT p.id
"""
# Also returns what the pattern reaches: the assets, CVEs (from Vuln targets) and
# CPEs (from Software targets) it is about. collect() skips nulls, so an Asset
# contributes no CVE and a Vuln no CPE.
READ_PATTERNS_BY_ID = """
MATCH (p:Pattern) WHERE p.id IN $ids
OPTIONAL MATCH (p)-[:ABOUT]->(x)
WITH p, collect(DISTINCT x.id) AS about,
     collect(DISTINCT CASE WHEN x:Asset THEN x.id END) AS assets,
     collect(DISTINCT x.cve) AS cves, collect(DISTINCT x.cpe) AS cpes
OPTIONAL MATCH (p)-[:SEEN_IN]->(t:Triage)
RETURN p.id, p.kind, p.description, p.ts, about, collect(DISTINCT t.id), assets, cves, cpes
ORDER BY p.ts DESC, p.id
"""
READ_PATTERNS_ABOUT = """
MATCH (p:Pattern)-[:ABOUT]->(x) WHERE x.id IN $ids
RETURN DISTINCT p.id
"""
READ_CURRENT_PLAYBOOK = """
MATCH (:Technique {id: $technique})-[:HANDLED_BY]->(p:Playbook)
WHERE NOT (:Playbook)-[:SUPERSEDES]->(p)
OPTIONAL MATCH (p)-[:SUPERSEDES]->(o:Playbook)
RETURN p.id, p.technique, p.version, p.body, p.ts, o.id
"""
READ_PLAYBOOK_HISTORY = """
MATCH (:Technique {id: $technique})-[:HANDLED_BY]->(p:Playbook)
OPTIONAL MATCH (p)-[:SUPERSEDES]->(o:Playbook)
RETURN p.id, p.technique, p.version, p.body, p.ts, o.id
ORDER BY p.version DESC
"""


def _playbook(row) -> PlaybookRec:
    pid, tech, version, body, ts, old = row
    return PlaybookRec(id=pid, technique=tech, version=version, body=body, ts=ts, supersedes=old)


# ------------------------------------------------------------------ repository
class MemoryRepo:
    """Read/write agent memory in one FalkorDB connection's org graphs."""

    def __init__(
        self, db=None, *, allowed_orgs: list[str] | None = None, timeout_ms: int = QUERY_TIMEOUT_MS
    ) -> None:
        self.db = db or connect()
        self.allowed = set(allowed_orgs or get_settings().orgs)
        self.timeout_ms = timeout_ms

    # --- plumbing -----------------------------------------------------------
    def _org(self, org: str) -> str:
        if org not in self.allowed:
            raise MemoryError_(f"unknown org {org!r}; allowed: {sorted(self.allowed)}")
        return org

    def _w(self, org: str, cypher: str, params: dict):
        """The ONLY write path: a fixed memory query, parameters only."""
        if cypher not in WRITE_QUERIES:
            raise MemoryError_("refusing a write that is not a memory query")
        return self.db.select_graph(self._org(org)).query(cypher, params, timeout=self.timeout_ms)

    def _r(self, org: str, cypher: str, params: dict | None = None) -> list[list]:
        g = self.db.select_graph(self._org(org))
        return g.ro_query(cypher, params or {}, timeout=self.timeout_ms).result_set

    def _new_id(self, org: str, kind: str) -> str:
        return f"{org}:{kind}:{uuid.uuid4().hex[:12]}"

    def _require(self, org: str, label: str, ids: list[str]) -> None:
        rows = self._r(org, f"MATCH (n:{label}) WHERE n.id IN $ids RETURN n.id", {"ids": ids})
        missing = set(ids) - {r[0] for r in rows}
        if missing:
            raise MemoryError_(f"no {label} {sorted(missing)} in {org}")

    def ensure_indexes(self, org: str) -> None:
        g = self.db.select_graph(self._org(org))
        for label, prop in MEMORY_INDEXES.items():
            create_range_index(g, label, prop)

    # --- episodic: runs and their ordered steps -----------------------------
    def start_run(
        self, org: str, kind: str, *, started: int | None = None, run_id: str | None = None
    ) -> str:
        rid = run_id or self._new_id(org, "run")
        self._w(org, CREATE_RUN, {"id": rid, "kind": kind, "started": started or now_ts()})
        return rid

    def append_step(
        self, org: str, run_id: str, tool: str, tool_input: Any, *, ts: int | None = None
    ) -> AgentStepRec:
        sid = self._new_id(org, "step")
        h = input_hash(tool_input)
        res = self._w(
            org,
            APPEND_STEP,
            {"run": run_id, "id": sid, "tool": tool, "hash": h, "ts": ts or now_ts()},
        )
        if not res.result_set:
            raise MemoryError_(f"no Run {run_id!r} in {org}")
        return AgentStepRec(
            id=sid, tool=tool, input_hash=h, ts=ts or now_ts(), seq=res.result_set[0][0]
        )

    def record_run(
        self, org: str, kind: str, steps: list[tuple[str, Any]], *, started: int | None = None
    ) -> RunRec:
        """Write a whole run (tool, input) by (tool, input), in order."""
        rid = self.start_run(org, kind, started=started)
        for tool, tool_input in steps:
            self.append_step(org, rid, tool, tool_input)
        return self.get_run(org, rid)

    def get_run(self, org: str, run_id: str) -> RunRec:
        head = self._r(org, READ_RUN, {"id": run_id})
        if not head:
            raise MemoryError_(f"no Run {run_id!r} in {org}")
        steps = [
            AgentStepRec(id=i, tool=t, input_hash=h, ts=ts, seq=s)
            for i, t, h, ts, s in self._r(org, READ_STEPS, {"id": run_id})
        ]
        links = sorted(tuple(r) for r in self._r(org, READ_NEXT, {"id": run_id}))
        want = [(a.seq, b.seq) for a, b in zip(steps, steps[1:], strict=False)]
        return RunRec(
            id=run_id,
            kind=head[0][0],
            started=head[0][1],
            steps=steps,
            chain_ok=links == want and [s.seq for s in steps] == list(range(len(steps))),
        )

    # --- episodic: triage, verdicts, risk acceptances -----------------------
    def start_triage(self, org: str, *, run_id: str | None = None, ts: int | None = None) -> str:
        tid = self._new_id(org, "triage")
        self._w(org, CREATE_TRIAGE, {"id": tid, "ts": ts or now_ts()})
        if run_id:
            self._require(org, "Run", [run_id])
            self._w(org, LINK_TRIAGE_TO_RUN, {"run": run_id, "triage": tid})
        return tid

    def record_verdict(
        self,
        org: str,
        finding_id: str,
        decision: Decision,
        reason: str,
        *,
        triage_id: str | None = None,
        ts: int | None = None,
    ) -> VerdictRec:
        self._require(org, "Finding", [finding_id])
        if triage_id:
            self._require(org, "Triage", [triage_id])
        vid, ts = self._new_id(org, "verdict"), ts or now_ts()
        self._w(
            org,
            CREATE_VERDICT,
            {"id": vid, "finding": finding_id, "decision": decision, "reason": reason, "ts": ts},
        )
        if triage_id:
            self._w(org, LINK_VERDICT_TO_TRIAGE, {"triage": triage_id, "verdict": vid})
        return VerdictRec(id=vid, finding=finding_id, decision=decision, reason=reason, ts=ts)

    def verdicts(self, org: str, finding_ids: list[str]) -> list[VerdictRec]:
        return [
            VerdictRec(id=i, finding=f, decision=d, reason=r, ts=ts)
            for i, f, d, r, ts in self._r(org, READ_VERDICTS, {"ids": finding_ids})
        ]

    def record_risk_acceptance(
        self,
        org: str,
        finding_ids: list[str],
        reason: str,
        approved_by: str,
        expires: int,
        *,
        created: int | None = None,
    ) -> RiskAcceptanceRec:
        created = created or now_ts()
        if expires <= created:
            raise MemoryError_("a risk acceptance must expire after it is created")
        ids = sorted(set(finding_ids))
        self._require(org, "Finding", ids)
        self._require(org, "Person", [approved_by])
        rid = self._new_id(org, "riskacc")
        self._w(
            org,
            CREATE_RISK_ACCEPTANCE,
            {
                "id": rid,
                "reason": reason,
                "person": approved_by,
                "created": created,
                "expires": expires,
                "findings": ids,
            },
        )
        return RiskAcceptanceRec(
            id=rid,
            findings=ids,
            reason=reason,
            approved_by=approved_by,
            created=created,
            expires=expires,
            live=True,
        )

    def risk_acceptances(
        self,
        org: str,
        finding_ids: list[str],
        *,
        now: int | None = None,
        include_expired: bool = False,
    ) -> list[RiskAcceptanceRec]:
        """Acceptances on these findings. By default only LIVE ones (now < expires):
        an expired acceptance no longer suppresses anything."""
        rows = self._r(org, READ_RISK_ACCEPTANCES, {"ids": finding_ids, "now": now or now_ts()})
        out = [
            RiskAcceptanceRec(
                id=i,
                findings=f,
                reason=r,
                approved_by=a,
                approver_name=n,
                created=c,
                expires=e,
                live=bool(live),
            )
            for i, f, r, a, n, c, e, live in rows
        ]
        return out if include_expired else [x for x in out if x.live]

    # --- semantic: patterns --------------------------------------------------
    def upsert_pattern(
        self,
        org: str,
        kind: str,
        description: str,
        about_ids: list[str],
        *,
        seen_in: str | None = None,
        ts: int | None = None,
        pattern_id: str | None = None,
    ) -> PatternRec:
        """Create or refresh a Pattern. Same (kind, about entities) => same id, so
        re-learning a pattern updates it instead of duplicating it."""
        from .tools import label_of  # local: tools imports this module

        by_label: dict[str, list[str]] = {}
        for x in sorted(set(about_ids)):
            lbl = label_of(x)
            if lbl not in PATTERN_TARGETS:
                raise MemoryError_(f"a Pattern can only be ABOUT {sorted(PATTERN_TARGETS)}: {x!r}")
            by_label.setdefault(lbl, []).append(x)
        for lbl, ids in by_label.items():
            self._require(org, lbl, ids)
        if seen_in:
            self._require(org, "Triage", [seen_in])
        pid = pattern_id or (f"{org}:pattern:" + input_hash([kind, sorted(set(about_ids))])[:12])
        self._w(
            org,
            UPSERT_PATTERN,
            {"id": pid, "kind": kind, "description": description, "ts": ts or now_ts()},
        )
        for lbl, ids in by_label.items():
            self._w(org, LINK_PATTERN_ABOUT[lbl], {"id": pid, "ids": ids})
        if seen_in:
            self._w(org, LINK_PATTERN_SEEN_IN, {"id": pid, "triage": seen_in})
        return self._patterns_by_id(org, [pid])[0]

    def patterns_about(self, org: str, entity_ids: list[str]) -> list[PatternRec]:
        """Patterns ABOUT any of these entities (exact node match)."""
        ids = [r[0] for r in self._r(org, READ_PATTERNS_ABOUT, {"ids": entity_ids})]
        return self._patterns_by_id(org, ids)

    def _patterns_by_id(self, org: str, ids: list[str]) -> list[PatternRec]:
        if not ids:
            return []
        return [
            PatternRec(id=i, kind=k, description=d, ts=ts, about=sorted(a), seen_in=sorted(s))
            for i, k, d, ts, a, s, *_ in self._r(org, READ_PATTERNS_BY_ID, {"ids": ids})
        ]

    # --- procedural: versioned playbooks ------------------------------------
    def add_playbook_version(
        self, org: str, technique: str, body: str, *, ts: int | None = None
    ) -> PlaybookRec:
        """Publish the next version for a technique; it SUPERSEDES the current one,
        which stays in the graph as history."""
        cur = self.current_playbook(org, technique)
        version = (cur.version if cur else 0) + 1
        pid = f"{org}:playbook:{technique}:v{version}"
        self._w(org, ENSURE_TECHNIQUE, {"technique": technique})
        res = self._w(
            org,
            CREATE_PLAYBOOK,
            {
                "technique": technique,
                "id": pid,
                "version": version,
                "body": body,
                "ts": ts or now_ts(),
            },
        )
        if res.nodes_created == 0:
            raise MemoryError_(f"{pid} already exists: someone published v{version} first")
        if cur:
            self._w(org, LINK_SUPERSEDES, {"new": pid, "old": cur.id})
        return PlaybookRec(
            id=pid,
            technique=technique,
            version=version,
            body=body,
            ts=ts or now_ts(),
            supersedes=cur.id if cur else None,
        )

    def current_playbook(self, org: str, technique: str) -> PlaybookRec | None:
        rows = self._r(org, READ_CURRENT_PLAYBOOK, {"technique": technique})
        if len(rows) > 1:
            raise MemoryError_(f"{technique}: {len(rows)} unsuperseded playbooks")
        return _playbook(rows[0]) if rows else None

    def playbook_history(self, org: str, technique: str) -> list[PlaybookRec]:
        return [_playbook(r) for r in self._r(org, READ_PLAYBOOK_HISTORY, {"technique": technique})]

    def playbook_at(self, org: str, technique: str, ts: int) -> PlaybookRec | None:
        """The version that was current at time `ts` (latest published at or before it)."""
        live = [p for p in self.playbook_history(org, technique) if p.ts <= ts]
        return max(live, key=lambda p: p.version) if live else None

    # --- triage memory -------------------------------------------------------
    def triage_memory(
        self, org: str, finding_ids: list[str], *, now: int | None = None
    ) -> ToolResult:
        return triage_memory(lambda c, p: self._r(org, c, p), org, finding_ids, now=now)


# ------------------------------------------------------- triage memory (shared)
def triage_memory(
    read: Reader,
    org: str,
    finding_ids: list[str],
    *,
    now: int | None = None,
    qlog: list[QueryLog] | None = None,
) -> ToolResult:
    """Everything memory says about these findings, as a ToolResult.

    `read(cypher, params) -> rows` is injected so the same logic runs through
    GraphTools' logged read-only path (the MCP tool) or a MemoryRepo.
      * risk acceptances: LIVE ones suppress; expired ones are listed but do not;
      * verdicts: newest first;
      * patterns: about the finding's asset, its software image (same CPE), or
        its CVE anywhere in the org.
    """
    now = now or now_ts()
    ids = list(dict.fromkeys(finding_ids))
    ras = read(READ_RISK_ACCEPTANCES, {"ids": ids, "now": now})
    verdicts = read(READ_VERDICTS, {"ids": ids})
    ctx = read(READ_FINDING_CONTEXT, {"ids": ids})
    known = {r[0] for r in ctx}
    assets = sorted({r[1] for r in ctx})
    cves = sorted({r[3] for r in ctx})
    cpes = sorted({r[5] for r in ctx})
    pids = [
        r[0] for r in read(READ_PATTERNS_BY_CONTEXT, {"assets": assets, "cves": cves, "cpes": cpes})
    ]
    pats = read(READ_PATTERNS_BY_ID, {"ids": pids}) if pids else []

    per: dict[str, dict] = {
        f: {
            "finding": f,
            "suppressed": False,
            "live_acceptances": [],
            "expired_acceptances": [],
            "verdicts": [],
            "patterns": [],
        }
        for f in ids
        if f in known
    }
    ev = Evidence(node_ids=[f for f in ids if f in known])
    live, expired = [], []
    for rid, fids, reason, approver, name, created, expires, is_live in ras:
        rec = {
            "id": rid,
            "findings": fids,
            "reason": reason,
            "approved_by": approver,
            "approver_name": name,
            "created": created,
            "expires": expires,
            "live": bool(is_live),
        }
        (live if is_live else expired).append(rec)
        ev.node_ids += [rid, approver]
        ev.edges.append(EdgeRef(src=rid, rel="APPROVED_BY", dst=approver))
        for f in fids:
            if f in per:
                per[f]["live_acceptances" if is_live else "expired_acceptances"].append(rid)
                per[f]["suppressed"] = per[f]["suppressed"] or bool(is_live)
                ev.edges.append(EdgeRef(src=rid, rel="ON", dst=f))
    vrecs = []
    for vid, f, decision, reason, ts in verdicts:
        vrecs.append({"id": vid, "finding": f, "decision": decision, "reason": reason, "ts": ts})
        if f in per:
            per[f]["verdicts"].append(vid)
        ev.node_ids.append(vid)
        ev.edges.append(EdgeRef(src=vid, rel="ON", dst=f))
    prec = []
    for pid, kind, desc, ts, about, seen, p_assets, p_cves, p_cpes in pats:
        prec.append(
            {
                "id": pid,
                "kind": kind,
                "description": desc,
                "ts": ts,
                "about": sorted(about),
                "seen_in": sorted(seen),
            }
        )
        ev.node_ids += [pid, *about]
        ev.edges += [EdgeRef(src=pid, rel="ABOUT", dst=x) for x in about]
        # Attach the pattern to each finding it reaches: same asset, same
        # software image (CPE) or same CVE.
        for f, asset, _, cve, _, cpe in ctx:
            if asset in p_assets or cve in p_cves or cpe in p_cpes:
                per[f]["patterns"].append(pid)
    ev.node_ids = list(dict.fromkeys(ev.node_ids))

    unknown = [f for f in ids if f not in known]
    n_sup = sum(1 for p in per.values() if p["suppressed"])
    summary = (
        f"Memory for {len(per)} finding(s): {n_sup} suppressed by a LIVE risk acceptance"
        f"{f', {len(expired)} expired acceptance(s) no longer apply' if expired else ''}; "
        f"{len(vrecs)} past verdict(s); {len(prec)} pattern(s)."
        + (f" Unknown finding ids: {unknown}." if unknown else "")
    )
    return ToolResult(
        summary=summary,
        data={
            "as_of": now,
            "findings": list(per.values()),
            "live_risk_acceptances": live,
            "expired_risk_acceptances": expired,
            "verdicts": vrecs,
            "patterns": prec,
            "unknown_findings": unknown,
        },
        evidence=ev,
        queries=qlog or [],
    )
