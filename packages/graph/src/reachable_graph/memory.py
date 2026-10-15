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

import contextlib
import hashlib
import json
import re
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
    policy: list[dict] = Field(default_factory=list)  # machine-readable rules (S5)
    source: str | None = None  # None = seeded starter; "verdict:<id>" = learned


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

# by: who decided ('agent' for a run's Reporter; null for a human/seeded triage;
# 'analyst' verdicts use CREATE_ANALYST_VERDICT).
CREATE_VERDICT = """
MATCH (f:Finding {id: $finding})
CREATE (v:Verdict {id: $id, decision: $decision, reason: $reason, ts: $ts, by: $by})-[:ON]->(f)
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
# policy: JSON list of machine-readable rules (S5, from analyst verdicts);
# source: what produced the version (null for the seeded starter playbooks).
CREATE_PLAYBOOK = """
MATCH (t:Technique {id: $technique})
MERGE (p:Playbook {id: $id})
ON CREATE SET p.technique = $technique, p.version = $version, p.body = $body, p.ts = $ts,
              p.policy = $policy, p.source = $source
MERGE (t)-[:HANDLED_BY]->(p)
RETURN p.version
"""
LINK_SUPERSEDES = """
MATCH (n:Playbook {id: $new}), (o:Playbook {id: $old})
MERGE (n)-[:SUPERSEDES]->(o)
"""

# --- agent runs (S4) ----------------------------------------------------------
# A Run of the agent graph carries the scan it reasoned about and the clock it
# used (as_of), separate from `started`, the wall-clock time it executed.
START_AGENT_RUN = """
MERGE (r:Run {id: $id})
ON CREATE SET r.started = $started, r.kind = $kind, r.scan = $scan, r.as_of = $as_of,
              r.status = 'running', r.budget = $budget
RETURN r.id
"""
FINISH_RUN = """
MATCH (r:Run {id: $id})
SET r.status = $status, r.finished = $finished, r.stats = $stats, r.models = $models
RETURN r.id
"""
# Like APPEND_STEP, but the step carries the whole trace record as properties
# (agent, kind tool|llm, input JSON, the Cypher the tool ran, timing, ...).
APPEND_AGENT_STEP = """
MATCH (r:Run {id: $run})
OPTIONAL MATCH (r)-[:HAS_STEP]->(prev:AgentStep)
WITH r, prev ORDER BY prev.seq DESC LIMIT 1
CREATE (r)-[:HAS_STEP]->(s:AgentStep {id: $id, seq: coalesce(prev.seq, -1) + 1})
SET s += $props
FOREACH (p IN CASE WHEN prev IS NULL THEN [] ELSE [prev] END | CREATE (p)-[:NEXT]->(s))
RETURN s.seq
"""
# A tool result, stored once per run per distinct content (id = run + sha), so
# a cache hit points at the very node the first call produced.
WRITE_TOOL_OUTPUT = """
MERGE (o:ToolOutput {id: $id})
ON CREATE SET o.tool = $tool, o.sha = $sha, o.summary = $summary, o.body = $body
RETURN o.id
"""
LINK_STEP_RESULT = """
MATCH (s:AgentStep {id: $step}), (o:ToolOutput {id: $output})
MERGE (s)-[:RESULT]->(o)
"""
# Each agent's handoff output, one label per agent. Labels come from this
# fixed tuple, never from input. Drift (S5) is the Sentinel's, written before
# Triage on a run over a new scan; Triage is then BUILT_ON it.
OUTPUT_LABELS = ("Drift", "Triage", "PathAnalysis", "FixPlan", "Report")
WRITE_OUTPUT = {
    label: f"""
MATCH (r:Run {{id: $run}})
CREATE (r)-[:HAS_OUTPUT {{agent: $agent}}]->(o:{label} {{id: $id}})
SET o.agent = $agent, o.ts = $ts, o.as_of = $as_of, o.summary = $summary, o.payload = $payload
RETURN o.id
"""
    for label in OUTPUT_LABELS
}
LINK_OUTPUT_CITES = {
    label: f"""
MATCH (o:{label} {{id: $id}})
MATCH (f:Finding) WHERE f.id IN $findings
MERGE (o)-[:CITES]->(f)
RETURN count(f)
"""
    for label in OUTPUT_LABELS
}
# The handoff chain: each output was built on the previous agent's output.
LINK_BUILT_ON = {
    (new, old): f"""
MATCH (n:{new} {{id: $new}}), (o:{old} {{id: $old}})
MERGE (n)-[:BUILT_ON]->(o)
"""
    for new, old in zip(OUTPUT_LABELS[1:], OUTPUT_LABELS[:-1], strict=True)
}

# --- S5 ----------------------------------------------------------------------
SET_RUN_STATUS = "MATCH (r:Run {id: $id}) SET r.status = $status RETURN r.id"
# The Sentinel's alert: only ever raised for a brand-new path to a crown jewel.
RAISE_ALERT = """
MATCH (r:Run {id: $run})
CREATE (r)-[:RAISED]->(a:Alert {id: $id})
SET a.kind = $kind, a.ts = $ts, a.raised = $raised, a.from_scan = $from_scan,
    a.to_scan = $to_scan, a.summary = $summary, a.payload = $payload
RETURN a.id
"""
LINK_ALERT_CITES = """
MATCH (a:Alert {id: $id})
MATCH (f:Finding) WHERE f.id IN $ids
MERGE (a)-[:CITES]->(f)
RETURN count(f)
"""
LINK_ALERT_ABOUT = """
MATCH (a:Alert {id: $id})
MATCH (x:Asset) WHERE x.id IN $ids
MERGE (a)-[:ABOUT]->(x)
RETURN count(x)
"""
# An analyst's review of an agent verdict (procedural memory's input).
CREATE_ANALYST_VERDICT = """
MATCH (f:Finding {id: $finding}), (o:Verdict {id: $reviews})
CREATE (v:Verdict {id: $id, decision: $decision, reason: $reason, ts: $ts, by: 'analyst',
                   review: $review, overrides: $overrides, run: $run})-[:ON]->(f)
CREATE (v)-[:REVIEWS]->(o)
RETURN v.id
"""
LINK_VERDICT_LED_TO = """
MATCH (v:Verdict {id: $verdict}), (p:Playbook {id: $playbook})
MERGE (v)-[:LED_TO]->(p)
"""

# Cold start: delete every memory node except the seeded starter playbooks (and
# the Technique anchors). One fixed query per label; labels from this tuple only.
RESET_LABELS = (
    "AgentStep",
    "ToolOutput",
    "Report",
    "FixPlan",
    "PathAnalysis",
    "Drift",
    "Alert",
    "Verdict",
    "Triage",
    "Run",
    "RiskAcceptance",
    "Pattern",
)
RESET_MEMORY = {label: f"MATCH (n:{label}) DETACH DELETE n" for label in RESET_LABELS}
RESET_LEARNED_PLAYBOOKS = "MATCH (p:Playbook) WHERE p.source IS NOT NULL DETACH DELETE p"

# Carry-over (scan v1's graph -> scan v2's): memory belongs to the org, not to a
# scan. Every copied node is MERGEd by id with the source's properties; every
# copied edge is MERGEd between nodes that exist in the target (infrastructure
# nodes are matched, never created). Labels and edge types come from these
# fixed tables only.
CARRY_LABELS = (
    "Technique",
    "Playbook",
    "RiskAcceptance",
    "Triage",
    "Verdict",
    "Pattern",
    "Run",
    "Drift",
    "PathAnalysis",
    "FixPlan",
    "Report",
)
CARRY_NODE = {label: f"MERGE (n:{label} {{id: $id}}) SET n += $props" for label in CARRY_LABELS}
CARRY_EDGES = (
    ("Technique", "HANDLED_BY", "Playbook"),
    ("Playbook", "SUPERSEDES", "Playbook"),
    ("RiskAcceptance", "ON", "Finding"),
    ("RiskAcceptance", "APPROVED_BY", "Person"),
    ("Verdict", "ON", "Finding"),
    ("Verdict", "REVIEWS", "Verdict"),
    ("Verdict", "LED_TO", "Playbook"),
    ("Triage", "HAS_VERDICT", "Verdict"),
    ("Pattern", "ABOUT", "Asset"),
    ("Pattern", "ABOUT", "Software"),
    ("Pattern", "ABOUT", "Vuln"),
    ("Pattern", "SEEN_IN", "Triage"),
    ("Run", "HAS_TRIAGE", "Triage"),
    *(("Run", "HAS_OUTPUT", lbl) for lbl in OUTPUT_LABELS),
    *((lbl, "CITES", "Finding") for lbl in OUTPUT_LABELS),
    *(zip(OUTPUT_LABELS[1:], ("BUILT_ON",) * 4, OUTPUT_LABELS[:-1], strict=True)),
)
CARRY_EDGE = {
    (a, rel, b): f"MATCH (a:{a} {{id: $a}}) MATCH (b:{b} {{id: $b}}) MERGE (a)-[:{rel}]->(b)"
    for a, rel, b in CARRY_EDGES
}

WRITE_QUERIES = frozenset(
    {
        SET_RUN_STATUS,
        RAISE_ALERT,
        LINK_ALERT_CITES,
        LINK_ALERT_ABOUT,
        CREATE_ANALYST_VERDICT,
        LINK_VERDICT_LED_TO,
        *RESET_MEMORY.values(),
        RESET_LEARNED_PLAYBOOKS,
        *CARRY_NODE.values(),
        *CARRY_EDGE.values(),
        CREATE_RUN,
        APPEND_STEP,
        START_AGENT_RUN,
        FINISH_RUN,
        APPEND_AGENT_STEP,
        WRITE_TOOL_OUTPUT,
        LINK_STEP_RESULT,
        *WRITE_OUTPUT.values(),
        *LINK_OUTPUT_CITES.values(),
        *LINK_BUILT_ON.values(),
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
RETURN p.id, p.technique, p.version, p.body, p.ts, o.id, p.policy, p.source
"""
READ_PLAYBOOK_HISTORY = """
MATCH (:Technique {id: $technique})-[:HANDLED_BY]->(p:Playbook)
OPTIONAL MATCH (p)-[:SUPERSEDES]->(o:Playbook)
RETURN p.id, p.technique, p.version, p.body, p.ts, o.id, p.policy, p.source
ORDER BY p.version DESC
"""

# --- S5 reads ------------------------------------------------------------------
# The verdict a run's Reporter recorded on a finding (what an analyst reviews).
READ_RUN_VERDICT = """
MATCH (:Run {id: $run})-[:HAS_TRIAGE]->(t:Triage)-[:HAS_VERDICT]->(v:Verdict)
MATCH (v)-[:ON]->(:Finding {id: $finding})
RETURN v.id, v.decision, v.reason, t.id ORDER BY v.ts DESC, v.id LIMIT 1
"""
# Episodic recall: the latest earlier agent run's fix plan (its routing).
READ_PRIOR_FIXPLAN = """
MATCH (r:Run)-[:HAS_OUTPUT]->(o:FixPlan)
WHERE r.id <> $run AND r.as_of <= $as_of AND r.status IN ['complete', 'degraded']
RETURN r.id, r.as_of, o.payload ORDER BY r.as_of DESC, r.started DESC, o.ts DESC LIMIT 1
"""
# The live stream (S5 API): a run's steps after a given seq, light (no result
# bodies), and the run's own properties (status, stats).
READ_STEPS_AFTER = """
MATCH (r:Run {id: $id})-[:HAS_STEP]->(s:AgentStep) WHERE s.seq > $after
RETURN properties(s) ORDER BY s.seq LIMIT $limit
"""
READ_RECENT_RUNS = """
MATCH (r:Run) WHERE r.kind IN ['agent_triage', 'sentinel'] AND r.carried_from IS NULL
RETURN r.id, r.kind, r.scan, r.status, r.started, r.as_of, r.models
ORDER BY r.started DESC LIMIT $limit
"""
READ_ALERTS = """
MATCH (r:Run)-[:RAISED]->(a:Alert)
RETURN a.id, a.kind, a.ts, a.from_scan, a.to_scan, a.summary, r.id ORDER BY a.raised DESC
"""
# Carry-over reads: every memory node of a label with its properties, and the
# edges between memory nodes and what they are about.
CARRY_READ_NODES = {
    label: f"MATCH (n:{label}) RETURN n.id, properties(n)" for label in CARRY_LABELS
}
CARRY_READ_EDGES = {
    (a, rel, b): f"MATCH (x:{a})-[:{rel}]->(y:{b}) RETURN x.id, y.id" for a, rel, b in CARRY_EDGES
}

# agent runs (S4)
READ_SCAN = "MATCH (s:Scan) RETURN s.id, s.version, s.ts ORDER BY s.ts DESC LIMIT 1"
READ_RUN_PROPS = "MATCH (r:Run {id: $id}) RETURN properties(r)"
READ_AGENT_STEPS = """
MATCH (r:Run {id: $id})-[:HAS_STEP]->(s:AgentStep)
OPTIONAL MATCH (s)-[:RESULT]->(o:ToolOutput)
RETURN properties(s), o.id, o.body ORDER BY s.seq
"""
READ_OUTPUT = {
    label: f"""
MATCH (:Run {{id: $run}})-[:HAS_OUTPUT]->(o:{label})
RETURN o.id, o.agent, o.ts, o.summary, o.payload ORDER BY o.ts DESC LIMIT 1
"""
    for label in OUTPUT_LABELS
}
# Step / run properties stored as JSON text (FalkorDB holds primitives and flat arrays).
_JSON_PROPS = {"input", "queries", "tool_calls", "budget", "stats", "detail"}


def _playbook(row) -> PlaybookRec:
    pid, tech, version, body, ts, old, policy, source = row
    return PlaybookRec(
        id=pid,
        technique=tech,
        version=version,
        body=body,
        ts=ts,
        supersedes=old,
        policy=_policy(policy),
        source=source,
    )


def _policy(raw) -> list[dict]:
    """A playbook's machine-readable rules (JSON text; none on starter playbooks)."""
    if not raw:
        return []
    try:
        rules = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return [r for r in rules if isinstance(r, dict)] if isinstance(rules, list) else []


# An analyst who rejects an agent's decision is saying "one notch the other way".
ESCALATE = {
    "schedule": "fix_now",
    "not_reachable": "schedule",
    "accept_risk": "fix_now",
    "false_positive": "schedule",
    "fix_now": "schedule",
}
# A reject reason that is about this one instance is not a rule for the next
# finding: it names a node, or says why only this case is special.
_INSTANCE_WORDS = re.compile(
    r"\b(this (host|box|server|one|finding|asset|instance)|just this|only this|one[- ]off|"
    r"decommission\w*|temporar\w*|this week|until (monday|tuesday|wednesday|thursday|friday)|"
    r"[a-z0-9_]+:(asset|finding|vuln|sw|secret|ident|ds):\d+)\b",
    re.IGNORECASE,
)


def is_reusable(reason: str) -> bool:
    """Is a reject reason a rule for every finding like this one (-> a new playbook
    version), or about this instance only (-> just the verdict)? Deliberately
    simple and explainable; the CLI / API can override it."""
    return len(reason.split()) >= 5 and not _INSTANCE_WORDS.search(reason)


# ------------------------------------------------------------------ repository
class MemoryRepo:
    """Read/write agent memory in one FalkorDB connection's org graphs."""

    def __init__(
        self, db=None, *, allowed_orgs: list[str] | None = None, timeout_ms: int = QUERY_TIMEOUT_MS
    ) -> None:
        self.db = db or connect()
        self.allowed = set(allowed_orgs or get_settings().graphs)
        self.timeout_ms = timeout_ms
        self.lock_waits = 0  # how often a memory lock was contended (S5 concurrency)

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
        by: str | None = None,
    ) -> VerdictRec:
        self._require(org, "Finding", [finding_id])
        if triage_id:
            self._require(org, "Triage", [triage_id])
        vid, ts = self._new_id(org, "verdict"), ts or now_ts()
        self._w(
            org,
            CREATE_VERDICT,
            {
                "id": vid,
                "finding": finding_id,
                "decision": decision,
                "reason": reason,
                "ts": ts,
                "by": by,
            },
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
        self,
        org: str,
        technique: str,
        body: str,
        *,
        ts: int | None = None,
        policy: list[dict] | None = None,
        source: str | None = None,
        lock: bool = True,
    ) -> PlaybookRec:
        """Publish the next version for a technique; it SUPERSEDES the current one,
        which stays in the graph as history.

        Read-modify-write (read the current version, write version + 1), so two
        writers can race: both read v2, both try v3, one loses (MERGE on the
        deterministic id refuses the duplicate). The memory lock serialises just
        this, so the second writer reads v3 and publishes v4: no lost update."""
        with self.lock(org, f"playbook:{technique}") if lock else contextlib.nullcontext():
            cur = self.current_playbook(org, technique)
            version = (cur.version if cur else 0) + 1
            pid = f"{org}:playbook:{technique}:v{version}"
            ts = ts or now_ts()
            self._w(org, ENSURE_TECHNIQUE, {"technique": technique})
            res = self._w(
                org,
                CREATE_PLAYBOOK,
                {
                    "technique": technique,
                    "id": pid,
                    "version": version,
                    "body": body,
                    "ts": ts,
                    "policy": json.dumps(policy) if policy else None,
                    "source": source,
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
            ts=ts,
            supersedes=cur.id if cur else None,
            policy=policy or [],
            source=source,
        )

    # --- S5: a short lock for read-modify-write memory updates ---------------
    @contextlib.contextmanager
    def lock(self, org: str, name: str, *, ttl_ms: int = 5_000, wait_s: float = 10.0):
        """A short mutual-exclusion lock, held in the FalkorDB server itself (it
        speaks Redis: SET NX PX), so it serialises writers across threads AND
        processes (the API, the CLI, an eval). Only read-modify-write memory
        updates take it; plain CREATE/MERGE writes are atomic per query already.
        The TTL frees it if a holder dies; release is compare-and-delete, so a
        holder that outlived its TTL cannot free someone else's lock."""
        key = f"reachable:lock:{self._org(org)}:{name}"
        token = uuid.uuid4().hex
        conn = self.db.connection
        deadline = time.monotonic() + wait_s
        waited = 0
        while not conn.set(key, token, nx=True, px=ttl_ms):
            if time.monotonic() > deadline:
                raise MemoryError_(f"memory lock {name!r} on {org} still held after {wait_s}s")
            waited += 1
            time.sleep(0.01)
        self.lock_waits += waited > 0
        try:
            yield
        finally:
            conn.eval(_RELEASE_LUA, 1, key, token)

    def set_run_status(self, org: str, run_id: str, status: str) -> None:
        self._w(org, SET_RUN_STATUS, {"id": run_id, "status": status})

    # --- S5: the Sentinel's alert ---------------------------------------------
    def raise_alert(
        self,
        org: str,
        run_id: str,
        *,
        kind: str,
        ts: int,
        from_scan: str,
        to_scan: str,
        summary: str,
        payload: dict,
        findings: list[str],
        assets: list[str],
    ) -> str:
        aid = self._new_id(org, "alert")
        self._w(
            org,
            RAISE_ALERT,
            {
                "run": run_id,
                "id": aid,
                "kind": kind,
                "ts": ts,
                "raised": now_ts(),
                "from_scan": from_scan,
                "to_scan": to_scan,
                "summary": summary,
                "payload": json.dumps(payload, sort_keys=True, default=str),
            },
        )
        if findings:
            self._w(org, LINK_ALERT_CITES, {"id": aid, "ids": sorted(set(findings))})
        if assets:
            self._w(org, LINK_ALERT_ABOUT, {"id": aid, "ids": sorted(set(assets))})
        return aid

    # --- S5: what the live stream reads ---------------------------------------
    def run_head(self, org: str, run_id: str) -> dict | None:
        rows = self._r(org, READ_RUN_PROPS, {"id": run_id})
        return _decode(dict(rows[0][0])) if rows else None

    def steps_after(self, org: str, run_id: str, after: int = -1, limit: int = 200) -> list[dict]:
        """A run's trace steps with seq > after, in order, without result bodies."""
        rows = self._r(org, READ_STEPS_AFTER, {"id": run_id, "after": after, "limit": limit})
        return [_decode(dict(r[0])) for r in rows]

    def recent_runs(self, org: str, limit: int = 10) -> list[dict]:
        keys = ("id", "kind", "scan", "status", "started", "as_of", "models")
        return [
            dict(zip(keys, r, strict=True))
            for r in self._r(org, READ_RECENT_RUNS, {"limit": limit})
        ]

    def alerts(self, org: str) -> list[dict]:
        keys = ("id", "kind", "ts", "from_scan", "to_scan", "summary", "run")
        return [dict(zip(keys, r, strict=True)) for r in self._r(org, READ_ALERTS)]

    # --- S5: cold start and carry-over ---------------------------------------
    def reset_memory(self, org: str) -> dict[str, int]:
        """Cold start: delete every memory node (runs, traces, outputs, verdicts,
        risk acceptances, patterns, alerts, learned playbook versions). Keeps only
        the seeded starter playbooks and the Technique anchors. Infrastructure is
        never touched: each query is a fixed DETACH DELETE on one memory label."""
        out = {}
        for label in RESET_LABELS:
            out[label] = self._w(org, RESET_MEMORY[label], {}).nodes_deleted
        out["Playbook(learned)"] = self._w(org, RESET_LEARNED_PLAYBOOKS, {}).nodes_deleted
        return out

    def carry_over(self, src: str, dst: str) -> dict[str, int]:
        """Copy the org's memory from one scan's graph into the next scan's graph.

        Memory belongs to the org, not to a scan; our scans live in separate
        graphs (`org_a` = v1, `org_a_v2` = v2) so they can be diffed side by side.
        A new scan therefore inherits the previous graph's memory: playbooks (every
        version), risk acceptances, verdicts (and the triages they hang off),
        patterns, and each earlier run with its handoff outputs (not its
        step-by-step trace, which stays where it ran). MERGE by id: idempotent.
        Edges attach to infrastructure nodes that exist in the new scan by id; a
        memory edge to something the new scan no longer has is dropped."""
        counts: dict[str, int] = {}
        for label in CARRY_LABELS:
            rows = self._r(src, CARRY_READ_NODES[label])
            for nid, props in rows:
                props = {k: v for k, v in dict(props).items() if k != "id"}
                if label == "Run":
                    props.setdefault("carried_from", src)
                self._w(dst, CARRY_NODE[label], {"id": nid, "props": props})
            counts[label] = len(rows)
        edges = 0
        for triple in CARRY_EDGES:
            for a, b in self._r(src, CARRY_READ_EDGES[triple]):
                self._w(dst, CARRY_EDGE[triple], {"a": a, "b": b})
                edges += 1
        counts["edges"] = edges
        return counts

    # --- S5: episodic recall for the Fixer -----------------------------------
    def prior_routes(self, org: str, *, run_id: str, as_of: int) -> tuple[str | None, dict]:
        """Who got each fix last time: the routing in the latest earlier run's fix
        plan, per asset, kept only while that on-call slot still covers `as_of`
        (a week later the pager may have moved on: look it up again)."""
        rows = self._r(org, READ_PRIOR_FIXPLAN, {"run": run_id, "as_of": as_of})
        if not rows:
            return None, {}
        prior, _, payload = rows[0]
        routes = {}
        for f in json.loads(payload).get("fixes", []):
            oc = f.get("on_call") or {}
            if not f.get("asset") or not f.get("team") or not _covers(oc.get("window"), as_of):
                continue
            routes.setdefault(
                f["asset"],
                {
                    "asset": f["asset"],
                    "team": f["team"],
                    "on_call": oc,
                    "adrs": f.get("adrs", []),
                    "source": f"memory:{prior}",
                },
            )
        return prior, routes

    # --- S5: procedural memory from an analyst's verdict ----------------------
    def record_analyst_verdict(
        self,
        org: str,
        run_id: str,
        finding_id: str,
        review: Literal["accept", "reject"],
        reason: str,
        *,
        reusable: bool | None = None,
    ) -> dict:
        """An analyst accepts or rejects the decision a run made on a finding.

        accept: a Verdict confirming the agent's decision.
        reject: a Verdict with the corrected decision (ESCALATE: one notch the
          other way). If the reason is reusable (a rule, not a remark about this
          one host; see is_reusable), it becomes a new Playbook version for the
          finding's ATT&CK technique(s): the old version stays and is SUPERSEDED,
          and the new one carries a machine-readable rule {when, decision,
          instead_of} that later runs apply.
        Both are timestamped on the synthetic clock, one hour after the run's
        scan: a run of a LATER scan sees them; a re-run "as of" the same scan
        time sees memory as it was then."""
        if review not in ("accept", "reject"):
            raise MemoryError_("review must be 'accept' or 'reject'")
        head = self._r(org, READ_RUN_PROPS, {"id": run_id})
        if not head:
            raise MemoryError_(f"no Run {run_id!r} in {org}")
        run = _decode(dict(head[0][0]))
        rows = self._r(org, READ_RUN_VERDICT, {"run": run_id, "finding": finding_id})
        if not rows:
            raise MemoryError_(f"run {run_id} recorded no verdict on {finding_id}")
        agent_vid, agent_decision, _, _ = rows[0]
        decision = ESCALATE.get(agent_decision, "fix_now") if review == "reject" else agent_decision
        ts = int(run.get("as_of") or now_ts()) + ANALYST_DELAY_S
        vid = self._new_id(org, "verdict")
        self._w(
            org,
            CREATE_ANALYST_VERDICT,
            {
                "finding": finding_id,
                "reviews": agent_vid,
                "id": vid,
                "decision": decision,
                "reason": reason,
                "ts": ts,
                "review": review,
                "overrides": agent_decision if review == "reject" else None,
                "run": run_id,
            },
        )
        out = {
            "verdict": vid,
            "finding": finding_id,
            "review": review,
            "agent_decision": agent_decision,
            "decision": decision,
            "reusable": False,
            "playbooks": [],
        }
        if review != "reject":
            return out
        reusable = is_reusable(reason) if reusable is None else reusable
        out["reusable"] = reusable
        if not reusable:
            return out
        facts = self._finding_facts(org, run_id, finding_id)
        for tech in facts.pop("techniques"):
            rule = {
                "when": facts,
                "decision": decision,
                "instead_of": agent_decision,
                "because": reason,
                "verdict": vid,
            }
            with self.lock(org, f"playbook:{tech}"):
                cur = self.current_playbook(org, tech)
                n = (cur.body.count("\n") + 2) if cur else 1
                when = ", ".join(f"{k}={v}" for k, v in facts.items())
                line = (
                    f"{n}. Analyst rule ({vid}): a {tech} finding with {when} is {decision}, "
                    f"not {agent_decision}. {reason}"
                )
                pb = self.add_playbook_version(
                    org,
                    tech,
                    f"{cur.body}\n{line}" if cur else line,
                    ts=ts,
                    policy=[*(cur.policy if cur else []), rule],
                    source=f"verdict:{vid}",
                    lock=False,  # held above, across the read of the current version
                )
            self._w(org, LINK_VERDICT_LED_TO, {"verdict": vid, "playbook": pb.id})
            out["playbooks"].append(
                {"id": pb.id, "technique": tech, "version": pb.version, "supersedes": pb.supersedes}
            )
        return out

    def _finding_facts(self, org: str, run_id: str, finding_id: str) -> dict:
        """What a playbook rule generalises over: the finding's ATT&CK techniques
        and, as the run saw them, whether it is a way in from the Internet, on a
        crown-jewel path, and in CISA KEV."""
        tp = (self.read_output(org, run_id, "Triage") or {}).get("payload", {})
        pp = (self.read_output(org, run_id, "PathAnalysis") or {}).get("payload", {})
        techs, inet = set(), False
        for p in pp.get("paths", []):
            for s in p["steps"]:
                if s.get("fix_token") == finding_id:
                    techs.add(s.get("technique"))
                    inet = inet or s["key"].split("|")[2] == "internet"
        row = next(
            (
                f
                for f in tp.get("investigate", []) + tp.get("carried", [])
                if f["finding"] == finding_id
            ),
            {},
        )
        techs |= set(row.get("techniques") or [])
        return {
            "techniques": sorted(t for t in techs if t),
            "from_internet": inet,
            "on_crown_path": any(r["finding"] == finding_id for r in pp.get("ranked", [])),
            "kev": bool(row.get("kev")),
        }

    def finding_context(self, org: str, finding_ids: list[str]) -> dict[str, dict]:
        """Asset, vuln (CVE) and software (CPE) behind each finding."""
        rows = self._r(org, READ_FINDING_CONTEXT, {"ids": list(dict.fromkeys(finding_ids))})
        return {
            f: {"asset": a, "vuln": v, "cve": cve, "software": s, "cpe": cpe}
            for f, a, v, cve, s, cpe in rows
        }

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

    # --- agent runs (S4): the handoff record ---------------------------------
    def scan_info(self, org: str) -> dict | None:
        """The scan this graph holds and when it ran: the agents' clock."""
        rows = self._r(org, READ_SCAN)
        return {"id": rows[0][0], "version": rows[0][1], "ts": rows[0][2]} if rows else None

    def start_agent_run(
        self,
        org: str,
        *,
        kind: str,
        scan: str,
        as_of: int,
        budget: dict,
        run_id: str | None = None,
        started: int | None = None,
    ) -> str:
        rid = run_id or self._new_id(org, "run")
        self._w(
            org,
            START_AGENT_RUN,
            {
                "id": rid,
                "kind": kind,
                "scan": scan,
                "as_of": as_of,
                "budget": json.dumps(budget, sort_keys=True),
                "started": started or now_ts(),
            },
        )
        return rid

    def append_agent_step(
        self, org: str, run_id: str, props: dict[str, Any], *, output: dict | None = None
    ) -> AgentStepRec:
        """Append one traced step (a tool call or an LLM call). Dict/list values are
        stored as JSON text. `output` = {tool, sha, summary, body}: the result,
        stored once per (run, sha) and linked with RESULT."""
        sid = self._new_id(org, "step")
        flat = {
            k: (json.dumps(v, sort_keys=True, default=str) if isinstance(v, dict | list) else v)
            for k, v in props.items()
            if v is not None
        }
        flat.setdefault("ts", now_ts())
        flat.setdefault("input_hash", input_hash(props.get("input")))
        res = self._w(org, APPEND_AGENT_STEP, {"run": run_id, "id": sid, "props": flat})
        if not res.result_set:
            raise MemoryError_(f"no Run {run_id!r} in {org}")
        if output is not None:
            oid = f"{run_id}:out:{output['sha'][:16]}"
            self._w(org, WRITE_TOOL_OUTPUT, {"id": oid, **output})
            self._w(org, LINK_STEP_RESULT, {"step": sid, "output": oid})
        return AgentStepRec(
            id=sid,
            tool=flat.get("tool", ""),
            input_hash=flat.get("input_hash", ""),
            ts=flat["ts"],
            seq=res.result_set[0][0],
        )

    def write_output(
        self,
        org: str,
        run_id: str,
        label: str,
        *,
        agent: str,
        payload: dict,
        summary: str,
        as_of: int,
        cites: list[str] | None = None,
        built_on: str | None = None,
        ts: int | None = None,
    ) -> str:
        """Write one agent's handoff output; the next agent reads it back with
        read_output. CITES links it to the findings it talks about, BUILT_ON to
        the output it was built from."""
        if label not in OUTPUT_LABELS:
            raise MemoryError_(f"unknown output label {label!r}")
        oid = self._new_id(org, label.lower())
        self._w(
            org,
            WRITE_OUTPUT[label],
            {
                "run": run_id,
                "id": oid,
                "agent": agent,
                "ts": ts or now_ts(),
                "as_of": as_of,
                "summary": summary,
                "payload": json.dumps(payload, sort_keys=True, default=str),
            },
        )
        if label == "Triage":  # also the S3 shape: Run -[:HAS_TRIAGE]-> Triage
            self._w(org, LINK_TRIAGE_TO_RUN, {"run": run_id, "triage": oid})
        if cites:
            self._w(org, LINK_OUTPUT_CITES[label], {"id": oid, "findings": sorted(set(cites))})
        if built_on:
            prev = OUTPUT_LABELS[OUTPUT_LABELS.index(label) - 1]
            self._w(org, LINK_BUILT_ON[(label, prev)], {"new": oid, "old": built_on})
        return oid

    def read_output(self, org: str, run_id: str, label: str) -> dict | None:
        """The latest output of this kind in the run, payload decoded."""
        if label not in OUTPUT_LABELS:
            raise MemoryError_(f"unknown output label {label!r}")
        rows = self._r(org, READ_OUTPUT[label], {"run": run_id})
        if not rows:
            return None
        oid, agent, ts, summary, payload = rows[0]
        return {
            "id": oid,
            "agent": agent,
            "ts": ts,
            "summary": summary,
            "payload": json.loads(payload),
        }

    def finish_run(
        self, org: str, run_id: str, *, status: str, stats: dict, models: list[str]
    ) -> None:
        self._w(
            org,
            FINISH_RUN,
            {
                "id": run_id,
                "status": status,
                "finished": now_ts(),
                "stats": json.dumps(stats, sort_keys=True),
                "models": models,
            },
        )

    def agent_run(self, org: str, run_id: str) -> dict:
        """The whole run read back from the graph: run properties, every step in
        seq order (with its stored result), every agent output. Enough to replay
        or re-render the run without the process that produced it."""
        head = self._r(org, READ_RUN_PROPS, {"id": run_id})
        if not head:
            raise MemoryError_(f"no Run {run_id!r} in {org}")
        run = _decode(dict(head[0][0]))
        steps = []
        for props, oid, body in self._r(org, READ_AGENT_STEPS, {"id": run_id}):
            s = _decode(dict(props))
            s["result_ref"] = oid
            s["result"] = json.loads(body) if body else None
            steps.append(s)
        outputs = {}
        for label in OUTPUT_LABELS:
            out = self.read_output(org, run_id, label)
            if out:
                outputs[label] = out
        return {
            "run": run,
            "steps": steps,
            "outputs": outputs,
            "chain_ok": self.get_run(org, run_id).chain_ok,
        }

    # --- triage memory -------------------------------------------------------
    def triage_memory(
        self, org: str, finding_ids: list[str], *, now: int | None = None
    ) -> ToolResult:
        return triage_memory(lambda c, p: self._r(org, c, p), org, finding_ids, now=now)


ANALYST_DELAY_S = 3600  # an analyst reviews a run an hour after its scan (synthetic clock)
_RELEASE_LUA = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) "
    "else return 0 end"
)


def _covers(window: str | None, ts: int) -> bool:
    """Does an on-call window 'YYYY-MM-DD/YYYY-MM-DD' (end exclusive) cover ts?"""
    if not window or "/" not in window:
        return False
    from datetime import UTC, datetime

    start, end = (
        int(datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=UTC).timestamp())
        for d in window.split("/")
    )
    return start <= ts < end


def _decode(props: dict) -> dict:
    for k in _JSON_PROPS & set(props):
        with contextlib.suppress(TypeError, ValueError):
            props[k] = json.loads(props[k])
    return props


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
