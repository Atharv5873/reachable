"""Derive the ATTACK_STEP layer: one Cypher query per attack rule.

The org graph loaded in S1 describes *infrastructure*: what is exposed, what can
reach what, what runs where, which secrets sit on which hosts. It does not say
what an attacker can *do*. This module materialises that as a second layer of
edges between the concrete entity nodes already in the graph:

    (Internet | Asset | Identity | Secret | DataStore)
        -[:ATTACK_STEP {key, rule, technique, likelihood, cost, fix_token, because}]->
    (Asset | Identity | Secret | DataStore)

Each rule in reachable_core.attack_rules is ONE Cypher query: MATCH the rule's
precondition as a graph pattern, then MERGE the step. The networkx oracle in
packages/orggen implements the same rules in Python; tests/test_derive.py checks
that both produce the same Internet -> crown-jewel paths with the same fix tokens.

Edge properties:
    key        deterministic MERGE key  "<rule>|<fix_token>|<src id>|<dst id>"
    rule       attack_rules rule name
    technique  ATT&CK technique id
    likelihood 0..1 chance the step succeeds
    cost       -ln(likelihood), so the cheapest path is the MOST LIKELY path
               (sum of -ln p  =  -ln of the product of p)
    fix_token  what a defender remediates to remove this edge: a Finding id for
               exploit steps, or a step:<kind>:<a>:<b> token for credential and
               permission hops. Same vocabulary as the oracle.
    because    evidence node ids (Finding, Vuln, Software, Secret, ...) that
               justify the step; why_step() resolves them.

The local_privesc fold. The oracle models privilege as a separate state node
priv:<asset> (asset -> priv:asset -> root-owned secret). We don't invent loose
state nodes in the graph: a privesc is only useful for what it unlocks, so the
edge lands directly on the root-owned Secret, with fix_token = the privesc
Finding and because = [finding, vuln, software, secret]. Its likelihood is
privesc x creds_in_files, so a path's total likelihood matches the oracle's.

After the steps, two derived helpers are built from ATTACK_STEP alone:
  * the FLOW layer (node-split fix tokens) that algo.maxFlow runs on, and
  * a :CrownPath label on every node lying on an Internet -> crown-jewel path,
    which lets algo.betweenness restrict itself to the part that matters.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from reachable_core.attack_rules import (
    HOP_CAP,
    NETWORK_VECTORS,
    OPEN_STATUS,
    PRIVESC_MIN_CVSS,
    READ_ACTIONS,
    RULES,
)
from reachable_core.db import create_range_index
from reachable_core.effort import (
    DEFAULT_KIND_EFFORT,
    FIX_AT_SOURCE,
    KIND_EFFORT,
    MAX_EFFORT,
    MIN_EFFORT,
    STEP_EFFORT,
)

# "Infinite" capacity for structural FLOW edges. Any value larger than the
# number of fix tokens works: the max flow can never exceed the token count.
BIG_CAPACITY = 1_000_000

# ---------------------------------------------------------------------------
# FalkorDB gotcha: `MATCH ... WHERE NOT (pattern)  MATCH (f) ...  WITH f.id`
# fails with "'f' not defined". So each rule puts ALL its patterns in one
# comma-joined MATCH, followed by a single WHERE holding the pattern predicate.
#
# Shared tail of every rule query. Each rule ends with
#     WITH src, dst, token, lk, because
# and this MERGEs the step. MERGE on the deterministic key makes re-running a
# no-op; SET refreshes the payload; `stale = false` marks it as seen this run.
# ---------------------------------------------------------------------------
_EMIT = """
MERGE (src)-[e:ATTACK_STEP {key: $rule + '|' + token + '|' + src.id + '|' + dst.id}]->(dst)
SET e.rule = $rule, e.technique = $technique, e.fix_token = token,
    e.likelihood = lk, e.cost = -log(lk), e.because = because, e.stale = false
RETURN count(e) AS n
"""

# --- exploit_public_facing (T1190) -----------------------------------------
# Internet exposes the asset; it runs software with a network-vector vuln that a
# scanner reported and still reports (an OPEN Finding ON asset, OF vuln); no
# Control mitigates that vuln ON THIS ASSET (MITIGATES is scoped by its `asset`
# property). A fixed finding enables nothing: that is what makes drift real.
EXPLOIT_PUBLIC_FACING = (
    """
MATCH (src:Internet)-[:EXPOSES]->(dst:Asset)-[:RUNS]->(s:Software)-[:HAS_VULN]->(v:Vuln),
      (f:Finding)-[:ON]->(dst), (f)-[:OF]->(v)
WHERE v.av IN $network_vectors AND f.status = $open_status
  AND NOT (:Control)-[:MITIGATES {asset: dst.id}]->(v)
WITH DISTINCT src, dst, f.id AS token, v.likelihood AS lk, [f.id, v.id, s.id] AS because
"""
    + _EMIT
)

# --- exploit_remote_service (T1210) ----------------------------------------
# Same as above, but the attacker is already on src and reaches dst over a
# CAN_REACH edge whose port the vulnerable software actually listens on
# (an empty `ports` list means unknown, which matches any port).
EXPLOIT_REMOTE_SERVICE = (
    """
MATCH (src:Asset)-[r:CAN_REACH]->(dst:Asset)-[:RUNS]->(s:Software)-[:HAS_VULN]->(v:Vuln),
      (f:Finding)-[:ON]->(dst), (f)-[:OF]->(v)
WHERE v.av IN $network_vectors AND f.status = $open_status
  AND (size(s.ports) = 0 OR r.port IN s.ports)
  AND NOT (:Control)-[:MITIGATES {asset: dst.id}]->(v)
WITH DISTINCT src, dst, f.id AS token, v.likelihood AS lk, [f.id, v.id, s.id] AS because
"""
    + _EMIT
)

# --- local_privesc (T1068), folded onto the root-owned secret ---------------
# A LOCAL-vector vuln (CVSS >= threshold) on an asset that HOLDS a secret which
# needs root to read. The edge goes asset -> secret; fixing the privesc Finding
# removes it.
LOCAL_PRIVESC = (
    """
MATCH (src:Asset)-[:RUNS]->(s:Software)-[:HAS_VULN]->(v:Vuln),
      (f:Finding)-[:ON]->(src), (f)-[:OF]->(v),
      (src)-[:HOLDS]->(dst:Secret {requires_priv: true})
WHERE v.av = 'LOCAL' AND v.cvss >= $privesc_min_cvss AND f.status = $open_status
  AND NOT (:Control)-[:MITIGATES {asset: src.id}]->(v)
WITH DISTINCT src, dst, f.id AS token, v.likelihood * $creds_likelihood AS lk,
     [f.id, v.id, s.id, dst.id] AS because
"""
    + _EMIT
)

# --- creds_in_files (T1552.001) --------------------------------------------
# A compromised asset gives up the (non-root) secrets stored on it.
CREDS_IN_FILES = (
    """
MATCH (src:Asset)-[:HOLDS]->(dst:Secret {requires_priv: false})
WITH src, dst, 'step:creds:' + src.id + ':' + dst.id AS token, $likelihood AS lk,
     [dst.id] AS because
"""
    + _EMIT
)

# --- ssh_with_stolen_key (T1021.004) ---------------------------------------
SSH_WITH_STOLEN_KEY = (
    """
MATCH (src:Secret {kind: 'ssh_key'})-[:UNLOCKS]->(dst:Asset)
WITH src, dst, 'step:ssh:' + src.id + ':' + dst.id AS token, $likelihood AS lk,
     [src.id] AS because
"""
    + _EMIT
)

# --- db_with_password (T1078) ----------------------------------------------
DB_WITH_PASSWORD = (
    """
MATCH (src:Secret {kind: 'db_password'})-[:UNLOCKS]->(dst:DataStore)
WITH src, dst, 'step:db:' + src.id + ':' + dst.id AS token, $likelihood AS lk,
     [src.id] AS because
"""
    + _EMIT
)

# --- use_cloud_account (T1078.004), two shapes -----------------------------
# (a) a stolen cloud key logs in as the identity it unlocks;
USE_CLOUD_KEY = (
    """
MATCH (src:Secret {kind: 'cloud_key'})-[:UNLOCKS]->(dst:Identity)
WITH src, dst, 'step:usekey:' + src.id + ':' + dst.id AS token, $likelihood AS lk,
     [src.id] AS because
"""
    + _EMIT
)
# (b) an identity assumes another role it is allowed to assume.
ASSUME_ROLE = (
    """
MATCH (src:Identity)-[:CAN_ASSUME]->(dst:Identity)
WITH src, dst, 'step:assume:' + src.id + ':' + dst.id AS token, $likelihood AS lk,
     [dst.id] AS because
"""
    + _EMIT
)

# --- instance_metadata (T1552.005) -----------------------------------------
# A compromised CLOUD asset hands over its attached role via the metadata API.
INSTANCE_METADATA = (
    """
MATCH (src:Asset {cloud: true})-[:ASSUMES]->(dst:Identity)
WITH src, dst, 'step:imds:' + src.id + ':' + dst.id AS token, $likelihood AS lk,
     [dst.id] AS because
"""
    + _EMIT
)

# --- read_cloud_storage (T1530) --------------------------------------------
READ_CLOUD_STORAGE = (
    """
MATCH (src:Identity)-[p:CAN]->(dst:DataStore)
WHERE p.action IN $read_actions
WITH src, dst, 'step:read:' + src.id + ':' + dst.id AS token, $likelihood AS lk,
     [src.id, dst.id] AS because
"""
    + _EMIT
)


@dataclass(frozen=True)
class RuleQuery:
    name: str  # a key of attack_rules.RULES
    variant: str  # distinguishes the two use_cloud_account shapes
    cypher: str


RULE_QUERIES: list[RuleQuery] = [
    RuleQuery("exploit_public_facing", "", EXPLOIT_PUBLIC_FACING),
    RuleQuery("exploit_remote_service", "", EXPLOIT_REMOTE_SERVICE),
    RuleQuery("local_privesc", "folded", LOCAL_PRIVESC),
    RuleQuery("creds_in_files", "", CREDS_IN_FILES),
    RuleQuery("ssh_with_stolen_key", "", SSH_WITH_STOLEN_KEY),
    RuleQuery("db_with_password", "", DB_WITH_PASSWORD),
    RuleQuery("use_cloud_account", "cloud_key", USE_CLOUD_KEY),
    RuleQuery("use_cloud_account", "assume_role", ASSUME_ROLE),
    RuleQuery("instance_metadata", "", INSTANCE_METADATA),
    RuleQuery("read_cloud_storage", "", READ_CLOUD_STORAGE),
]

# Every rule in the spec must have a derivation query (and nothing else may).
assert {q.name for q in RULE_QUERIES} == set(RULES), "RULE_QUERIES out of sync with RULES"


def _params(rq: RuleQuery) -> dict:
    rule = RULES[rq.name]
    return {
        "rule": rule.name,
        "technique": rule.technique,
        "likelihood": rule.likelihood,
        "network_vectors": sorted(NETWORK_VECTORS),
        "open_status": OPEN_STATUS,
        "privesc_min_cvss": PRIVESC_MIN_CVSS,
        "creds_likelihood": RULES["creds_in_files"].likelihood,
        "read_actions": list(READ_ACTIONS),
    }


# ---------------------------------------------------------------------------
# Mark-and-sweep around the rule queries, so derive is idempotent AND drops
# steps whose precondition disappeared (a finding fixed, a secret removed).
# ---------------------------------------------------------------------------
MARK_STALE = "MATCH ()-[e:ATTACK_STEP]->() SET e.stale = true"
SWEEP_STALE = "MATCH ()-[e:ATTACK_STEP]->() WHERE e.stale = true DELETE e"
CLEAR_MARK = "MATCH ()-[e:ATTACK_STEP]->() REMOVE e.stale"

# ---------------------------------------------------------------------------
# FLOW layer for algo.maxFlow (node-split fix tokens).
#
# For every fix token t:            (FixIn t) -[:FLOW {cap: 1}]-> (FixOut t)
# For every step u -[t]-> v:        u -[:FLOW {cap: BIG}]-> (FixIn t)
#                                   (FixOut t) -[:FLOW {cap: BIG}]-> v
#
# Only the unit edges can be cut, so a minimum cut is a set of fix tokens, and
# a token shared by several steps is counted once. Bonus: the result has no
# parallel edges, which algo.maxFlow requires (it rejects multi-edges).
# ---------------------------------------------------------------------------
DROP_FLOW = "MATCH (n) WHERE n:FixIn OR n:FixOut DETACH DELETE n"
# The layer is a pure function of ATTACK_STEP, so we drop and rebuild it rather
# than MERGE: three CREATE passes over DISTINCT rows are ~100x faster than a
# per-row edge MERGE (which re-scans the node's existing edges every time).
BUILD_FLOW = [
    # 1. one unit-capacity gate per fix token
    """
    MATCH ()-[e:ATTACK_STEP]->()
    WITH DISTINCT e.fix_token AS t
    CREATE (:FixIn {token: t, id: 'fix_in:' + t})-[:FLOW {cap: 1}]->
           (:FixOut {token: t, id: 'fix_out:' + t})
    RETURN count(t) AS tokens
    """,
    # 2. step source -> its token's gate entrance
    """
    MATCH (u)-[e:ATTACK_STEP]->()
    WITH DISTINCT u, e.fix_token AS t
    MATCH (fi:FixIn {token: t})
    CREATE (u)-[:FLOW {cap: $big, effort: $big}]->(fi)
    """,
    # 3. gate exit -> step target
    """
    MATCH ()-[e:ATTACK_STEP]->(v)
    WITH DISTINCT e.fix_token AS t, v
    MATCH (fo:FixOut {token: t})
    CREATE (fo)-[:FLOW {cap: $big, effort: $big}]->(v)
    """,
]

# ---------------------------------------------------------------------------
# Effort on each fix gate (reachable_core.effort), the capacity min_cut uses in
# mode="cheapest". The fix lands on one node, picked by rule:
#   exploit steps     -> the asset the Finding is ON (the step target; for the
#                        folded local_privesc, the step source);
#   FIX_AT_SOURCE     -> the step source (host holding the secret, ...);
#   other step tokens -> the step target (host trusting the key, data store...).
# Base effort comes from that node's kind (findings) or the rule (step tokens),
# plus the owning team's change_effort, clamped to [MIN, MAX].
# FalkorDB gotcha: every non-aggregated variable used after an aggregation must
# be a grouping key of that WITH; otherwise it silently comes through as null.
# The gate is reached by traversal, u -[:FLOW]-> FixIn {token}, not by an id
# lookup per row (which would not use the index, see the S2 gotchas).
# ---------------------------------------------------------------------------
SET_GATE_EFFORT = """
MATCH (u)-[e:ATTACK_STEP]->(v)
WITH DISTINCT u, v, e.rule AS rule, e.fix_token AS tok
WITH u, rule, tok, tok STARTS WITH 'step:' AS is_step,
     CASE WHEN rule = 'local_privesc' OR (tok STARTS WITH 'step:' AND rule IN $fix_at_source)
          THEN u ELSE v END AS n
OPTIONAL MATCH (t:Team)-[:OWNS]->(n)
WITH u, tok, rule, is_step, n, max(coalesce(t.change_effort, 0)) AS bump
WITH u, tok, bump + CASE WHEN is_step THEN coalesce($step_effort[rule], $default_effort)
                         ELSE coalesce($kind_effort[n.kind], $default_effort) END AS x
MATCH (u)-[:FLOW]->(fi:FixIn)-[gate:FLOW]->(:FixOut)
WHERE fi.token = tok
SET gate.effort = CASE WHEN x < $min_effort THEN $min_effort
                       WHEN x > $max_effort THEN $max_effort ELSE x END
RETURN count(DISTINCT gate)
"""


def effort_params() -> dict:
    return {
        "fix_at_source": sorted(FIX_AT_SOURCE),
        "step_effort": STEP_EFFORT,
        "kind_effort": KIND_EFFORT,
        "default_effort": DEFAULT_KIND_EFFORT,
        "min_effort": MIN_EFFORT,
        "max_effort": MAX_EFFORT,
    }


# ---------------------------------------------------------------------------
# :CrownPath label = nodes on some Internet -> crown-jewel ATTACK_STEP path.
# The pattern is anchored at both ends; the planner expands from the crown
# jewel backwards (few predecessors) rather than from the Internet (huge
# fan-out). The *1..HOP_CAP bound keeps the expansion finite.
# ---------------------------------------------------------------------------
CLEAR_CROWN_PATH = "MATCH (n:CrownPath) REMOVE n:CrownPath"
MARK_CROWN_PATH = f"""
MATCH p = (:Internet)-[:ATTACK_STEP*1..{HOP_CAP}]->(:DataStore {{crown_jewel: true}})
UNWIND nodes(p) AS n
WITH DISTINCT n
SET n:CrownPath
RETURN count(n) AS n
"""


def derive(graph) -> dict:
    """(Re)derive ATTACK_STEP, FLOW and :CrownPath on one org graph. Idempotent."""
    t0 = time.perf_counter()
    create_range_index(graph, "FixIn", "token")
    create_range_index(graph, "FixOut", "token")
    _create_edge_index(graph)

    graph.query(MARK_STALE)
    per_rule: dict[str, dict] = {}
    for rq in RULE_QUERIES:
        t = time.perf_counter()
        res = graph.query(rq.cypher, _params(rq))
        label = f"{rq.name}:{rq.variant}" if rq.variant else rq.name
        per_rule[label] = {
            "merged": int(res.result_set[0][0]) if res.result_set else 0,
            "impl": "cypher",
            "ms": round((time.perf_counter() - t) * 1000, 1),
        }
    swept = graph.query(SWEEP_STALE).relationships_deleted
    graph.query(CLEAR_MARK)

    graph.query(DROP_FLOW)
    tokens = graph.query(BUILD_FLOW[0]).result_set[0][0]
    for q in BUILD_FLOW[1:]:
        graph.query(q, {"big": BIG_CAPACITY})
    t = time.perf_counter()
    gates = graph.query(SET_GATE_EFFORT, effort_params()).result_set[0][0]
    effort_ms = round((time.perf_counter() - t) * 1000, 1)

    graph.query(CLEAR_CROWN_PATH)
    crown_nodes = graph.query(MARK_CROWN_PATH).result_set[0][0]

    by_rule = graph.query(
        "MATCH ()-[e:ATTACK_STEP]->() RETURN e.rule, count(e) ORDER BY e.rule"
    ).result_set
    return {
        "attack_steps": sum(int(n) for _, n in by_rule),
        "by_rule": {r: int(n) for r, n in by_rule},
        "per_query": per_rule,
        "swept_stale": swept,
        "fix_tokens": int(tokens),
        "effort_gates": int(gates),
        "effort_ms": effort_ms,
        "crown_path_nodes": int(crown_nodes),
        "seconds": round(time.perf_counter() - t0, 2),
    }


def _create_edge_index(graph) -> None:
    """Range indexes on ATTACK_STEP.key (why_step) and .fix_token (min_cut,
    simulate_fix), so looking a step up by either is an index seek."""
    for prop in ("key", "fix_token"):
        try:
            graph.query(f"CREATE INDEX FOR ()-[e:ATTACK_STEP]-() ON (e.{prop})")
        except Exception as exc:  # noqa: BLE001 - only swallow "already indexed"
            msg = str(exc).lower()
            if "already indexed" not in msg and "already exists" not in msg:
                raise


def edge_signature(graph) -> list[tuple]:
    """Every ATTACK_STEP as a comparable tuple, for the idempotency check."""
    rows = graph.ro_query(
        """
        MATCH (a)-[e:ATTACK_STEP]->(b)
        RETURN a.id, b.id, e.key, e.rule, e.technique, e.fix_token,
               e.likelihood, e.cost, e.because
        """
    ).result_set
    return sorted(tuple(tuple(x) if isinstance(x, list) else x for x in r) for r in rows)
