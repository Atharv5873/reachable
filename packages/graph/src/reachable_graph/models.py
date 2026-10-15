"""Typed inputs and the standard ToolResult every tool returns.

These models are the contract between the graph tools, the MCP server and (in
S4) the agent. The input models double as the MCP tool schemas, so their field
descriptions and bounds are what the LLM sees when choosing arguments.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, Field

from reachable_core.attack_rules import HOP_CAP

# --- Caps (enforced by validation; a request outside them never reaches the DB)
MAX_K = 25  # paths per attack_paths / simulate_fix call
MAX_ROWS = 200  # rows any tool returns
MAX_BFS_DEPTH = HOP_CAP
MAX_BFS_NODES = 500
MAX_FIX_TOKENS = 50
MAX_TARGETS = 20
QUERY_TIMEOUT_MS = 10_000  # per query, passed to GRAPH.RO_QUERY

_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_:.\-]{0,127}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_:.\-]{0,255}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_PARAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _match(rx: re.Pattern, what: str):
    def check(v: str) -> str:
        if not rx.match(v):
            raise ValueError(f"invalid {what}: {v!r}")
        return v

    return check


NodeId = Annotated[str, AfterValidator(_match(_ID_RE, "node id"))]
FixToken = Annotated[str, AfterValidator(_match(_TOKEN_RE, "fix token"))]
CveId = Annotated[str, AfterValidator(_match(_CVE_RE, "CVE id"))]
OrgName = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")]


# --- Inputs -----------------------------------------------------------------
class OrgInput(BaseModel):
    org: OrgName = Field(description="Org graph name, e.g. 'org_a'.")


class ExposureInput(OrgInput):
    limit: int = Field(50, ge=1, le=MAX_ROWS, description="Max exposed assets to return.")


class AttackPathsInput(OrgInput):
    target_id: NodeId | None = Field(
        None, description="A DataStore id to target. Omit to target every crown jewel."
    )
    k: int = Field(5, ge=1, le=MAX_K, description="How many most-likely paths to return.")
    source_id: NodeId | None = Field(
        None,
        description="Start node id (an Asset/Identity/Secret the attacker holds). "
        "Omit to start from the Internet.",
    )
    max_hops: int = Field(HOP_CAP, ge=1, le=HOP_CAP, description="Longest path, in steps.")


class BlastRadiusInput(OrgInput):
    asset_id: NodeId = Field(description="Id of the compromised Asset (or Identity/Secret).")
    max_depth: int = Field(HOP_CAP, ge=1, le=MAX_BFS_DEPTH, description="BFS depth limit.")


class MinCutInput(OrgInput):
    target_ids: list[NodeId] | None = Field(
        None,
        max_length=MAX_TARGETS,
        description="DataStore ids to protect. Omit to protect every crown jewel.",
    )
    prefer: Literal["entry", "crown"] = Field(
        "entry",
        description="Several minimum fix sets can exist. 'entry' returns the one closest to "
        "the Internet (patch the way in); 'crown' the one closest to the targets (lock the vault).",
    )


class ChokePointsInput(OrgInput):
    top: int = Field(10, ge=1, le=50, description="How many choke points to return.")


class WhyStepInput(OrgInput):
    edge_key: str = Field(
        min_length=3, max_length=600, description="The `key` of an ATTACK_STEP edge."
    )


class VulnIntelInput(BaseModel):
    cve: CveId = Field(description="CVE id, e.g. 'CVE-2021-44228'.")
    org: OrgName | None = Field(
        None, description="Optionally, an org graph to report where this CVE appears."
    )


class SimulateFixInput(OrgInput):
    fix_tokens: list[FixToken] = Field(
        min_length=1,
        max_length=MAX_FIX_TOKENS,
        description="Fix tokens to apply (Finding ids or step:* tokens from other tools).",
    )
    k: int = Field(5, ge=1, le=MAX_K, description="Remaining paths to show after the fix.")


class RunCypherInput(OrgInput):
    query: str = Field(min_length=1, max_length=4000, description="A READ-ONLY Cypher query.")
    params: dict[str, Any] = Field(default_factory=dict, description="Query parameters.")
    limit: int = Field(50, ge=1, le=MAX_ROWS, description="Row cap (a LIMIT is forced).")

    def model_post_init(self, _ctx: Any) -> None:
        bad = [k for k in self.params if not _PARAM_RE.match(k)]
        if bad:
            raise ValueError(f"invalid parameter names: {bad}")


# --- Output -----------------------------------------------------------------
class EdgeRef(BaseModel):
    src: str
    rel: str
    dst: str
    key: str | None = None  # set for ATTACK_STEP edges (their MERGE key)


class Evidence(BaseModel):
    node_ids: list[str] = Field(default_factory=list)
    edges: list[EdgeRef] = Field(default_factory=list)
    paths: list[list[str]] = Field(default_factory=list)


class QueryLog(BaseModel):
    graph: str
    cypher: str
    params: dict[str, Any]
    ms: float


class ToolResult(BaseModel):
    summary: str
    data: dict[str, Any]
    evidence: Evidence = Field(default_factory=Evidence)
    queries: list[QueryLog] = Field(default_factory=list)
    truncated: bool = False
