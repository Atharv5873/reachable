"""Typed inputs and the standard ToolResult every tool returns.

These models are the contract between the graph tools, the MCP server and (in
S4) the agent. The input models double as the MCP tool schemas, so their field
descriptions and bounds are what the LLM sees when choosing arguments.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

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
_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,62}$")
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


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
Hostname = Annotated[str, AfterValidator(_match(_HOST_RE, "hostname"))]
Port = Annotated[int, Field(ge=1, le=65535)]
TechniqueId = Annotated[str, AfterValidator(_match(_TECH_RE, "ATT&CK technique id"))]
# Epoch seconds the answer is evaluated at. Agents always pass the scan's time;
# omitted, a tool falls back to its own notion of "now" (documented per tool).
AsOf = Annotated[int | None, Field(None, ge=0)]


# --- Inputs -----------------------------------------------------------------
class OrgInput(BaseModel):
    org: OrgName = Field(description="Org graph name, e.g. 'org_a'.")


class ScanFindingsInput(OrgInput):
    limit: int = Field(
        30, ge=1, le=MAX_ROWS, description="Max findings to list (attack-step findings first)."
    )
    view: Literal["ranked", "triage"] = Field(
        "ranked",
        description="ranked: the top findings by what they enable. triage: aggregates (by "
        "technique, severity, exposure) plus only the Internet-facing candidates, compact.",
    )


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
    mode: Literal["fewest", "cheapest"] = Field(
        "fewest",
        description="'fewest': the smallest NUMBER of fixes (every fix counts 1). 'cheapest': "
        "the lowest total EFFORT (each fix weighted 1-5 by what it touches and who owns it); "
        "may be more fixes, each easier.",
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


# --- Company layer (Track 03) ------------------------------------------------
class OwnersInput(OrgInput):
    asset_id: NodeId = Field(description="An Asset or DataStore id.")
    as_of: AsOf = Field(
        None,
        description="Epoch seconds: who was on call at this time (default: the slot marked "
        "current).",
    )


class _Exposure(BaseModel):
    """An exposure, named by asset id OR hostname, optionally narrowed to a port."""

    model_config = ConfigDict(extra="forbid")
    asset_id: NodeId | None = Field(None, description="Asset id (or give hostname).")
    hostname: Hostname | None = Field(None, description="Asset hostname (or give asset_id).")
    port: Port | None = Field(None, description="Only decisions about this port.")

    @model_validator(mode="after")
    def _one_of(self):
        if (self.asset_id is None) == (self.hostname is None):
            raise ValueError("give exactly one of asset_id or hostname")
        return self


class DecisionTrailInput(OrgInput, _Exposure):
    pass


# company_query: a FIXED set of intents, each with its own parameter model.
# Never free text to Cypher: the agent maps a question onto one of these.
class WhoOwnsParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: NodeId


class WhoIsOnCallParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    team_id: NodeId | None = None
    asset_id: NodeId | None = None

    @model_validator(mode="after")
    def _one_of(self):
        if (self.team_id is None) == (self.asset_id is None):
            raise ValueError("give exactly one of team_id or asset_id")
        return self


class WhyExposedParams(_Exposure):
    pass


class WhoApprovedParams(_Exposure):
    pass


class FixHistoryParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: NodeId


COMPANY_INTENTS: dict[str, type[BaseModel]] = {
    "who_owns": WhoOwnsParams,
    "who_is_on_call": WhoIsOnCallParams,
    "why_exposed": WhyExposedParams,
    "who_approved": WhoApprovedParams,
    "fix_history": FixHistoryParams,
}
CompanyIntent = Literal["who_owns", "who_is_on_call", "why_exposed", "who_approved", "fix_history"]


class CompanyQueryInput(OrgInput):
    question_kind: CompanyIntent = Field(
        description="who_owns {asset_id} | who_is_on_call {team_id|asset_id} | "
        "why_exposed {asset_id|hostname, port?} | who_approved {asset_id|hostname, port?} | "
        "fix_history {asset_id}"
    )
    params: dict[str, Any] = Field(
        default_factory=dict, description="Parameters for the chosen question_kind."
    )
    as_of: AsOf = Field(None, description="Epoch seconds for on-call questions (see owners).")

    def typed_params(self) -> BaseModel:
        return COMPANY_INTENTS[self.question_kind].model_validate(self.params)


# --- Memory layer (Track 02) -------------------------------------------------
class TriageMemoryInput(OrgInput):
    finding_ids: list[NodeId] = Field(
        min_length=1, max_length=MAX_ROWS, description="Finding ids to recall memory for."
    )
    as_of: int | None = Field(
        None,
        ge=0,
        description="Epoch seconds to judge risk-acceptance expiry at (default: now). "
        "Use it to ask what was in force at an earlier time.",
    )


class PlaybooksInput(OrgInput):
    techniques: list[TechniqueId] = Field(
        min_length=1, max_length=20, description="ATT&CK technique ids, e.g. ['T1190', 'T1210']."
    )
    as_of: AsOf = Field(
        None,
        description="Epoch seconds: the version that was current then (default: the newest).",
    )


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
