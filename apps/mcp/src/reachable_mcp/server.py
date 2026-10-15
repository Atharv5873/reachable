"""Reachable MCP server: the typed FalkorDB graph tools, over stdio or streamable HTTP.

    reachable-mcp                       # stdio (Claude Desktop / Claude Code / any MCP host)
    reachable-mcp --http --port 8002    # streamable HTTP at /mcp, API key required

Every tool is a thin wrapper over reachable_graph.tools.GraphTools: the
argument types/bounds come straight from the Pydantic input models (one source
of truth for the caps), and every result is the standard ToolResult
{summary, data, evidence, queries, truncated}.

The descriptions below are written for the LLM that picks tools in S4: each
says what the tool answers, when to use it, and when NOT to.
"""

from __future__ import annotations

import argparse
import hmac
import logging
import os
from functools import cache
from typing import Annotated, Any, Literal

import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError as MCPToolError
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field, ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse

from reachable_graph import models as M
from reachable_graph.models import ToolResult
from reachable_graph.tools import GraphTools, ToolError

log = logging.getLogger("reachable.mcp")

INSTRUCTIONS = """\
Reachable answers "what can an attacker actually reach?" over FalkorDB graphs of
synthetic orgs (org_a, org_b, org_c; the week-later rescan of each is loaded as
org_a_v2, ...). Each org graph has a materialised
ATTACK_STEP layer: one edge per attacker step (exploit, stolen credential,
role assumption, ...), each with a likelihood and a fix_token (the Finding id or
step:* token that removes it if fixed).

Typical flow: scan_findings (what the scan found, ranked by what each finding
enables) -> exposure_surface -> attack_paths -> why_step on surprising hops ->
min_cut for the smallest fix set -> simulate_fix to PROVE it before proposing.
vuln_intel explains a CVE. run_cypher_readonly is a last resort.

The same graphs hold the company layer (teams, people, on-call, ADRs, tickets):
owners routes a fix to a team and tonight's on-call person; decision_trail and
company_query answer "why is this exposed and who approved it?" with the ADR as
the source. triage_memory recalls prior verdicts, live risk acceptances and
recurring patterns for findings before you triage them again; playbooks gives
the versioned procedure in force per ATT&CK technique. Time-dependent tools
(triage_memory, playbooks, owners, company_query) take as_of in epoch seconds:
pass the scan's time, not today's, when reasoning about a scan.
Every result carries `evidence` (ids that exist in the graph): cite them.
"""


def arg(model: type, name: str, tp: Any) -> Any:
    """Annotated[tp, description + bounds] taken from a Pydantic input model field,
    so the MCP schema the LLM sees carries exactly the caps the tools enforce.
    (Defaults are written in each signature, never copied from the model.)"""
    fi = model.model_fields[name]
    return Annotated[(tp, Field(description=fi.description), *fi.metadata)]


@cache
def _tools() -> GraphTools:
    return GraphTools()


def _call(fn, *args, **kwargs) -> ToolResult:
    """Run a tool; turn anticipated failures into MCP tool errors the model can read."""
    try:
        return fn(*args, **kwargs)
    except (ToolError, ValidationError, NotImplementedError) as exc:
        raise MCPToolError(str(exc)) from exc


Org = arg(M.OrgInput, "org", str)

server = MCPServer(name="reachable", instructions=INSTRUCTIONS, version="0.4.0")


@server.tool(
    name="exposure_surface",
    description=(
        "List the org's internet-exposed assets and, for each, the vulns an attacker on the "
        "Internet can actually exploit (finding id, CVE, CVSS, EPSS, KEV, step likelihood) plus "
        "vulns that are exposed but blocked by a Control. USE FIRST to see where an attack "
        "starts. Do NOT use it to judge impact: exposure says nothing about what lies behind "
        "the asset (use attack_paths / blast_radius)."
    ),
)
def exposure_surface(org: Org, limit: arg(M.ExposureInput, "limit", int) = 50) -> ToolResult:
    return _call(_tools().exposure_surface, org, limit=limit)


@server.tool(
    name="attack_paths",
    description=(
        "Top-k MOST LIKELY attack paths from the Internet (or from source_id) to the org's crown "
        "jewels (or to target_id), via weighted shortest paths over ATTACK_STEP with "
        "cost = -ln(likelihood). Each path lists hops (rule, ATT&CK technique, likelihood, "
        "fix_token, edge key) and its overall likelihood. USE to answer 'can an attacker reach X, "
        "and how?' and to rank findings by real risk. Do NOT use for 'what is the smallest set of "
        "fixes' (min_cut) or 'what does one compromised host expose' (blast_radius). "
        "truncated=true means more paths exist beyond k."
    ),
)
def attack_paths(
    org: Org,
    target_id: arg(M.AttackPathsInput, "target_id", str | None) = None,
    k: arg(M.AttackPathsInput, "k", int) = 5,
    source_id: arg(M.AttackPathsInput, "source_id", str | None) = None,
    max_hops: arg(M.AttackPathsInput, "max_hops", int) = M.HOP_CAP,
) -> ToolResult:
    return _call(
        _tools().attack_paths,
        org,
        target_id=target_id,
        k=k,
        source_id=source_id,
        max_hops=max_hops,
    )


@server.tool(
    name="blast_radius",
    description=(
        "Everything an attacker can reach from ONE compromised node (asset, identity or secret): "
        "BFS over ATTACK_STEP up to max_depth, with counts by type and any crown jewels reached. "
        "USE for incident response ('host X is popped, what now?') or to size the impact of one "
        "finding. Do NOT use to find paths FROM the Internet (attack_paths) or to rank fixes."
    ),
)
def blast_radius(
    org: Org,
    asset_id: arg(M.BlastRadiusInput, "asset_id", str),
    max_depth: arg(M.BlastRadiusInput, "max_depth", int) = M.HOP_CAP,
) -> ToolResult:
    return _call(_tools().blast_radius, org, asset_id, max_depth=max_depth)


@server.tool(
    name="min_cut",
    description=(
        "The MINIMUM set of fixes (fix_tokens: Finding ids and step:* tokens) that disconnects "
        "the Internet from every crown jewel (or from target_ids), computed with max-flow/min-cut "
        "(algo.maxFlow on a node-split graph where each fix has capacity 1), plus a "
        "human-readable action and an effort estimate (1-5) per fix. mode='fewest' (default) "
        "minimises the NUMBER of fixes; mode='cheapest' minimises total EFFORT (by asset kind "
        "and owning team), which can mean more but easier fixes. prefer='entry' picks fixes "
        "nearest the Internet, prefer='crown' nearest the data. USE when asked 'what should we "
        "fix first?' or 'smallest / cheapest remediation plan'. ALWAYS confirm with simulate_fix "
        "before recommending. Do NOT use to list every risky finding (attack_paths)."
    ),
)
def min_cut(
    org: Org,
    target_ids: arg(M.MinCutInput, "target_ids", list[str] | None) = None,
    prefer: arg(M.MinCutInput, "prefer", Literal["entry", "crown"]) = "entry",
    mode: arg(M.MinCutInput, "mode", Literal["fewest", "cheapest"]) = "fewest",
) -> ToolResult:
    return _call(_tools().min_cut, org, target_ids=target_ids, prefer=prefer, mode=mode)


@server.tool(
    name="choke_points",
    description=(
        "Nodes that many crown-jewel attack paths funnel through: betweenness centrality "
        "(algo.betweenness) over the ATTACK_STEP subgraph lying on Internet->crown-jewel paths, "
        "with the share of crown paths through each and the steps (fix tokens) leading into it. "
        "USE to explain WHY a fix matters structurally or to suggest defensive monitoring points. "
        "Do NOT treat as the fix list: the provably minimal fix set comes from min_cut."
    ),
)
def choke_points(org: Org, top: arg(M.ChokePointsInput, "top", int) = 10) -> ToolResult:
    return _call(_tools().choke_points, org, top=top)


@server.tool(
    name="why_step",
    description=(
        "Explain ONE attack step (by its ATTACK_STEP edge key from attack_paths/blast_radius/"
        "min_cut): the rule and its plain-English precondition, the ATT&CK technique, the "
        "likelihood, the fix that removes it, and the evidence nodes (finding, vuln, software, "
        "secret, role) with the real structural edges that satisfied the rule. USE whenever you "
        "state that a step is possible, so the claim is grounded. Do NOT guess edge keys."
    ),
)
def why_step(org: Org, edge_key: arg(M.WhyStepInput, "edge_key", str)) -> ToolResult:
    return _call(_tools().why_step, org, edge_key)


@server.tool(
    name="vuln_intel",
    description=(
        "Public threat intel for a CVE from the threatintel graph: CVSS + vector, EPSS (+"
        "percentile), CISA KEV and ransomware use, CWEs, affected products, the ATT&CK "
        "techniques our attack rules map it to, and the step likelihood we assign it. Pass org to "
        "also see how many findings in that org carry it and how many enable an attack step. "
        "USE to explain why a finding is (or is not) urgent. Do NOT use it to decide "
        "reachability: a KEV 9.8 can still be unreachable (check attack_paths)."
    ),
)
def vuln_intel(
    cve: arg(M.VulnIntelInput, "cve", str),
    org: arg(M.VulnIntelInput, "org", str | None) = None,
) -> ToolResult:
    return _call(_tools().vuln_intel, cve, org=org)


@server.tool(
    name="simulate_fix",
    description=(
        "PROVE a fix before proposing it: in a throwaway copy of the org graph, remove every "
        "attack step enabled by the given fix_tokens, re-run attack_paths, and report which crown "
        "jewels became unreachable and which paths remain. Never modifies the real graph. USE "
        "after min_cut, or to test any remediation idea ('what if we patch these 3 findings?'). "
        "Do NOT use for discovery; it costs a graph copy (~0.3 s)."
    ),
)
def simulate_fix(
    org: Org,
    fix_tokens: arg(M.SimulateFixInput, "fix_tokens", list[str]),
    k: arg(M.SimulateFixInput, "k", int) = 5,
) -> ToolResult:
    return _call(_tools().simulate_fix, org, fix_tokens, k=k)


@server.tool(
    name="run_cypher_readonly",
    description=(
        "LAST RESORT escape hatch: run a read-only openCypher query (FalkorDB dialect) on an org "
        "graph. Writes are rejected by the server (GRAPH.RO_QUERY), a LIMIT is forced, a timeout "
        "applies, and the call is logged. Labels: Internet, Asset, Software, Vuln, Finding, "
        "Identity, Secret, DataStore, Control, Zone; company: Team, Person, OnCall, ADR, Ticket; "
        "memory: Run, AgentStep, Triage, Verdict, RiskAcceptance, Pattern, Playbook; attack "
        "layer: ATTACK_STEP {key, rule, technique, likelihood, cost, fix_token, because}. "
        "USE only when no typed tool answers "
        "the question. Do NOT use for paths, cuts or blast radius: the typed tools are capped, "
        "faster and return evidence."
    ),
)
def run_cypher_readonly(
    org: Org,
    query: arg(M.RunCypherInput, "query", str),
    params: arg(M.RunCypherInput, "params", dict[str, Any] | None) = None,
    limit: arg(M.RunCypherInput, "limit", int) = 50,
) -> ToolResult:
    return _call(_tools().run_cypher_readonly, org, query, params or {}, limit=limit)


# ------------------------------------------------------------ company layer
@server.tool(
    name="owners",
    description=(
        "Who owns an asset or data store: the owning team(s), every member with their role, and "
        "the person on call for each team (right now, or at as_of). USE to route a fix or an "
        "incident to a "
        "human ('who do I page about this host?'). Do NOT use to explain why something is "
        "configured the way it is (decision_trail) or what an attacker can do (attack_paths)."
    ),
)
def owners(
    org: Org,
    asset_id: arg(M.OwnersInput, "asset_id", str),
    as_of: arg(M.OwnersInput, "as_of", int | None) = None,
) -> ToolResult:
    return _call(_tools().owners, org, asset_id, as_of=as_of)


@server.tool(
    name="decision_trail",
    description=(
        "The decision trail behind an asset's configuration: every ADR (architecture decision "
        "record) that changed it, optionally only those about one port, each with title, "
        "decision text, date and the approver (name, role, team), next to the asset's live "
        "Internet exposure and its exploitable Internet attack steps. Name the asset by asset_id "
        "OR hostname. USE for 'why is port X open on Y?' and 'who signed off on this?'; cite the "
        "ADR id as the source. An empty trail means an UNDOCUMENTED change, worth flagging. Do "
        "NOT use for ownership or on-call (owners)."
    ),
)
def decision_trail(
    org: Org,
    asset_id: arg(M.DecisionTrailInput, "asset_id", str | None) = None,
    hostname: arg(M.DecisionTrailInput, "hostname", str | None) = None,
    port: arg(M.DecisionTrailInput, "port", int | None) = None,
) -> ToolResult:
    return _call(_tools().decision_trail, org, asset_id=asset_id, hostname=hostname, port=port)


@server.tool(
    name="company_query",
    description=(
        "Company-brain questions as a FIXED set of parameterised intents (never free text): "
        "who_owns {asset_id}; who_is_on_call {team_id | asset_id}; why_exposed {asset_id | "
        "hostname, port?}; who_approved {asset_id | hostname, port?}; fix_history {asset_id} "
        "(tickets that fixed or are fixing findings on the asset). Returns a one-line `answer` "
        "plus evidence (ADR / ticket / person ids). USE when a person asks a who/why question "
        "about the org; map their words onto one intent. Do NOT pass Cypher or prose in params: "
        "unknown keys are rejected."
    ),
)
def company_query(
    org: Org,
    question_kind: arg(M.CompanyQueryInput, "question_kind", M.CompanyIntent),
    params: arg(M.CompanyQueryInput, "params", dict[str, Any] | None) = None,
    as_of: arg(M.CompanyQueryInput, "as_of", int | None) = None,
) -> ToolResult:
    return _call(_tools().company_query, org, question_kind, params or {}, as_of=as_of)


# ------------------------------------------------------------- memory layer
@server.tool(
    name="triage_memory",
    description=(
        "Recall what earlier triage already decided about findings: LIVE risk acceptances "
        "(signed off, not yet expired: these suppress the finding), EXPIRED ones (listed, but "
        "they no longer suppress anything), past verdicts (decision + reason), and patterns "
        "that reach the finding (same asset, same software image/CPE, or same CVE elsewhere). "
        "as_of evaluates expiry at an earlier time. USE before re-triaging findings so you do "
        "not repeat or contradict a past decision. Do NOT treat an expired acceptance as "
        "permission, and do NOT use this to judge reachability (attack_paths)."
    ),
)
def triage_memory(
    org: Org,
    finding_ids: arg(M.TriageMemoryInput, "finding_ids", list[str]),
    as_of: arg(M.TriageMemoryInput, "as_of", int | None) = None,
) -> ToolResult:
    return _call(_tools().triage_memory, org, finding_ids, as_of=as_of)


# -------------------------------------------------------------- agent layer
@server.tool(
    name="scan_findings",
    description=(
        "Start of triage: which scan this graph holds and WHEN it ran (use its ts as your "
        "clock), the crown jewels, counts, and the open findings ranked by what they enable in "
        "the attack layer: on a crown-jewel path first, then reachable from the Internet, then "
        "KEV / step likelihood / CVSS. Also lists the most severe findings that enable NO attack "
        "step (high score, no way in) and the findings that already carry a decision (risk "
        "acceptance or verdict: check them with triage_memory). USE FIRST when triaging a "
        "scan. Do NOT use it to get the "
        "paths themselves (attack_paths) or what memory says about a finding (triage_memory)."
    ),
)
def scan_findings(
    org: Org,
    limit: arg(M.ScanFindingsInput, "limit", int) = 30,
    view: arg(M.ScanFindingsInput, "view", Literal["ranked", "triage"]) = "ranked",
) -> ToolResult:
    return _call(_tools().scan_findings, org, limit=limit, view=view)


@server.tool(
    name="playbooks",
    description=(
        "Procedural memory: for each ATT&CK technique, the playbook version in force at as_of "
        "(newest published at or before it) with its steps, plus the version history (older "
        "versions are kept, SUPERSEDED). USE to pick how to handle the techniques your findings "
        "enable. Do NOT use it to decide whether a finding is reachable (attack_paths)."
    ),
)
def playbooks(
    org: Org,
    techniques: arg(M.PlaybooksInput, "techniques", list[str]),
    as_of: arg(M.PlaybooksInput, "as_of", int | None) = None,
) -> ToolResult:
    return _call(_tools().playbooks, org, techniques, as_of=as_of)


# --------------------------------------------------------------------- HTTP
@server.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse(
        {"status": "ok", "tools": sorted(t.name for t in await server.list_tools())}
    )


class ApiKeyMiddleware:
    """Require `Authorization: Bearer <key>` or `X-API-Key: <key>` on every HTTP
    request except /health. Constant-time comparison; fails closed."""

    def __init__(self, app, api_key: str) -> None:
        self.app, self.key = app, api_key.encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") == "/health":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        given = headers.get("x-api-key") or headers.get("authorization", "").removeprefix("Bearer ")
        if not hmac.compare_digest(given.encode(), self.key):
            resp = JSONResponse({"error": "missing or invalid API key"}, status_code=401)
            return await resp(scope, receive, send)
        return await self.app(scope, receive, send)


def http_app(api_key: str, allowed_hosts: list[str]):
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=[f"http://{h}" for h in allowed_hosts],
    )
    app = server.streamable_http_app(transport_security=security, stateless_http=True)
    return ApiKeyMiddleware(app, api_key)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="reachable-mcp")
    p.add_argument("--http", action="store_true", help="serve streamable HTTP instead of stdio")
    p.add_argument("--host", default=os.environ.get("MCP_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("MCP_PORT", "8002")))
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO)

    if not args.http:
        server.run("stdio")
        return
    key = os.environ.get("MCP_API_KEY", "")
    if len(key) < 16:
        raise SystemExit("MCP_API_KEY must be set (>= 16 chars) to serve HTTP")
    hosts = os.environ.get("MCP_ALLOWED_HOSTS", "localhost:*,127.0.0.1:*").split(",")
    uvicorn.run(
        http_app(key, [h.strip() for h in hosts if h.strip()]), host=args.host, port=args.port
    )


if __name__ == "__main__":
    main()
