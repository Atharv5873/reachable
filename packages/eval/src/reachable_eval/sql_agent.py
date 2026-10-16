"""sql_agent: the same LLM loop with one tool, read-only text-to-SQL over the
Postgres mirror (the eval_<graph> views). It can join and aggregate any table,
including WITH RECURSIVE; it has no path or graph primitive.

Guard rails, in depth:
  1. the role (store.RO_ROLE) can read eval_<graph> and nothing else, its
     transactions are read-only and it has a 5 s statement timeout;
  2. psycopg sends the statement with the extended protocol, which refuses more
     than one statement per call;
  3. a cheap syntactic check: a single SELECT/WITH, no session/role functions;
  4. at most 50 rows come back (the 51st only tells us it was truncated), and
     the loop's shared tool budget (24 calls, as for the other two) caps queries.
"""

from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager

import psycopg

from .agent import LLMPrioritiser, LocalTool, LocalToolbox, ToolInfraError
from .store import ScanData, ro_connect

MAX_ROWS = 50
CELL_CHARS = 200

SCHEMA_DOC = """\
Tables (PostgreSQL 17; the search_path is this org's mirror, use bare names):
  zones(id, name, trust)                    trust 0 = internet ... higher = more internal
  assets(id, kind, zone, env, hostname, cloud)
  software(id, vendor, product, version, cpe)
  vulns(id, cve, cvss, av, pr, ui, epss, kev, ransomware)
  findings(id, scanner, first_seen, status)  status 'open' | 'fixed'
  identities(id, kind, name, over_broad)
  secrets(id, kind, requires_priv)
  datastores(id, kind, crown_jewel)
  controls(id, kind)
  edges(src, dst, type, props jsonb), type is one of:
    EXPOSES     'internet' -> asset  (props.port)       the asset faces the Internet
    CAN_REACH   asset -> asset       (props.port)       network reachability
    RUNS        asset -> software
    HAS_VULN    software -> vuln
    ON          finding -> asset;   OF  finding -> vuln
    IN_ZONE     asset -> zone
    HOLDS       asset -> secret;    UNLOCKS secret -> asset | identity | datastore
    ASSUMES     asset -> identity;  CAN_ASSUME identity -> identity
    CAN         identity -> datastore (props.action)
    MITIGATES   control -> vuln     (props.asset: the asset it protects)"""

_FORBIDDEN = re.compile(
    r"\b(set_config|current_setting|pg_read|pg_ls|pg_stat_file|lo_import|lo_export|dblink|"
    r"copy|reset|set\s+role|set\s+session|"
    r"insert|update|delete|merge|truncate|alter|drop|create|grant|revoke|call|do|lock|vacuum)\b",
    re.IGNORECASE,
)
_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)


def check_sql(text: str) -> str:
    """The statement to run, or raise ValueError saying why not."""
    q = _COMMENT.sub(" ", text or "").strip().rstrip(";").strip()
    if not q:
        raise ValueError("empty query")
    if ";" in q:
        raise ValueError("one statement per call")
    if not re.match(r"(?is)^(select|with)\b", q):
        raise ValueError("only SELECT (or WITH ... SELECT) queries are allowed")
    if _FORBIDDEN.search(q):
        raise ValueError("that function or statement is not allowed")
    return q


def run_sql(graph: str, text: str) -> dict:
    q = check_sql(text)
    try:
        conn = ro_connect(graph)
    except psycopg.OperationalError as exc:
        raise ToolInfraError(f"sql backend unavailable: {exc}") from exc
    with conn, conn.cursor() as cur:
        try:
            cur.execute(q)
        except psycopg.errors.QueryCanceled:
            raise  # the statement timeout: a query the model should make cheaper
        except psycopg.OperationalError as exc:
            raise ToolInfraError(f"sql backend failed: {exc}") from exc
        cols = [d.name for d in cur.description or []]
        rows = cur.fetchmany(MAX_ROWS + 1)
    truncated = len(rows) > MAX_ROWS
    rows = [[_cell(v) for v in r] for r in rows[:MAX_ROWS]]
    return {
        "summary": f"{len(rows)} row(s){' (truncated at 50)' if truncated else ''}",
        "data": {"columns": cols, "rows": rows},
        "truncated": truncated,
    }


def _cell(v):
    if isinstance(v, float):
        return round(v, 4)
    if isinstance(v, int | bool) or v is None:
        return v
    s = str(v)
    return s if len(s) <= CELL_CHARS else s[:CELL_CHARS] + "..."


def sql_toolbox_factory():
    @asynccontextmanager
    async def make(data: ScanData):
        async def sql_query(args: dict) -> dict:
            # psycopg's async driver needs a selector loop on Windows; a thread does not.
            return await asyncio.to_thread(run_sql, data.ref.graph, str(args.get("sql", "")))

        yield LocalToolbox(
            [
                LocalTool(
                    "sql_query",
                    "Run ONE read-only SQL SELECT over this organisation's inventory and "
                    f"scanner data. At most {MAX_ROWS} rows come back; 5 s timeout.\n" + SCHEMA_DOC,
                    {
                        "type": "object",
                        "properties": {"sql": {"type": "string", "description": "One SELECT."}},
                        "required": ["sql"],
                    },
                    sql_query,
                )
            ]
        )

    return make


def sql_agent(llm_factory=None) -> LLMPrioritiser:
    kw = {"llm_factory": llm_factory} if llm_factory else {}
    return LLMPrioritiser("sql_agent", sql_toolbox_factory(), ("sql_query",), **kw)
