"""Reachable API: the backend the UI (S6) talks to.

    POST /runs                      {org, scan} -> starts a run in the background, returns run_id
    GET  /runs/{run_id}/stream      Server-Sent Events: the run's steps as they happen
    GET  /runs/{run_id}             the run as written to the graph (outputs + trace)
    POST /runs/{run_id}/verdict     an analyst accepts / rejects a decision (procedural memory)
    GET  /orgs                      orgs, their scans, recent runs and alerts
    GET  /orgs/{org}/drift          exposure_drift between two scans
    GET  /health                    both datastores (open, no key)

Two rules shape it:

* The run and the stream never block each other. A run executes in its own
  thread with its own event loop (LLM calls, MCP tool calls, graph writes); the
  request that started it has already returned. The stream does not listen to
  the agents at all: it polls the run's trace (the AgentStep chain the agents
  write anyway) for steps after the last one it sent, off the event loop. So a
  client can connect late, reconnect (Last-Event-ID), or several can watch, and
  the agents never wait for a slow reader.
* Same auth as the MCP server: `Authorization: Bearer <key>` or `X-API-Key`
  (API_KEY, else MCP_API_KEY); constant-time compare; /health is open.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import threading
import time
from collections.abc import AsyncIterator
from typing import Literal

import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from reachable_core.db import connect, ping
from reachable_core.schema import THREATINTEL_GRAPH
from reachable_core.settings import get_settings
from reachable_graph.memory import MemoryError_, MemoryRepo
from reachable_graph.tools import GraphTools, ToolError

log = logging.getLogger("reachable.api")

FINAL = {"complete", "degraded", "budget_exhausted", "failed"}
POLL_S = 0.25  # how often the stream looks for new steps
KEEPALIVE_S = 10.0  # an SSE comment when nothing happened for this long


# ------------------------------------------------------------------ requests
class RunRequest(BaseModel):
    org: str = Field(description="org_a | org_b | org_c")
    scan: Literal["v1", "v2"] = "v1"
    fake: bool = Field(False, description="the deterministic stub model (no LLM cost)")
    cold: bool = Field(False, description="v2: do not carry v1's memory over")
    as_of: int | None = Field(None, ge=0, description="the run's clock (default: scan time)")


class VerdictRequest(BaseModel):
    finding: str
    decision: Literal["accept", "reject"]
    reason: str = Field(min_length=3, max_length=2000)
    reusable: bool | None = Field(None, description="None: decide with the heuristic")


# ------------------------------------------------------------------ events
def sse(event: dict, seq: int | None = None) -> str:
    """One Server-Sent Event: `id` (the trace seq, for Last-Event-ID resume),
    `event` (its type) and `data` (JSON)."""
    head = f"id: {seq}\n" if seq is not None else ""
    return f"{head}event: {event['type']}\ndata: {json.dumps(event, default=str)}\n\n"


def step_events(repo: MemoryRepo, graph: str, run_id: str, s: dict) -> list[dict]:
    """What one trace step means for a watcher. Tool steps carry the Cypher the
    tool ran and its timing (from the tool's own query log); output steps are
    expanded from the output node the agent wrote (paths, ranking, fix plan)."""
    base = {"seq": s["seq"], "agent": s.get("agent"), "ts": s.get("ts")}
    kind = s.get("kind")
    if kind == "agent":
        return [{**base, "type": "agent_entered"}]
    if kind == "tool":
        return [
            {
                **base,
                "type": "tool_called",
                "tool": s.get("tool"),
                "by": s.get("by") or "model",
                "ok": s.get("ok", False),
                "cached": bool(s.get("cached")),
                "refused": bool(s.get("refused")),
                "ms": s.get("ms"),
                "db_ms": s.get("db_ms"),
                "summary": (s.get("summary") or s.get("error") or "")[:400],
                "queries": [
                    {"graph": q.get("graph"), "cypher": q.get("cypher"), "ms": q.get("ms")}
                    for q in (s.get("queries") or [])
                ],
            }
        ]
    if kind == "llm":
        return [
            {
                **base,
                "type": "llm_called",
                "ok": s.get("ok", True),
                "model": s.get("model"),
                "served_by": s.get("served_by"),
                "ms": s.get("ms"),
                "tokens_in": s.get("tokens_in"),
                "tokens_out": s.get("tokens_out"),
                "tool_calls": [c.get("name") for c in (s.get("tool_calls") or [])],
            }
        ]
    if kind == "memory":
        return [{**base, "type": "memory", "action": s.get("tool"), "detail": s.get("detail")}]
    if kind == "output":
        return output_events(repo, graph, run_id, s.get("tool"), base)
    return []


def output_events(repo: MemoryRepo, graph: str, run_id: str, label: str, base: dict) -> list[dict]:
    out = repo.read_output(graph, run_id, label) or {}
    p = out.get("payload") or {}
    ev = {**base, "output": out.get("id"), "summary": out.get("summary")}
    if label == "Drift":
        events = [
            {
                **ev,
                "type": "drift_checked",
                "new_paths": [x["hops"] for x in p.get("new_paths", [])],
                "closed_paths": [x["hops"] for x in p.get("closed_paths", [])],
                "flagged_on_arrival": sorted(p.get("flagged_on_arrival") or {}),
            }
        ]
        if p.get("alert"):
            events.append({**ev, "type": "alert_raised", "alert": p["alert"]})
        return events
    if label == "Triage":
        return [
            {
                **ev,
                "type": "triage_done",
                "investigate": [f["finding"] for f in p.get("investigate", [])],
                "carried": [c["finding"] for c in p.get("carried", [])],
                "suppressed": [x["finding"] for x in p.get("suppressed", [])],
            }
        ]
    if label == "PathAnalysis":
        paths = [
            {
                **ev,
                "type": "path_found",
                "rank": i + 1,
                "target": x["target"],
                "likelihood": round(x["likelihood"], 4),
                "hops": [n.get("name") or n["id"] for n in x["nodes"]],
                "steps": [st["key"] for st in x["steps"]],
            }
            for i, x in enumerate(p.get("paths", [])[:10])
        ]
        ranked = [
            {
                **ev,
                "type": "finding_ranked",
                **{k: r.get(k) for k in ("rank", "finding", "score", "why", "ranked_by")},
            }
            for r in p.get("ranked", [])[:15]
        ]
        return paths + ranked
    if label == "FixPlan":
        return [
            {
                **ev,
                "type": "fix_chosen",
                "chosen": p.get("chosen"),
                "fix_tokens": p.get("fix_tokens"),
                "total_effort": p.get("total_effort"),
                "verified": p.get("verified"),
                "fixes": [
                    {
                        "token": f["token"],
                        "action": f.get("action"),
                        "team": (f.get("team") or {}).get("name"),
                        "routed_by": f.get("routed_by"),
                    }
                    for f in p.get("fixes", [])
                ],
            }
        ]
    if label == "Report":
        return [{**ev, "type": "report_written", "headline": p.get("headline")}]
    return []


# ------------------------------------------------------------------ the app
class ApiKeyMiddleware:
    """`Authorization: Bearer <key>` or `X-API-Key: <key>` on every request except
    /health and /: the same scheme as the MCP server. Constant time; fails closed."""

    OPEN = {"/health", "/"}

    def __init__(self, app, api_key: str) -> None:
        self.app, self.key = app, api_key.encode()

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope.get("path") in self.OPEN
            or scope["method"] == "OPTIONS"
        ):
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        given = headers.get("x-api-key") or headers.get("authorization", "").removeprefix("Bearer ")
        if not hmac.compare_digest(given.encode(), self.key):
            resp = JSONResponse({"error": "missing or invalid API key"}, status_code=401)
            return await resp(scope, receive, send)
        return await self.app(scope, receive, send)


def create_app(
    *,
    api_key: str | None = None,
    repo: MemoryRepo | None = None,
    tools: GraphTools | None = None,
    llm_factory=None,
    scan_graph=None,
) -> FastAPI:
    """The app. Tests pass their own repo/tools (a throwaway graph's allowlist)
    and llm_factory; production uses the shared settings."""
    settings = get_settings()
    scan_graph = scan_graph or settings.scan_graph  # (org, scan) -> graph name
    key = api_key or os.environ.get("API_KEY") or os.environ.get("MCP_API_KEY") or ""
    if len(key) < 16:
        raise RuntimeError("API_KEY (or MCP_API_KEY) must be set, >= 16 chars")
    app = FastAPI(title="Reachable", version="0.5.0")
    state = {"repo": repo, "tools": tools, "threads": {}}

    def get_repo() -> MemoryRepo:
        if state["repo"] is None:
            state["repo"] = MemoryRepo()
        return state["repo"]

    def get_tools() -> GraphTools:
        if state["tools"] is None:
            state["tools"] = GraphTools()
        return state["tools"]

    def graph_of(run_id: str) -> str:
        graph = run_id.split(":", 1)[0]  # run ids are <graph>:run:<hex>
        if graph not in get_repo().allowed:
            raise HTTPException(404, f"no run {run_id!r}")
        return graph

    def make_llm(fake: bool):
        if llm_factory is not None:
            return llm_factory(fake)
        from reachable_agents.fake import FakeLLM
        from reachable_agents.llm import RouterLLM

        return FakeLLM() if fake else RouterLLM()

    # -------------------------------------------------------------- health
    @app.get("/")
    def hello() -> dict:
        return {"service": "reachable", "docs": "/docs", "version": app.version}

    @app.get("/health")
    def health() -> JSONResponse:
        """Check both datastores. Returns 503 if either is unreachable."""
        checks: dict[str, dict] = {}
        try:
            db = connect(settings)
            ok = ping(db)
            present = db.list_graphs()
            checks["falkordb"] = {
                "ok": ok,
                "threatintel": THREATINTEL_GRAPH in present,
                "org_graphs": [g for g in settings.graphs if g in present],
            }
        except Exception as exc:  # report, don't crash: this is a health endpoint
            checks["falkordb"] = {"ok": False, "error": str(exc)}
        try:
            with psycopg.connect(settings.postgres_dsn, connect_timeout=3) as conn:
                conn.execute("SELECT 1")
            checks["postgres"] = {"ok": True}
        except Exception as exc:
            checks["postgres"] = {"ok": False, "error": str(exc)}
        healthy = all(c["ok"] for c in checks.values())
        return JSONResponse(
            status_code=200 if healthy else 503,
            content={"status": "ok" if healthy else "degraded", "checks": checks},
        )

    # ---------------------------------------------------------------- runs
    @app.post("/runs", status_code=202)
    def start_run(req: RunRequest) -> dict:
        """Create the Run node now (so the id can be streamed at once), then run
        the agents in a background thread with its own event loop."""
        from reachable_agents.graph import run_agents  # heavy import: on first use

        if req.org not in settings.orgs:
            raise HTTPException(422, f"unknown org {req.org!r}; one of {settings.orgs}")
        repo = get_repo()
        graph = scan_graph(req.org, req.scan)
        if graph not in repo.allowed:
            raise HTTPException(404, f"graph {graph} is not available")
        info = repo.scan_info(graph)
        if info is None:
            raise HTTPException(409, f"{graph} is not loaded (make seed)")
        as_of = req.as_of or info["ts"]
        run_id = repo.start_agent_run(
            graph, kind="agent_triage", scan=req.scan, as_of=as_of, budget={}
        )
        llm = make_llm(req.fake)

        def work() -> None:
            try:
                asyncio.run(
                    run_agents(
                        req.org,
                        req.scan,
                        llm=llm,
                        as_of=as_of,
                        repo=repo,
                        graph=graph,
                        run_id=run_id,
                        carry_memory=not req.cold,
                    )
                )
            except Exception:  # noqa: BLE001 - recorded on the run; the API stays up
                log.exception("run %s failed", run_id)
                head = repo.run_head(graph, run_id) or {}
                if head.get("status") not in FINAL:
                    repo.set_run_status(graph, run_id, "failed")

        t = threading.Thread(target=work, name=f"run-{run_id}", daemon=True)
        state["threads"][run_id] = t
        t.start()
        return {
            "run_id": run_id,
            "graph": graph,
            "as_of": as_of,
            "stream": f"/runs/{run_id}/stream",
            "result": f"/runs/{run_id}",
        }

    @app.get("/runs/{run_id}")
    def get_run(run_id: str, full: bool = False) -> dict:
        """The run as written to the graph: run properties, every agent output, and
        the trace (light by default; full=true includes each tool's stored result)."""
        graph = graph_of(run_id)
        try:
            dump = get_repo().agent_run(graph, run_id)
        except MemoryError_ as exc:
            raise HTTPException(404, str(exc)) from exc
        if not full:
            for s in dump["steps"]:
                s.pop("result", None)
        dump["graph"] = graph
        return dump

    @app.get("/runs/{run_id}/stream")
    async def stream(run_id: str, request: Request) -> StreamingResponse:
        graph = graph_of(run_id)
        repo = get_repo()
        if await asyncio.to_thread(repo.run_head, graph, run_id) is None:
            raise HTTPException(404, f"no run {run_id!r}")
        last = request.headers.get("last-event-id")
        after = int(last) if last and last.lstrip("-").isdigit() else -1
        return StreamingResponse(
            events(repo, graph, run_id, after, request),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/runs/{run_id}/events")
    def all_events(run_id: str) -> list[dict]:
        """Every event so far, as one JSON list (what the stream would replay)."""
        graph = graph_of(run_id)
        repo = get_repo()
        return [
            e
            for s in repo.steps_after(graph, run_id, -1, 2000)
            for e in step_events(repo, graph, run_id, s)
        ]

    @app.post("/runs/{run_id}/verdict")
    def verdict(run_id: str, req: VerdictRequest) -> dict:
        graph = graph_of(run_id)
        try:
            return get_repo().record_analyst_verdict(
                graph, run_id, req.finding, req.decision, req.reason, reusable=req.reusable
            )
        except MemoryError_ as exc:
            raise HTTPException(422, str(exc)) from exc

    # ---------------------------------------------------------------- orgs
    @app.get("/orgs")
    def orgs() -> list[dict]:
        repo = get_repo()
        present = set(repo.db.list_graphs())
        out = []
        for org in settings.orgs:
            scans = []
            for scan in ("v1", "v2"):
                g = scan_graph(org, scan)
                if g not in present or g not in repo.allowed:
                    continue
                scans.append(
                    {
                        "scan": scan,
                        "graph": g,
                        "info": repo.scan_info(g),
                        "recent_runs": repo.recent_runs(g, 5),
                        "alerts": repo.alerts(g)[:5],
                    }
                )
            out.append({"org": org, "scans": scans})
        return out

    @app.get("/orgs/{org}/drift")
    def drift(
        org: str, from_scan: str = "v1", to_scan: str = "v2", include_paths: bool = True
    ) -> dict:
        if org not in settings.orgs:
            raise HTTPException(404, f"unknown org {org!r}")
        try:
            base = scan_graph(org, "v1")  # exposure_drift resolves <base>_v2 itself
            r = get_tools().exposure_drift(base, from_scan, to_scan, include_paths)
        except (ToolError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return r.model_dump()

    async def events(
        repo: MemoryRepo, graph: str, run_id: str, after: int, request: Request
    ) -> AsyncIterator[str]:
        """Poll the trace; send each new step's events; end with report_ready (or
        run_failed) once the run is final and every step has been sent."""
        quiet = time.monotonic()
        yield "retry: 2000\n\n"
        while True:
            if await request.is_disconnected():
                return
            steps = await asyncio.to_thread(repo.steps_after, graph, run_id, after)
            for s in steps:
                for e in await asyncio.to_thread(step_events, repo, graph, run_id, s):
                    yield sse(e, s["seq"])
                after = s["seq"]
            if steps:
                quiet = time.monotonic()
                continue
            head = await asyncio.to_thread(repo.run_head, graph, run_id) or {}
            if head.get("status") in FINAL:
                # The run may have written steps between our read and its finish.
                if await asyncio.to_thread(repo.steps_after, graph, run_id, after):
                    continue
                report = await asyncio.to_thread(repo.read_output, graph, run_id, "Report")
                p = (report or {}).get("payload") or {}
                final = {
                    "type": "report_ready" if report else "run_failed",
                    "run_id": run_id,
                    "status": head.get("status"),
                    "headline": p.get("headline"),
                    "risk": p.get("risk"),
                    "report": (report or {}).get("id"),
                    "stats": head.get("stats"),
                }
                yield sse(final, after)
                return
            if time.monotonic() - quiet > KEEPALIVE_S:
                quiet = time.monotonic()
                yield ": keepalive\n\n"
            await asyncio.sleep(POLL_S)

    origins = [
        o for o in os.environ.get("API_CORS_ORIGINS", "http://localhost:3000").split(",") if o
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "X-API-Key", "Content-Type", "Last-Event-ID"],
    )
    app.add_middleware(ApiKeyMiddleware, api_key=key)
    return app


def _app() -> FastAPI:
    """uvicorn reachable_api.main:app. Built at import, but only if a key is set:
    importing the module (e.g. for tests) must not require one."""
    try:
        return create_app()
    except RuntimeError as exc:
        log.warning("API not configured: %s", exc)
        fallback = FastAPI(title="Reachable (no API key set)")

        @fallback.get("/health")
        def health() -> JSONResponse:
            return JSONResponse(status_code=503, content={"status": "no API key configured"})

        return fallback


app = _app()
