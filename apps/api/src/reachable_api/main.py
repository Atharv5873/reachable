"""Reachable API. Placeholder in S1: hello-world plus a health check that
pings both datastores. Agents and attack-path endpoints arrive in S2+.
"""

import psycopg
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from reachable_core.db import connect, ping
from reachable_core.schema import ORG_GRAPHS, THREATINTEL_GRAPH
from reachable_core.settings import get_settings

app = FastAPI(title="Reachable", version="0.1.0")


@app.get("/")
def hello() -> dict:
    return {
        "service": "reachable",
        "message": "Triage findings by what an attacker can reach. Agents arrive in S2+.",
    }


@app.get("/health")
def health() -> JSONResponse:
    """Check both datastores. Returns 503 if either is unreachable."""
    settings = get_settings()
    checks: dict[str, dict] = {}

    try:
        db = connect(settings)
        ok = ping(db)
        present = db.list_graphs()
        checks["falkordb"] = {
            "ok": ok,
            "threatintel": THREATINTEL_GRAPH in present,
            "org_graphs": [g for g in ORG_GRAPHS if g in present],
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
