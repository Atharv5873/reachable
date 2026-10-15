"""Thin helpers over the official `falkordb` client.

Design notes (the WHY):
* We keep ONE connection object and `select_graph(name)` per graph. FalkorDB
  stores every graph in the same Redis server keyed by name, so `org_a`,
  `org_b` and `threatintel` are just different keys on one server.
* Every write goes through `run_batched`, which issues a parameterised
  `UNWIND $rows AS row ...` query. Parameterised Cypher only: values never get
  string-formatted into the query text (injection-safe and lets FalkorDB cache
  the plan). Batching keeps each query's payload bounded so we don't blow the
  query/result-set limits on a 2000-asset org.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from itertools import islice
from typing import Any

from falkordb import FalkorDB

from .settings import Settings, get_settings

# Default UNWIND batch size. Large enough to amortise round-trips, small enough
# to stay well under RESULTSET_SIZE and MAX_QUEUED_QUERIES on bulk loads.
BATCH = 1000


def connect(settings: Settings | None = None) -> FalkorDB:
    """Open a FalkorDB connection using the shared settings."""
    s = settings or get_settings()
    return FalkorDB(host=s.falkordb_host, port=s.falkordb_port, password=s.falkordb_password)


def ping(db: FalkorDB) -> bool:
    """True if the server answers PING. Raises if unreachable."""
    return bool(db.connection.ping())


def list_graphs(db: FalkorDB) -> list[str]:
    return list(db.list_graphs())


def drop_graph(db: FalkorDB, name: str) -> None:
    """Delete a graph if it exists. Idempotent — safe to call on a fresh server."""
    if name in db.list_graphs():
        db.select_graph(name).delete()


def _chunks(it: Iterable[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    iterator = iter(it)
    while chunk := list(islice(iterator, size)):
        yield chunk


def run_batched(
    graph,
    cypher: str,
    rows: Iterable[dict[str, Any]],
    *,
    batch: int = BATCH,
    extra_params: dict[str, Any] | None = None,
) -> int:
    """Run a parameterised `UNWIND $rows AS row ...` query in batches.

    `cypher` must reference the parameter `$rows` (a list) and may use
    `row.<field>` to read each element. Returns the total row count processed.
    """
    total = 0
    for chunk in _chunks(rows, batch):
        params: dict[str, Any] = {"rows": chunk}
        if extra_params:
            params.update(extra_params)
        graph.query(cypher, params)
        total += len(chunk)
    return total


def create_range_index(graph, label: str, prop: str) -> None:
    """Create a range index on (label).(prop), ignoring 'already indexed' errors.

    FalkorDB raises if the index already exists, so loaders can call this freely
    to stay idempotent without first querying db.indexes().
    """
    try:
        graph.query(f"CREATE INDEX FOR (n:{label}) ON (n.{prop})")
    except Exception as exc:  # noqa: BLE001 - only swallow the "exists" case
        if "already indexed" not in str(exc).lower() and "already exists" not in str(exc).lower():
            raise


def memory_usage_mb(db: FalkorDB, name: str) -> int:
    """Return total_graph_sz_mb from GRAPH.MEMORY USAGE, or -1 if unavailable.

    The command returns a RESP flat array of alternating field/value pairs.
    """
    try:
        raw = db.connection.execute_command("GRAPH.MEMORY", "USAGE", name)
    except Exception:  # noqa: BLE001 - optional metric; never fail a load over it
        return -1
    # Walk the flat [k1, v1, k2, v2, ...] array for total_graph_sz_mb.
    for i in range(0, len(raw) - 1, 2):
        key = raw[i].decode() if isinstance(raw[i], bytes) else raw[i]
        if key == "total_graph_sz_mb":
            return int(raw[i + 1])
    return -1
