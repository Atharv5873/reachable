"""`python -m reachable_graph derive` — build the ATTACK_STEP layer on every org graph.

Run after `make seed`. Prints one JSON line per org, then re-runs the
derivation and checks the edge set is unchanged (the idempotency check).
"""

from __future__ import annotations

import argparse
import json

from reachable_core.db import connect
from reachable_core.settings import get_settings

from .derive import derive, edge_signature


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="reachable_graph")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("derive")
    d.add_argument("--graph", action="append", help="graph name (default: every org)")
    d.add_argument("--no-check", action="store_true", help="skip the idempotency re-run")
    args = p.parse_args(argv)

    db = connect()
    # Default: every scan graph that is loaded (v1 always; v2 once seeded).
    loaded = set(db.list_graphs())
    names = args.graph or [g for g in get_settings().graphs if g in loaded]
    for name in names:
        if name not in db.list_graphs():
            raise SystemExit(f"graph {name!r} not loaded (run `make seed`)")
        g = db.select_graph(name)
        stats = derive(g)
        if not args.no_check:
            before = edge_signature(g)
            derive(g)
            stats["idempotent"] = edge_signature(g) == before
        print(json.dumps({"graph": name, **stats}))


if __name__ == "__main__":
    main()
