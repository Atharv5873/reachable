"""`python -m reachable_orggen` — generate orgs, load them, write labels.

Subcommands:
  seed   Generate all orgs, load FalkorDB (+ Postgres mirror), write labels
         (v1 and v2). Skips Postgres with --no-postgres.
  reset  Drop every org graph + Postgres schema (Makefile reloads afterwards).
  sample Write a tiny committed sample under data/orgs/sample/.
"""

from __future__ import annotations

import argparse
import json
import time

from reachable_core.db import connect, drop_graph
from reachable_core.settings import get_settings

from .build import drift_org, generate_org
from .generate import GenConfig
from .labels import write_labels
from .load_falkordb import load_org
from .load_postgres import drop_org_postgres, load_org_postgres


def _seed(seed: int, scale: float, postgres: bool) -> None:
    settings = get_settings()
    db = connect(settings)
    cfg = GenConfig(scale=scale)

    for org in settings.orgs:
        t0 = time.time()
        ob = generate_org(org, seed, cfg)
        stats = load_org(db, ob.dataset)
        if postgres:
            load_org_postgres(ob.dataset, settings)

        out_dir = settings.orgs_dir / org
        write_labels(out_dir, ob, scan="v1")

        # scan v2 (week-later drift): write labels_v2 with the one new path.
        v2, new_path = drift_org(org, seed, cfg)
        write_labels(out_dir, v2, scan="v2", new_path=new_path)

        stats["load_seconds"] = round(time.time() - t0, 1)
        stats["planted_paths"] = len(ob.ground_truth.paths)
        stats["min_cut"] = len(ob.ground_truth.min_cut)
        print(json.dumps(stats))


def _reset(seed: int, scale: float) -> None:
    settings = get_settings()
    db = connect(settings)
    for org in settings.orgs:
        drop_graph(db, org)
        drop_graph(db, f"{org}_v2")
        try:
            drop_org_postgres(org, settings)
        except Exception as exc:  # noqa: BLE001 - Postgres may be down; FalkorDB is primary
            print(f"(postgres drop skipped for {org}: {exc})")
    print("dropped org graphs + schemas")


def _sample(seed: int) -> None:
    """A tiny, fast, committed sample so the repo demonstrates shape offline."""
    settings = get_settings()
    cfg = GenConfig(scale=0.02)
    ob = generate_org("org_a", seed, cfg)
    out = settings.orgs_dir / "sample"
    write_labels(out, ob, scan="v1")
    # Also dump a compact dataset summary (not the full graph).
    summary = {
        "org": "org_a",
        "assets": len(ob.dataset.assets),
        "findings": len(ob.dataset.findings),
        "edges": len(ob.dataset.edges),
        "crown_jewels": ob.ground_truth.crown_jewels,
        "planted_paths": [p.name for p in ob.ground_truth.paths],
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), "utf-8")
    print(f"wrote sample to {out}")


def main(argv: list[str] | None = None) -> None:
    # --seed/--scale live on a parent parser shared by every subcommand, so
    # both `reachable_orggen seed --seed 42` (the Makefile form) and
    # `reachable_orggen --seed 42 seed` parse.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--seed", type=int, default=get_settings().seed)
    common.add_argument("--scale", type=float, default=1.0)
    p = argparse.ArgumentParser(prog="reachable_orggen")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seed", parents=[common])
    s.add_argument("--no-postgres", action="store_true", help="skip the Postgres mirror")
    sub.add_parser("reset", parents=[common])
    sub.add_parser("sample", parents=[common])
    args = p.parse_args(argv)

    if args.cmd == "seed":
        _seed(args.seed, args.scale, postgres=not args.no_postgres)
    elif args.cmd == "reset":
        _reset(args.seed, args.scale)
    elif args.cmd == "sample":
        _sample(args.seed)


if __name__ == "__main__":
    main()
