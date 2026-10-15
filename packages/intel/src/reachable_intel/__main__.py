"""`python -m reachable_intel` — build the snapshot and load it into FalkorDB.

Subcommands:
  build [--refetch]   Normalise the committed snapshot. With --refetch, pull
                      fresh raw feeds from the network first (needs NVD_API_KEY
                      for a reasonable fetch time).
  load                Load the committed snapshot into graph `threatintel`.
"""

from __future__ import annotations

import argparse
import sys
import time

from reachable_core.db import connect
from reachable_core.settings import get_settings

from .fetch import fetch_all, raw_dir
from .load import load_threatintel
from .normalise import build_snapshot


def _build(refetch: bool) -> None:
    settings = get_settings()
    if refetch or not (raw_dir(settings) / "nvd.json").exists():
        if not settings.nvd_api_key:
            print(
                "WARNING: NVD_API_KEY not set. Fetch will crawl at 5 req/30s and "
                "take many minutes. Get a free key: "
                "https://nvd.nist.gov/developers/request-an-api-key",
                file=sys.stderr,
            )
        t0 = time.time()
        print("Fetching raw feeds (KEV, EPSS, NVD, ATT&CK)...", file=sys.stderr)
        fetch_all(settings)
        print(f"Fetched in {time.time() - t0:.0f}s", file=sys.stderr)

    meta = build_snapshot(settings)
    print("Snapshot built:")
    print(f"  CVEs:        {meta['counts']['cves']}")
    print(f"  KEV CVEs:    {meta['counts']['kev_cves']}")
    print(f"  Ransomware:  {meta['counts']['ransomware_cves']}")
    print(f"  EPSS rows:   {meta['counts']['epss_rows']}")
    print(f"  Critical:    {meta['counts']['critical']}")
    print(f"  Techniques:  {meta['counts']['techniques']}")
    print(f"  Tactics:     {meta['counts']['tactics']}")


def _load() -> None:
    settings = get_settings()
    db = connect(settings)
    t0 = time.time()
    stats = load_threatintel(db, settings)
    stats["load_seconds"] = round(time.time() - t0, 1)
    print("threatintel loaded:")
    for k, v in stats.items():
        print(f"  {k}: {v}")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="reachable_intel")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="normalise the snapshot (optionally refetch)")
    b.add_argument("--refetch", action="store_true", help="pull fresh raw feeds first")
    sub.add_parser("load", help="load the snapshot into FalkorDB")
    args = p.parse_args(argv)

    if args.cmd == "build":
        _build(args.refetch)
    elif args.cmd == "load":
        _load()


if __name__ == "__main__":
    main()
