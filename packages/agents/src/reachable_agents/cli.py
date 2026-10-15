"""`python -m reachable_agents` — run the agents on a scan, or re-render a past run.

    triage  --org org_a --scan v1 [--as-of 2024-01-01] [--fake] [--mcp stdio]
            Run Triage -> Pathfinder -> Fixer -> Reporter, write everything to the
            org graph under a new run id, then dump runs/<run_id>.md + .json.
    replay  --org org_a --scan v1 --run-id <id>
            Re-render runs/<run_id>.md + .json from the graph alone.
    check   Probe every configured LLM deployment with one real tool call.

Both files are rendered from the run as READ BACK FROM THE GRAPH, not from the
objects the process holds.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from reachable_core.settings import REPO_ROOT, get_settings
from reachable_graph.memory import MemoryRepo

from .fake import FakeLLM
from .graph import run_agents
from .llm import RouterLLM, check_deployments
from .report import render_run


def parse_as_of(text: str | None) -> int | None:
    """'2024-01-01' (UTC midnight) or epoch seconds."""
    if text is None:
        return None
    if text.isdigit():
        return int(text)
    return int(datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=UTC).timestamp())


def dump_run(repo: MemoryRepo, graph: str, run_id: str, out_dir: Path) -> tuple[Path, Path]:
    dump = {"graph": graph, **repo.agent_run(graph, run_id)}
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = run_id.replace(":", "_")  # ':' is not allowed in Windows file names
    md, js = out_dir / f"{stem}.md", out_dir / f"{stem}.json"
    md.write_text(render_run(dump), "utf-8")
    js.write_text(json.dumps(dump, indent=1, default=str), "utf-8")
    return md, js


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="reachable_agents")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("triage", "replay"):
        s = sub.add_parser(name)
        s.add_argument("--org", required=True, choices=get_settings().orgs)
        s.add_argument("--scan", default="v1", choices=["v1", "v2"])
        s.add_argument("--out", type=Path, default=REPO_ROOT / "runs")
    t = sub.choices["triage"]
    t.add_argument("--as-of", help="the run's clock: YYYY-MM-DD or epoch s (default: scan time)")
    t.add_argument("--fake", action="store_true", help="deterministic stub model, no network")
    t.add_argument("--max-llm-calls", type=int)
    t.add_argument("--max-tool-calls", type=int)
    t.add_argument("--mcp", default="memory", choices=["memory", "stdio"])
    sub.choices["replay"].add_argument("--run-id", required=True)
    sub.add_parser("check", help="probe every configured LLM deployment with one tool call")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("reachable").setLevel(logging.INFO)
    # LiteLLM logs every failed attempt with a multi-KB debug dump; our own
    # reachable.llm warning says the same in one line.
    for name in ("LiteLLM", "LiteLLM Router", "LiteLLM Proxy"):
        logging.getLogger(name).setLevel(logging.CRITICAL)

    if args.cmd == "check":
        rows = asyncio.run(check_deployments())
        for r in rows or [
            {"deployment": "-", "model": "no keys set", "ok": False, "ms": 0, "note": ""}
        ]:
            mark = "OK  " if r["ok"] else "FAIL"
            print(f"{mark} {r['deployment']:<9} {r['model']:<36} {r['ms']:>6} ms  {r['note']}")
        raise SystemExit(0 if rows and all(r["ok"] for r in rows) else 1)

    repo = MemoryRepo()
    graph = get_settings().scan_graph(args.org, args.scan)

    if args.cmd == "replay":
        md, js = dump_run(repo, graph, args.run_id, args.out)
        print(f"wrote {md} and {js}")
        return

    llm = FakeLLM() if args.fake else RouterLLM()
    print("models:", "fake" if args.fake else ", ".join(llm.describe()))  # names only, no keys
    res = asyncio.run(
        run_agents(
            args.org,
            args.scan,
            llm=llm,
            as_of=parse_as_of(args.as_of),
            max_llm_calls=args.max_llm_calls,
            max_tool_calls=args.max_tool_calls,
            transport=args.mcp,
            repo=repo,
        )
    )
    md, js = dump_run(repo, res["graph"], res["run_id"], args.out)
    st = res["stats"]
    for line in res["log"]:
        print(" ", line)
    print(f"run_id: {res['run_id']}  ({res['status']}, {st['wall_ms'] / 1000:.1f} s)")
    print(
        f"LLM calls {st['llm_calls']}, tool calls {st['tool_calls']} "
        f"(+{st['cache_hits']} cached, {st['refused']} refused), "
        f"tokens {st['tokens_in']}+{st['tokens_out']}, fallbacks {st['fallbacks']}"
    )
    print("served by:", ", ".join(res["models"]) or "none")
    print(f"wrote {md}\n      {js}")


if __name__ == "__main__":
    main()
