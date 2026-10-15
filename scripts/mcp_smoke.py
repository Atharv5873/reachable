"""Smoke-test the Reachable MCP server: list the tools, then call three.

    uv run python scripts/mcp_smoke.py                          # stdio (spawns the server)
    uv run python scripts/mcp_smoke.py --http http://localhost:8002/mcp   # needs MCP_API_KEY

Over HTTP it also checks that a request WITHOUT the API key is refused (401).
Exit code 0 = every check passed.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

import httpx
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

ORG = "org_a"


async def smoke(client: Client) -> None:
    async with client as c:
        tools = sorted(t.name for t in (await c.list_tools()).tools)
        print(f"tools ({len(tools)}): {', '.join(tools)}")

        async def call(name: str, args: dict) -> dict:
            r = await c.call_tool(name, args)
            if r.is_error:
                raise SystemExit(f"FAIL {name}: {r.content[0].text}")
            out = r.structured_content
            print(f"\n[{name}] {out['summary']}")
            print(
                f"   evidence: {len(out['evidence']['node_ids'])} nodes, "
                f"{len(out['evidence']['edges'])} edges; queries: {len(out['queries'])}"
            )
            return out

        await call("attack_paths", {"org": ORG, "k": 3})
        cut = await call("min_cut", {"org": ORG})
        sim = await call("simulate_fix", {"org": ORG, "fix_tokens": cut["data"]["fix_tokens"]})
        assert sim["data"]["all_crown_jewels_disconnected"], "min_cut did not disconnect"
        print("\nOK: min_cut's fix set disconnects every crown jewel (proved by simulate_fix)")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--http", metavar="URL", help="streamable HTTP endpoint, e.g. http://localhost:8002/mcp"
    )
    args = p.parse_args()

    if not args.http:
        params = StdioServerParameters(command=sys.executable, args=["-m", "reachable_mcp.server"])
        asyncio.run(smoke(Client(params)))
        return

    key = os.environ.get("MCP_API_KEY", "")
    if not key:
        raise SystemExit("set MCP_API_KEY")
    denied = httpx.post(args.http, json={}, headers={"Content-Type": "application/json"})
    assert denied.status_code == 401, f"expected 401 without key, got {denied.status_code}"
    print("OK: request without API key -> 401")
    http = create_mcp_http_client(headers={"X-API-Key": key})
    asyncio.run(smoke(Client(streamable_http_client(args.http, http_client=http))))


if __name__ == "__main__":
    main()
