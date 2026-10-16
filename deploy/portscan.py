"""External TCP port check of the VPS (S10). Run it from OUTSIDE the VPS (your
laptop, a phone hotspot); from the box itself everything looks open. Stdlib only.

    python deploy/portscan.py reachable-api.devarv.dev

Expected: 80 and 443 open (Caddy), 22 open (SSH, yours), everything else
closed or filtered: FalkorDB 6379/6380, its Browser 3000/3001, Postgres
5432/5434, the API 8000/8001, MCP 8002. Exits 1 if a database/API port answers.
"""

from __future__ import annotations

import socket
import sys
from concurrent.futures import ThreadPoolExecutor

EXPECT_OPEN = {80: "http (Caddy, redirects)", 443: "https (Caddy)"}
ALLOWED = {22: "ssh"}
MUST_BE_CLOSED = {
    6379: "FalkorDB", 6380: "FalkorDB (dev offset)", 3000: "FalkorDB Browser",
    3001: "FalkorDB Browser (dev offset)", 5432: "Postgres", 5434: "Postgres (dev offset)",
    8000: "API", 8001: "API (dev offset)", 8002: "MCP",
}


def probe(host: str, port: int, family: int) -> bool:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "reachable-api.devarv.dev"
    addrs = sorted({(ai[0], ai[4][0]) for ai in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})
    ports = {**EXPECT_OPEN, **ALLOWED, **MUST_BE_CLOSED}
    bad = 0
    for family, ip in addrs:
        with ThreadPoolExecutor(16) as ex:
            res = dict(zip(ports, ex.map(lambda p: probe(ip, p, family), ports)))
        if not any(res.values()):
            print(f"{ip}: nothing answered (no route from here?), skipped")
            continue
        print(f"{ip}:")
        for p, name in sorted(ports.items()):
            is_open = res[p]
            if p in EXPECT_OPEN:
                verdict = "ok" if is_open else "EXPECTED OPEN"
                bad += not is_open
            elif p in ALLOWED:
                verdict = "ok (allowed)" if is_open else "ok"
            else:
                verdict = "EXPOSED" if is_open else "ok"
                bad += is_open
            print(f"  {p:>5} {name:<30} {'open' if is_open else 'closed':<7} {verdict}")
    print("PASS" if not bad else f"FAIL ({bad} port(s) wrong)")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
