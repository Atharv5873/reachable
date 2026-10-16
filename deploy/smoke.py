"""Smoke test the live API over HTTPS (S10). Stdlib only; exits 1 on any failure.

    REACHABLE_API_KEY=... python3 deploy/smoke.py --url https://reachable-api.devarv.dev

Checks: /health open and green (both datastores, all six org graphs); http://
redirects to https://; a non-public endpoint refuses no key and a wrong key;
/orgs with the key lists the three orgs; every run in demo_runs.json reads back
complete and its /events list ends in report_ready; /evals carries the S9
comparison; the API allows no browser origin cross-origin (CORS).
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

OK, FAIL = "PASS", "FAIL"
results: list[tuple[str, str, str]] = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url: str, headers: dict | None = None, method: str = "GET", follow: bool = True):
    """(status, headers, body bytes, ms); never raises on an HTTP status."""
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    opener = (
        urllib.request.build_opener()
        if follow
        else urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    )
    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, r.headers, r.read(), (time.monotonic() - t0) * 1000
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read(), (time.monotonic() - t0) * 1000


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((OK if ok else FAIL, name, detail))
    print(f"[{OK if ok else FAIL}] {name}" + (f"  ({detail})" if detail else ""), flush=True)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--runs", default=str(Path(__file__).with_name("demo_runs.json")))
    a = ap.parse_args()
    base = a.url.rstrip("/")
    key = os.environ.get("REACHABLE_API_KEY") or sys.exit("REACHABLE_API_KEY is not set")
    auth = {"X-API-Key": key}
    host = urllib.parse.urlparse(base).hostname

    st, _, body, ms = fetch(f"{base}/health")
    h = json.loads(body or b"{}")
    graphs = (h.get("checks", {}).get("falkordb") or {}).get("org_graphs") or []
    check("GET /health is open and green", st == 200 and h.get("status") == "ok", f"{st}, {ms:.0f} ms")
    check("all six org graphs + threatintel are loaded", len(graphs) == 6 and h["checks"]["falkordb"].get("threatintel"), f"{graphs}")

    st, hd, _, _ = fetch(f"http://{host}/health", follow=False)
    loc = hd.get("Location", "") if hd else ""
    check("http:// redirects to https://", st in (301, 302, 307, 308) and loc.startswith("https://"), f"{st} -> {loc}")
    st, hd, _, _ = fetch(f"{base}/health")
    check("HSTS header set", "max-age" in (hd.get("Strict-Transport-Security") or ""))

    for path in ("orgs", "evals", "runs/org_a:run:000000000000/events"):
        st, _, _, _ = fetch(f"{base}/{path}")
        check(f"GET /{path} without a key -> 401", st == 401, str(st))
    st, _, _, _ = fetch(f"{base}/orgs", {"X-API-Key": "wrong-" + "x" * 30})
    check("GET /orgs with a wrong key -> 401", st == 401, str(st))
    st, _, _, _ = fetch(f"{base}/docs")
    check("GET /docs (OpenAPI UI) needs the key", st == 401, str(st))

    st, _, body, ms = fetch(f"{base}/orgs", auth)
    orgs = json.loads(body) if st == 200 else []
    check("GET /orgs with the key -> the three orgs", st == 200 and [o["org"] for o in orgs] == ["org_a", "org_b", "org_c"], f"{st}, {ms:.0f} ms")

    st, hd, _, _ = fetch(f"{base}/orgs", {**auth, "Origin": "https://evil.example"})
    check("no CORS grant for a foreign origin", not (hd and hd.get("Access-Control-Allow-Origin")), f"ACAO={hd.get('Access-Control-Allow-Origin') if hd else None}")

    runs = json.loads(Path(a.runs).read_text()).get("runs", {}) if Path(a.runs).exists() else {}
    check("demo_runs.json lists the four demo runs", set(runs) == {"org_a_v1", "org_b_v1", "org_c_v1", "org_a_v2"}, a.runs)
    for name, rid in runs.items():
        q = urllib.parse.quote(rid, safe="")
        st, _, body, ms = fetch(f"{base}/runs/{q}", auth)
        run = json.loads(body).get("run", {}) if st == 200 else {}
        real = run.get("models") and not any("fake" in m for m in run["models"])
        check(f"GET /runs/{rid} ({name}) complete, real model", st == 200 and run.get("status") == "complete" and bool(real), f"{st}, {ms:.0f} ms, {run.get('models')}")
        st, _, body, ms = fetch(f"{base}/runs/{q}/events", auth)
        ev = json.loads(body) if st == 200 else []
        check(f"  /events ends in report_ready ({len(ev)} events)", bool(ev) and ev[-1]["type"] == "report_ready", f"{ms:.0f} ms")

    st, _, body, _ = fetch(f"{base}/evals", auth)
    res = json.loads(body).get("results", {}) if st == 200 else {}
    check("GET /evals carries the S9 comparison + ablation", {"comparison", "ablation", "gate_a"} <= set(res), f"{sorted(res)}")

    failed = [r for r in results if r[0] == FAIL]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
