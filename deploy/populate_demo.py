"""Record the demo's replay runs on a freshly seeded backend (S10). Stdlib only.

    REACHABLE_API_KEY=... python3 populate_demo.py --url https://reachable-api.devarv.dev

What replay mode needs, in order (each with the real model, ~6 calls a run):
  1. one finished v1 run per org (org_a, org_b, org_c);
  2. on org_a's v1 run, the analyst accepts finding 06859 as a risk for 90 days
     (POST /runs/{id}/verdict with accept_risk_days), exactly what the Drift
     screen's "Accept as risk" button sends;
  3. the org_a v2 run, which carries that memory over: the Drift screen's new
     crown path + memory recognition, and the accepted risk suppressed.

A step whose run already exists (a finished real-model run) is skipped, so a
rerun after a partial failure only does what is missing; --force redoes all.
The run ids land in demo_runs.json next to this file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

FINAL = {"complete", "degraded", "budget_exhausted", "failed"}
ACCEPT = "org_a:finding:06859"
REASON = "Compensating control in place; vendor fix lands next quarter."


class Api:
    def __init__(self, url: str, key: str) -> None:
        self.url, self.key = url.rstrip("/"), key

    def call(self, method: str, path: str, body: dict | None = None) -> dict | list:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"{self.url}/{path}",
            data=data,
            method=method,
            headers={"X-API-Key": self.key, "Content-Type": "application/json"},
        )
        for attempt in range(6):
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 5:  # two runs already going
                    time.sleep(int(e.headers.get("Retry-After") or 30))
                    continue
                raise SystemExit(f"{method} /{path} -> {e.code}: {e.read()[:300]!r}") from e
        raise AssertionError("unreachable")

    def get(self, path: str):
        return self.call("GET", path)

    def post(self, path: str, body: dict):
        return self.call("POST", path, body)


def q(run_id: str) -> str:
    return urllib.request.quote(run_id, safe="")


def existing(api: Api, org: str, scan: str) -> str | None:
    """The newest finished real-model run of org/scan, if any."""
    for o in api.get("orgs"):
        if o["org"] != org:
            continue
        for s in o["scans"]:
            if s["scan"] != scan:
                continue
            for r in sorted(s["recent_runs"], key=lambda r: -(r.get("started") or 0)):
                real = not any("fake" in m for m in r.get("models") or [])
                if r["kind"] == "agent_triage" and r["status"] == "complete" and real:
                    return r["id"]
    return None


def run(api: Api, org: str, scan: str, timeout_s: int) -> str:
    r = api.post("runs", {"org": org, "scan": scan})
    rid = r["run_id"]
    print(f"  started {rid}", flush=True)
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout_s:
        time.sleep(3)
        head = api.get(f"runs/{q(rid)}")["run"]
        if head.get("status") in FINAL:
            took = time.monotonic() - t0
            print(f"  {rid}: {head['status']} in {took:.0f} s, models {head.get('models')}")
            if head["status"] != "complete":
                raise SystemExit(f"{rid} ended {head['status']}: check `./prod.sh logs api`")
            return rid
    raise SystemExit(f"{rid} not finished after {timeout_s} s")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True, help="the API, e.g. https://reachable-api.devarv.dev")
    ap.add_argument("--force", action="store_true", help="record new runs even if some exist")
    ap.add_argument("--timeout", type=int, default=420, help="seconds per run")
    ap.add_argument("--out", default=str(Path(__file__).with_name("demo_runs.json")))
    a = ap.parse_args()
    key = os.environ.get("REACHABLE_API_KEY") or sys.exit("REACHABLE_API_KEY is not set")
    api = Api(a.url, key)
    health = api.get("health")
    print(f"health: {health['status']}  graphs: {health['checks']['falkordb'].get('org_graphs')}")
    if len(health["checks"]["falkordb"].get("org_graphs") or []) < 6:
        sys.exit("the org graphs are not loaded: run `./prod.sh seed` first")

    out: dict = {"api": a.url, "runs": {}}
    for org in ("org_a", "org_b", "org_c"):
        have = None if a.force else existing(api, org, "v1")
        print(f"{org} v1: " + (f"kept {have}" if have else "recording"))
        out["runs"][f"{org}_v1"] = have or run(api, org, "v1", a.timeout)

    have = None if a.force else existing(api, "org_a", "v2")
    if have:
        print(f"org_a v2: kept {have} (its risk acceptance was recorded before it)")
        out["runs"]["org_a_v2"] = have
    else:
        v1 = out["runs"]["org_a_v1"]
        verdict = api.post(
            f"runs/{q(v1)}/verdict",
            {"finding": ACCEPT, "decision": "accept", "reason": REASON, "accept_risk_days": 90},
        )
        out["risk_acceptance"] = verdict.get("risk_acceptance")
        print(f"org_a v1: accepted {ACCEPT} as a risk -> {out['risk_acceptance']}")
        print("org_a v2: recording (carries v1's memory)")
        out["runs"]["org_a_v2"] = run(api, "org_a", "v2", a.timeout)

    out["recorded_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    Path(a.out).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(out["runs"], indent=2))
    print(f"-> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
