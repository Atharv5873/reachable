# Reachable: production runbook (S10)

Live: **https://reachable-web-sand.vercel.app** (Vercel, region fra1), with the API at
**https://reachable-api.devarv.dev** (Hetzner VPS `91.98.216.38`, Falkenstein,
2 vCPU / 3.7 GB, Ubuntu 26.04, Docker 29 + Compose v5). Everything below was run
on 2026-10-16. Commands are copy-paste.

```
phone / laptop ──HTTPS──> Vercel (Next.js, fra1)                    VPS 91.98.216.38
                           /api/r/* route handler ──HTTPS + X-API-Key──> :443 Caddy (Let's Encrypt)
                           (key: server-side env)                         └─> api:8000 (FastAPI, agents, MCP in-process)
                                                                                ├─> falkordb:6379  (no host port)
                                                                                └─> postgres:5432  (no host port)
```

## 0. What you need

| thing | where |
|---|---|
| SSH to the VPS | `ssh root@91.98.216.38` (key `~/.ssh/id_ed25519`) |
| DNS | `reachable-api.devarv.dev` A -> `91.98.216.38`, AAAA -> `2a01:4f8:c012:699e::1` (both this box; Let's Encrypt tries IPv6 first) |
| Vercel | CLI logged in, team `atharv-sharmas-projects-77fdf735` (Atharv Sharma's projects), project `reachable-web`, root `apps/web` |
| Secrets | `/opt/reachable/deploy/.env.prod` on the VPS (mode 600, never in git) |
| Gemini credit | **keep ~$10** so a live judge run never answers 402. Replay needs none. |

## 1. Backend (VPS)

First deploy (from your laptop, in the repo):

```sh
git archive --format=tar HEAD | ssh root@91.98.216.38 'mkdir -p /opt/reachable && tar -x -C /opt/reachable'
ssh root@91.98.216.38
cd /opt/reachable/deploy
cp .env.prod.example .env.prod && chmod 600 .env.prod
# fill: REACHABLE_API_KEY, FALKORDB_PASSWORD, POSTGRES_PASSWORD (python3 -c "import secrets; print(secrets.token_urlsafe(32))"), GEMINI_API_KEY
./prod.sh up          # build, start, wait for every healthcheck (Caddy gets the cert in ~5 s)
./prod.sh seed        # make intel && make seed inside the network (~2 min, deterministic, SEED=42)
./prod.sh populate    # the 4 demo runs with the real model (~1 min, ~24 model calls, ~$0.05)
./prod.sh smoke       # 21 HTTPS checks
```

Update the code later (data and runs are kept; volumes are not touched):

```sh
git archive --format=tar HEAD | ssh root@91.98.216.38 'tar -x -C /opt/reachable'
ssh root@91.98.216.38 'cd /opt/reachable/deploy && ./prod.sh up'
```

Day-to-day: `./prod.sh ps`, `./prod.sh logs api`, `./prod.sh restart` (down + up;
FalkorDB AOF + named volumes keep graphs, demo runs and the certificate).

**Never** add a `ports:` entry for falkordb/postgres/api. Docker writes its own
iptables rules ahead of ufw, so a published port is public even though ufw says
22/80/443 only.

## 2. Demo runs recorded on the VPS (replay content)

`deploy/demo_runs.json` (committed):

| run | id |
|---|---|
| org_a v1 | `org_a:run:d83515921bd8` |
| org_b v1 | `org_b:run:8fdd1f960d65` |
| org_c v1 | `org_c:run:f973097ae0e6` |
| org_a v2 (after accepting 06859 as a risk, `org_a:riskacc:01034b717cfa`, 90 days) | `org_a_v2:run:6fe91bc3bdbf` |

The v2 run: Sentinel alert on the one new crown path
(internet -> vireo-basalt-edge-192 -> ember-sol-data-405 -> db_password -> bucket),
06859 **suppressed** by the acceptance, 7 findings carried from v1, 1 investigated.

Replay picks the newest finished *real-model* run per org/scan. A live judge run
(real model) becomes the newest and replay then shows it; to pin the demo, use the
run picker or a URL with `&run=<id>` (the video should use these ids). A stub-model
run never displaces them.

## 3. Frontend (Vercel)

```sh
cd apps/web
vercel link --yes --project reachable-web            # once; writes .vercel/ (gitignored)
printf 'https://reachable-api.devarv.dev' > /tmp/u && vercel env add REACHABLE_API_URL production < /tmp/u
ssh root@91.98.216.38 "sed -n 's/^REACHABLE_API_KEY=//p' /opt/reachable/deploy/.env.prod" | tr -d '\r\n' > /tmp/k
vercel env add REACHABLE_API_KEY production --sensitive < /tmp/k && rm /tmp/k /tmp/u
vercel deploy --prod --yes
```

`apps/web/vercel.json` pins `framework: nextjs` (a project made with `vercel
project add` defaults to "Other" and the build fails with *The Output Directory
"public" is empty*) and `regions: ["fra1"]` (next to the VPS; the default iad1
adds a transatlantic round trip to every proxied call).

The key is never a `NEXT_PUBLIC_` var. Prove it after every deploy:

```sh
cd apps/web
REACHABLE_API_KEY=<key> npm run test:bundle                                        # local prod build
REACHABLE_API_KEY=<key> npm run test:bundle:live -- https://reachable-web-sand.vercel.app  # what Vercel serves
```

## 4. Checks (all passed 2026-10-16)

```sh
python deploy/portscan.py reachable-api.devarv.dev          # from OUTSIDE the VPS
REACHABLE_API_KEY=<key> python deploy/smoke.py --url https://reachable-api.devarv.dev
cd apps/web && E2E_BASE_URL=https://reachable-web-sand.vercel.app npx playwright test   # Gate C + smoke + replay
```

| check | result |
|---|---|
| port scan (IPv4 + IPv6) | 22, 80, 443 open; 3000/3001/5432/5434/6379/6380/8000/8001/8002 closed |
| http -> https | 308 to https, HSTS max-age 1 year |
| key required | /orgs, /evals, /runs/*, /docs: 401 with no key or a wrong key; /health open |
| CORS | no grant for any origin (the browser only talks to Vercel) |
| proxy CSRF | cross-site POST 403, non-JSON POST 403, same-origin POST 200, unlisted path 404 |
| key in client bundle | none (46 local build files; 30 live responses, ~1 MB) |
| key in logs | Caddy drops `X-Api-Key` / `Authorization` from access logs |
| persistence | `./prod.sh restart`: 6 graphs + 4 demo runs still there, smoke 21/21 |
| rate limiter | `LLM_RPM=20`, `AGENT_MAX_LLM_CALLS=20`, `API_MAX_RUNS=2` (3rd concurrent run: 429) |

## 5. Gate C on a real phone (manual, on cellular, Wi-Fi off)

Open https://reachable-web-sand.vercel.app and tick each:

1. Findings: the right-hand card says "Reachable ranks it #1" (CVSS 7.5, scanner #~4,000) with a tier badge.
2. "See its attack path": the graph draws; tap a hop -> its evidence opens.
3. Fix plan: toggle fewest / cheapest; Simulate -> every crown jewel SAFE.
4. Investigation: Replay (instant or 4x) -> the feed plays to "Report ready". No model.
5. Company brain (org_c): tap a suggestion -> an answer with its graph edges + Cypher.
6. Scan v2 -> Drift: NEW CROWN PATH, and 06859 under what memory recognised.
7. Evals: path recall@10, decoys, NDCG with its caveat.

The UI is built for desktop; on a phone the sidebar becomes an icon rail and wide
tables scroll sideways. Present the demo from a laptop.

## 6. If anything breaks during judging

* **API down / VPS issue**: `ssh root@91.98.216.38 'cd /opt/reachable/deploy && ./prod.sh ps && ./prod.sh logs api'`, then `./prod.sh restart`.
* **Vercel issue**: `vercel rollback` in `apps/web`, or redeploy.
* **Out of Gemini credit (402 on a live run)**: replay still works; top up, or set
  `LLM_RESERVE_MODEL` + `LLM_RESERVE_API_KEY` in `.env.prod` and `./prod.sh up`.
* **Fallback, always available**: the local stack reproduces the whole demo with no
  network: `make up && make seed`, one `make triage` per org (or the existing runs),
  `make web` -> http://localhost:3000 in Replay mode. **The demo video is recorded
  against replay regardless**, so it never depends on the VPS, Vercel or a model.

## 7. Rotating the key

New key in `.env.prod` -> `./prod.sh up` (api restarts) -> `vercel env rm REACHABLE_API_KEY production`,
`vercel env add ... --sensitive`, `vercel deploy --prod`. Expect ~1 min of 401s in between.
