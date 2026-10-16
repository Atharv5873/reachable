# Reachable dev tasks. Recipes call Python for anything non-trivial, so they
# behave the same under bash, macOS and Windows (GNU make + PowerShell/cmd).

SEED  ?= 42
SCALE ?= 1.0
PY      = uv run python
INTEL   = $(PY) -m reachable_intel
ORGGEN  = $(PY) -m reachable_orggen
GRAPH   = $(PY) -m reachable_graph

.PHONY: up down intel seed derive test reset lint fmt sample logs browser mcp mcp-http mcp-smoke gate-a triage drift verdict reset-memory memory-lift api web web-install web-test e2e eval ablation eval-score

# Create .env from the example on first run (never overwrites an existing one).
.env:
	$(PY) -c "import shutil; shutil.copyfile('.env.example', '.env')"

## Start FalkorDB (+ Browser), Postgres and the API; wait until healthy.
up: .env
	docker compose up -d --build --wait

## Stop containers. Data volumes are kept.
down:
	docker compose down

## Load the committed threat-intel snapshot into graph `threatintel` (offline).
## Pass REFETCH=1 to pull fresh feeds from the network and rebuild the snapshot
## first (needs NVD_API_KEY for a reasonable fetch time).
INTEL_REFETCH = $(if $(REFETCH),$(INTEL) build --refetch)
intel: .env
	$(INTEL_REFETCH)
	$(INTEL) load

## Generate the three synthetic orgs, their labels/oracle, and load FalkorDB + Postgres.
## Every graph is dropped and reloaded, so agent memory (runs, verdicts, learned
## patterns and playbook versions) is reset to the small synthetic seed.
seed: .env
	$(ORGGEN) seed --seed $(SEED) --scale $(SCALE)
	$(GRAPH) derive

## Derive the ATTACK_STEP layer (+ FLOW layer, :CrownPath) on every org graph.
## Run after `make seed`. Re-runs once and checks the edge set is unchanged.
derive: .env
	$(GRAPH) derive

## Drop every graph + Postgres schema, then reload intel and regenerate orgs.
reset: .env
	$(ORGGEN) reset --seed $(SEED) --scale $(SCALE)
	$(INTEL) load
	$(ORGGEN) seed --seed $(SEED) --scale $(SCALE)
	$(GRAPH) derive

## Unit tests + integration tests (integration tests skip if FalkorDB is down).
test:
	uv run pytest -v

lint:
	uv run ruff check .
	uv run ruff format --check .

fmt:
	uv run ruff format .
	uv run ruff check --fix .

## Regenerate the tiny committed sample in data/orgs/sample/.
sample:
	$(ORGGEN) sample --seed $(SEED)

## MCP server over stdio (point an MCP host at `uv run reachable-mcp`).
mcp:
	uv run reachable-mcp

## MCP server over streamable HTTP on :8002/mcp (needs MCP_API_KEY in .env).
mcp-http: .env
	uv run --env-file .env reachable-mcp --http

## List the MCP tools and call three (stdio). Over HTTP: URL=http://localhost:8002/mcp
mcp-smoke: .env
	uv run --env-file .env python scripts/mcp_smoke.py $(if $(URL),--http $(URL))

## Gate A: no-LLM evaluation of the tools against the oracle labels.
gate-a: .env
	$(PY) evals/gate_a.py

## Run the four agents on one scan; writes the run to the org graph and
## runs/<run_id>.md + .json. Needs GEMINI_API_KEY and/or GROQ_API_KEY in .env,
## or FAKE=1 for the deterministic stub model. AS_OF=YYYY-MM-DD overrides the clock.
ORG  ?= org_a
SCAN ?= v1
triage: .env
	$(PY) -m reachable_agents triage --org $(ORG) --scan $(SCAN) $(if $(FAKE),--fake) $(if $(AS_OF),--as-of $(AS_OF)) $(if $(COLD),--no-carry)

## The Sentinel on the week-later rescan (no LLM): carry memory into <org>_v2, flag
## arrivals that match a learned pattern, diff the Internet -> crown-jewel path
## sets of v1 and v2, and raise an Alert only on a brand-new crown path.
drift: .env
	$(PY) -m reachable_agents drift --org $(ORG) $(if $(COLD),--no-carry)

## An analyst's review of a run's decision on one finding (procedural memory):
##   make verdict RUN=<run id> FINDING=<finding id> DECISION=reject REASON="..."
## A reject with a reusable reason writes a new playbook version (old one kept).
verdict: .env
	$(PY) -m reachable_agents verdict --run-id "$(RUN)" --finding "$(FINDING)" --decision $(DECISION) --reason "$(REASON)" $(if $(REUSABLE),--reusable $(REUSABLE))

## Cold start for one scan graph: delete every memory node but the starter playbooks.
reset-memory: .env
	$(PY) -m reachable_agents reset-memory --org $(ORG) --scan $(SCAN)

## Gate B: the agents on <org>_v2 cold (fresh memory) vs warm (v1's memory present).
## Writes evals/results/memory_lift.md (+ .json). FAKE=1 runs it with the stub model.
memory-lift: .env
	$(PY) evals/memory_lift.py --org $(ORG) $(if $(FAKE),--fake)

## S7 comparison eval: severity_sort, smart_score, vector_rag, sql_agent and reachable
## rank the same findings on every scan (v1 + held-out v2), scored against the oracle.
## Prints a cost estimate first and refuses to start above MAX_USD (default 5). Raw
## outputs land in evals/results/raw/ (a rerun skips what exists; FORCE=1 redoes it);
## tables in evals/results/comparison.md (+ .json). DRY=1: estimate only. One provider seed by default
## (the headline); SEEDS="1 2 3" for the three-seed spread (about 3x the cost).
SEEDS ?= 1
EVAL_FLAGS = --seeds $(SEEDS) $(if $(MAX_USD),--max-usd $(MAX_USD)) $(if $(DRY),--dry-run) $(if $(FORCE),--force)
eval: .env
	$(PY) -m reachable_eval run $(EVAL_FLAGS)

## The ablation: the reachable agent on ORG/SCAN with its graph tools on, then off
## (every call answers "unavailable"). -> evals/results/ablation.md (+ .json).
ablation: .env
	$(PY) -m reachable_eval ablation --org $(ORG) --scan $(SCAN) $(EVAL_FLAGS)

## Recompute every eval table from evals/results/raw/ + the labels (no model, no keys).
eval-score: .env
	$(PY) -m reachable_eval score

## The API (FastAPI + SSE) on :8001 outside docker (API_KEY or MCP_API_KEY in .env).
api: .env
	uv run --env-file .env uvicorn reachable_api.main:app --port $${API_PORT:-8001}

## The web UI (S6) on :3000. Needs apps/web/.env.local with REACHABLE_API_URL and
## REACHABLE_API_KEY (copy apps/web/.env.example); the key stays on the server.
web-install:
	npm --prefix apps/web install

web:
	npm --prefix apps/web run dev

## Proxy unit tests, a production build, and a scan proving the key is in no client file.
web-test:
	npm --prefix apps/web run test
	npm --prefix apps/web run test:bundle

## Playwright smoke against the running backend (replay: no model calls).
e2e:
	npm --prefix apps/web run test:e2e

logs:
	docker compose logs -f --tail=100

## Print the FalkorDB Browser URL.
browser:
	@echo "FalkorDB Browser: http://localhost:$${FALKORDB_BROWSER_PORT:-3001}"
