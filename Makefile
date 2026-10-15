# Reachable dev tasks. Recipes call Python for anything non-trivial, so they
# behave the same under bash, macOS and Windows (GNU make + PowerShell/cmd).

SEED  ?= 42
SCALE ?= 1.0
PY      = uv run python
INTEL   = $(PY) -m reachable_intel
ORGGEN  = $(PY) -m reachable_orggen
GRAPH   = $(PY) -m reachable_graph

.PHONY: up down intel seed derive test reset lint fmt sample logs browser mcp mcp-http mcp-smoke gate-a triage

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
seed: .env
	$(ORGGEN) seed --seed $(SEED) --scale $(SCALE)

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
	$(PY) -m reachable_agents triage --org $(ORG) --scan $(SCAN) $(if $(FAKE),--fake) $(if $(AS_OF),--as-of $(AS_OF))

logs:
	docker compose logs -f --tail=100

## Print the FalkorDB Browser URL.
browser:
	@echo "FalkorDB Browser: http://localhost:$${FALKORDB_BROWSER_PORT:-3001}"
