# Reachable

Triage security-scanner findings by **what an attacker can actually reach**.

Reachable puts a company's infrastructure in a graph — assets and network
reachability, software and vulnerabilities, identities/permissions/secrets, and
crown-jewel data stores — alongside real public threat intelligence (CISA KEV,
FIRST EPSS, NVD, MITRE ATT&CK®). Agents then find real attack paths from the
Internet to crown jewels, and the minimum set of fixes that cuts them all.

The same graph holds the **company layer** (teams, people, on-call, decision
records, tickets: who owns it, why is it exposed, who approved it) and the
agents' **memory** (runs, verdicts, risk acceptances with expiry, learned
patterns, versioned playbooks).

> Entry for **Graph Hacks: Context for AI Agents** (WeMakeDevs × FalkorDB).
> **FalkorDB is the primary datastore and does the real work.** Postgres +
> pgvector exists only as a baseline for later eval stages. All company
> infrastructure, people and findings are **synthetic and fictional**; only the
> threat intelligence is real public data (see
> [`data/threatintel/ATTRIBUTION.md`](data/threatintel/ATTRIBUTION.md)).

## Stack

- Python 3.12 + [uv](https://docs.astral.sh/uv/) workspace, ruff, pytest.
- FalkorDB (`falkordb/falkordb:latest`) — primary graph store, Browser UI on
  `:3001`.
- pgvector Postgres — baseline mirror only.
- FastAPI backend: start a run, stream it live (SSE), read it back, drift, verdicts.
- Next.js 16 web app (`apps/web`): TypeScript, Tailwind 4, shadcn/ui, Cytoscape.js
  (dagre layout); talks to the API only through its own server-side proxy.

Host ports are offset from the defaults (FalkorDB `6380`, Browser `3001`,
Postgres `5434`, API `8001`) so this runs beside other local stacks.

## Quick start

```bash
cp .env.example .env          # set passwords; add NVD_API_KEY (recommended)
make up                       # FalkorDB + Postgres + API, waits until healthy
make intel                    # load the committed threat-intel snapshot
make seed                     # generate + load the 3 orgs, write labels, derive ATTACK_STEP
make test                     # unit + integration tests
make gate-a                   # no-LLM evaluation of the graph tools -> evals/results/
make mcp-smoke                # MCP server: list tools, call three
make triage FAKE=1            # the four agents with a stub model (no keys, no network)
make triage ORG=org_a SCAN=v1 # the four agents with real LLMs (GEMINI/GROQ keys in .env)
make drift ORG=org_a          # the Sentinel: what scan v2 changed for an attacker (no LLM)
make triage ORG=org_a SCAN=v2 # the rescan, with v1's memory (COLD=1: without it)
make verdict RUN=<run id> FINDING=<finding id> DECISION=reject REASON="..."
make memory-lift ORG=org_a    # Gate B: cold vs warm on the rescan -> evals/results/
make api                      # FastAPI + SSE on :8001 (or `docker compose up -d api`)
make web-install && make web  # the UI on http://localhost:3000 (copy apps/web/.env.example to .env.local)
make web-test && make e2e     # proxy tests, client-bundle key scan, Playwright smoke
```

Then open the FalkorDB Browser at <http://localhost:3001> and try the queries in
[`learning/S01.md`](learning/S01.md).

To refetch threat intel from the network instead of using the committed
snapshot (needs `NVD_API_KEY`):

```bash
make intel REFETCH=1
```

## Layout

```
reachable/
  apps/api/            FastAPI: runs, live SSE stream, drift, verdicts (S5); UI views, ask (S6)
  apps/web/            Next.js UI: seven screens, key-injecting proxy, Cytoscape graph (S6)
  apps/mcp/            MCP server (stdio + streamable HTTP) over the graph tools
  packages/core/       settings, schema, FalkorDB helpers, attack_rules.py
  packages/intel/      fetch + normalise KEV/EPSS/NVD/ATT&CK; load `threatintel`
  packages/orggen/     synthetic org generator, planters, networkx oracle, loaders
  packages/graph/      ATTACK_STEP derivation (derive.py), typed read-only tools (tools.py,
                       company_tools.py) and the agent memory repositories (memory.py)
  packages/agents/     LiteLLM router, MCP -> LLM tools, LangGraph agents, Sentinel, CLI
  evals/               Gate A (no-LLM tool evaluation), Gate B (memory lift) + results/
  scripts/             mcp_smoke.py
  data/threatintel/    committed filtered snapshot + ATTRIBUTION.md
  data/orgs/           generated (gitignored except a tiny sample)
  tests/               pytest (unit + integration + property)
  learning/            teaching notes (S01.md ... S06.md)
  runs/                agent run dumps (gitignored; the run itself lives in the graph)
```

## How it fits together

1. **`make intel`** fetches public threat intel, filters it to a committed
   snapshot, and loads a FalkorDB graph `threatintel`
   (`CVE`, `CWE`, `Product`, `Technique`, `Tactic`).
2. **`make seed`** generates three fictional orgs (`org_a` cloud-native SaaS,
   `org_b` retail web, `org_c` hybrid), each its own FalkorDB graph. Real CVE
   ids from the snapshot are denormalised onto `Vuln` nodes in each org graph.
3. **Ground truth** (planted attack paths, decoys, min-cut, finding priority) is
   computed by an independent networkx **oracle** and written to
   `data/orgs/<org>/labels.json` — never loaded into FalkorDB.

4. **`make derive`** (run by `make seed`) materialises the **attack layer**:
   one Cypher query per attack rule MATCHes the rule's precondition and MERGEs an
   `ATTACK_STEP` edge carrying `rule`, ATT&CK `technique`, `likelihood`,
   `cost = -ln(likelihood)`, the `fix_token` that removes it, and `because`
   (the evidence node ids). It also builds a node-split `FLOW` layer for
   `algo.maxFlow` and labels nodes on crown-jewel paths `:CrownPath`.
   A test asserts the derived Internet -> crown-jewel paths equal the oracle's,
   hop for hop and fix token for fix token.
5. **Tools** (`packages/graph/tools.py`, served by `apps/mcp`) answer questions
   with FalkorDB doing the work. All are read-only (`GRAPH.RO_QUERY`), capped,
   and return `{summary, data, evidence, queries, truncated}`:

   | tool | how |
   |---|---|
   | `exposure_surface` | internet-exposed assets + exploitable / control-blocked vulns |
   | `attack_paths` | `algo.SPpaths` over `ATTACK_STEP`, weight = -ln p: the k most likely paths |
   | `blast_radius` | `algo.bfs` from a compromised node |
   | `min_cut` | `algo.maxFlow` on the node-split FLOW layer + residual-graph cut recovery; `mode="fewest"` (count) or `"cheapest"` (effort 1-5 as capacity) |
   | `choke_points` | `algo.betweenness` restricted to `:CrownPath` |
   | `why_step` | one step's rule, technique, fix, and the structural edges behind it |
   | `vuln_intel` | CVSS/EPSS/KEV/ransomware/CWE/ATT&CK from `threatintel` |
   | `simulate_fix` | `GRAPH.COPY` to a scratch graph, drop the fixed steps, re-run paths |
   | `run_cypher_readonly` | logged escape hatch: read-only, forced LIMIT, timeout |
   | `owners` | owning team(s), members, and who is on call now |
   | `decision_trail` | the ADRs that changed an asset (approver, date) + its live exposure |
   | `company_query` | fixed intents: who_owns / who_is_on_call / why_exposed / who_approved / fix_history |
   | `triage_memory` | live vs expired risk acceptances, past verdicts, patterns reaching the findings |
   | `scan_findings` | the scan (version, time), crown jewels, open findings ranked by what they enable |
   | `playbooks` | the versioned playbook in force per ATT&CK technique at `as_of` |
   | `exposure_drift` | diff two scans' Internet -> crown-jewel path sets: new / closed / cost-changed; `new_crown_path` only for a brand-new path |

   A derivation query, for flavour (`exploit_remote_service`, T1210):

   ```cypher
   MATCH (src:Asset)-[r:CAN_REACH]->(dst:Asset)-[:RUNS]->(s:Software)-[:HAS_VULN]->(v:Vuln),
         (f:Finding)-[:ON]->(dst), (f)-[:OF]->(v)
   WHERE v.av IN $network_vectors
     AND (size(s.ports) = 0 OR r.port IN s.ports)
     AND NOT (:Control)-[:MITIGATES {asset: dst.id}]->(v)
   WITH DISTINCT src, dst, f.id AS token, v.likelihood AS lk, [f.id, v.id, s.id] AS because
   MERGE (src)-[e:ATTACK_STEP {key: $rule + '|' + token + '|' + src.id + '|' + dst.id}]->(dst)
   SET e.rule = $rule, e.technique = $technique, e.fix_token = token,
       e.likelihood = lk, e.cost = -log(lk), e.because = because
   ```

6. **Company layer and memory** (S3). The generator also plants teams, people
   (invented names), weekly on-call slots, an ADR for every planted entry point
   and shared funnel, and ticket history; and a little synthetic prior memory.
   At runtime, `reachable_graph/memory.py` is the only code that writes to an
   org graph: fixed, parameterised CREATE/MERGE queries on memory labels only
   (a test proves infrastructure is untouched). Derivation only uses findings
   with `status = 'open'`, so a fixed finding stops being an attack step.

7. **Gate A** (`make gate-a`) grades the tools against the oracle labels with no
   LLM: planted-path recall by difficulty, decoys in top paths, min-cut vs the
   oracle (each cut proven by `simulate_fix`), evidence validity, latency. See
   [`evals/results/gate_a.md`](evals/results/gate_a.md).

8. **Agents** (S4, `packages/agents`): Triage -> Pathfinder -> Fixer -> Reporter as
   a LangGraph StateGraph. Each agent is an LLM shown the MCP tool schemas; it
   **chooses** the tools, every call goes over MCP, and the model's answer is
   grounded against the real tool results (made-up ids, claims and numbers are
   dropped). Agents hand off through the graph: each writes its output on the
   `Run` node and the next reads it back; every tool and model call is an
   `AgentStep` carrying the Cypher it ran. A run reasons at the scan's time
   (`as_of`, from the `Scan` node), never the wall clock. LiteLLM routes Gemini
   Flash -> Groq -> an optional paid reserve, with per-run budgets and a cache.

   ```bash
   python -m reachable_agents check                 # probe each configured model
   make triage ORG=org_a SCAN=v1 [AS_OF=2023-12-01] # writes runs/<run_id>.md + .json
   python -m reachable_agents replay --org org_a --run-id <id>   # re-render from the graph
   ```

   Free tiers are tight (Gemini: 20 requests/day per model; a run is ~12): set
   `LLM_RESERVE_MODEL` + `LLM_RESERVE_API_KEY` for demos. See
   [`learning/S04.md`](learning/S04.md).

9. **Memory that changes behaviour, drift, and a live stream** (S5).
   A v2 run starts with the **Sentinel** (no LLM): it carries the org's memory into
   the rescan's graph, flags arriving findings a learned pattern matches (before
   any path search), diffs the two scans' crown-jewel path sets
   (`exposure_drift`) and raises an `Alert` only for a brand-new crown path.
   Then the agents use the three kinds of memory:

   * **episodic**: a finding whose earlier verdict still stands is carried, not
     re-investigated; the last run's owner routing is reused while the on-call
     slot covers the clock;
   * **semantic**: the Reporter learns "image X was the way in" patterns; the next
     scan's Sentinel flags new hosts built from it on arrival;
   * **procedural**: an analyst's rejected verdict with a reusable reason becomes a
     new playbook version (old one kept, `SUPERSEDES`) whose rule later runs apply.

   Gate B ([`evals/results/memory_lift.md`](evals/results/memory_lift.md)): on the
   same rescan, warm (v1's memory) vs cold (fresh) investigates fewer findings with
   fewer calls and reaches the same verified, minimal fix set. A run is ~26k input
   tokens and 7 LLM calls (S4: ~61k, 12). See [`learning/S05.md`](learning/S05.md).

10. **The UI** (S6, `apps/web`). Seven screens in demo order, every one reading
    the real graph: **01 Findings** (the same findings sorted by CVSS and by
    reachability: a CVSS 5.0 that starts the most likely path ranks #1, a 9.8 KEV
    in quarantine ranks nowhere), **02 Attack paths** (Cytoscape, Internet on the
    left, each edge an ATT&CK technique; click it for the `why_step` evidence),
    **03 Fix plan** (fewest vs cheapest cut, owners, on-call, ADRs, drafted
    tickets, "one fix, many paths"; *Simulate* flips the crown jewels to SAFE),
    **04 Investigation** (the run's steps live over SSE, or replayed from the
    graph at their real pace), **05 Company brain** (English -> one fixed intent),
    **06 Drift** (v1 -> v2: the one new path, what memory recognised, Gate B), and
    **07 Evals**. **Replay** is the default mode: it reads a finished run from the
    graph and never calls a model, which is what the demo video is recorded
    against. The browser never sees the API key: it calls `/api/r/*` on its own
    origin, and a server-only route handler adds the key and relays the SSE
    stream (with `Last-Event-ID`). One colour rule carries the design: ember red
    means "an attacker can get there", and nothing else is red. See
    [`learning/S06.md`](learning/S06.md).

## API

```bash
make api                                    # or: docker compose up -d api   (:8001)
curl -X POST localhost:8001/runs -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
     -d '{"org": "org_a", "scan": "v2"}'    # -> {"run_id": ..., "stream": "/runs/<id>/stream"}
curl -N localhost:8001/runs/<id>/stream -H "X-API-Key: $KEY"   # Server-Sent Events
```

| endpoint | |
|---|---|
| `POST /runs` `{org, scan, fake?, cold?}` | start a run in the background; returns `run_id` |
| `GET /runs/{id}/stream` | SSE: `agent_entered`, `tool_called` (with the Cypher + timing), `llm_called`, `memory`, `drift_checked`, `alert_raised`, `triage_done`, `path_found`, `finding_ranked`, `fix_chosen`, `report_written`, `report_ready`; resumable with `Last-Event-ID` |
| `GET /runs/{id}` | the run read back from the graph (outputs + trace) |
| `POST /runs/{id}/verdict` | an analyst's accept / reject (procedural memory) |
| `GET /orgs`, `GET /orgs/{org}/drift` | orgs, scans, recent runs and alerts; the v1 -> v2 drift |
| `GET /orgs/{org}/findings?scan=&run_id=` | the findings board: scanner order vs reachability order, a reason per row |
| `GET /runs/{id}/subgraph?finding=&context=&max_nodes=` | the run's attack paths + both min cuts as Cytoscape elements (capped) |
| `GET /runs/{id}/fixplan?mode=fewest\|cheapest` | a fix set with owners, on-call, ADRs and drafted tickets |
| `POST /orgs/{org}/simulate`, `GET /orgs/{org}/why_step` | `simulate_fix` on a scratch copy; one step's evidence |
| `POST /orgs/{org}/ask` `{question, mode}` | English -> one fixed `company_query` intent (model, or rules with no model) |
| `GET /evals` | `evals/results/*.json` |

The stream reads the run's trace in the graph; it never talks to the agents, so a
slow or late client never slows a run. At most two agent runs execute at once
(`API_MAX_RUNS`); a third `POST /runs` gets `429` with `Retry-After`. Auth: `Authorization: Bearer <key>` or
`X-API-Key` (`API_KEY`, else `MCP_API_KEY`); `/health` is open.

## MCP server

```bash
make mcp                                   # stdio: point an MCP host at `uv run reachable-mcp`
make mcp-http                              # streamable HTTP on :8002/mcp (MCP_API_KEY in .env)
docker compose up -d mcp                   # same, containerised
make mcp-smoke URL=http://localhost:8002/mcp
```

HTTP requires `Authorization: Bearer $MCP_API_KEY` or `X-API-Key`; `/health` is open.

See [`learning/S01.md`](learning/S01.md), [`learning/S02.md`](learning/S02.md),
[`learning/S03.md`](learning/S03.md), [`learning/S04.md`](learning/S04.md),
[`learning/S05.md`](learning/S05.md) and [`learning/S06.md`](learning/S06.md) for the concepts, the Cypher, the
max-flow / min-cut idea, the company brain and agent memory, and Browser
queries to run now.

## Attack rules

The nine attacker-step rules (precondition → ATT&CK technique) live in
[`packages/core/attack_rules.py`](packages/core/src/reachable_core/attack_rules.py).
Both the oracle and the later Cypher derivation implement this one spec, so they
can't silently disagree.
