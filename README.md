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
- FastAPI `/health` checking both datastores.

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
  apps/api/            FastAPI /health
  apps/mcp/            MCP server (stdio + streamable HTTP) over the graph tools
  packages/core/       settings, schema, FalkorDB helpers, attack_rules.py
  packages/intel/      fetch + normalise KEV/EPSS/NVD/ATT&CK; load `threatintel`
  packages/orggen/     synthetic org generator, planters, networkx oracle, loaders
  packages/graph/      ATTACK_STEP derivation (derive.py), typed read-only tools (tools.py,
                       company_tools.py) and the agent memory repositories (memory.py)
  evals/               Gate A (no-LLM tool evaluation) + results/
  scripts/             mcp_smoke.py
  data/threatintel/    committed filtered snapshot + ATTRIBUTION.md
  data/orgs/           generated (gitignored except a tiny sample)
  tests/               pytest (unit + integration + property)
  learning/            teaching notes (S01.md, S02.md, S03.md)
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

## MCP server

```bash
make mcp                                   # stdio: point an MCP host at `uv run reachable-mcp`
make mcp-http                              # streamable HTTP on :8002/mcp (MCP_API_KEY in .env)
docker compose up -d mcp                   # same, containerised
make mcp-smoke URL=http://localhost:8002/mcp
```

HTTP requires `Authorization: Bearer $MCP_API_KEY` or `X-API-Key`; `/health` is open.

See [`learning/S01.md`](learning/S01.md), [`learning/S02.md`](learning/S02.md)
and [`learning/S03.md`](learning/S03.md) for the concepts, the Cypher, the
max-flow / min-cut idea, the company brain and agent memory, and Browser
queries to run now.

## Attack rules

The nine attacker-step rules (precondition → ATT&CK technique) live in
[`packages/core/attack_rules.py`](packages/core/src/reachable_core/attack_rules.py).
Both the oracle and the later Cypher derivation implement this one spec, so they
can't silently disagree.
