# Reachable

Triage security-scanner findings by **what an attacker can actually reach**.

Reachable puts a company's infrastructure in a graph — assets and network
reachability, software and vulnerabilities, identities/permissions/secrets, and
crown-jewel data stores — alongside real public threat intelligence (CISA KEV,
FIRST EPSS, NVD, MITRE ATT&CK®). Agents then find real attack paths from the
Internet to crown jewels, and the minimum set of fixes that cuts them all.

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
make seed                     # generate + load the 3 orgs, write ground-truth labels
make test                     # unit + integration tests
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
  apps/api/            FastAPI /health (placeholder until S2)
  packages/core/       settings, schema, FalkorDB helpers, attack_rules.py
  packages/intel/      fetch + normalise KEV/EPSS/NVD/ATT&CK; load `threatintel`
  packages/orggen/     synthetic org generator, planters, networkx oracle, loaders
  data/threatintel/    committed filtered snapshot + ATTRIBUTION.md
  data/orgs/           generated (gitignored except a tiny sample)
  tests/               pytest (unit + integration)
  learning/            teaching notes (S01.md)
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

See [`learning/S01.md`](learning/S01.md) for the concepts and 5 Cypher queries to
run now.

## Attack rules

The nine attacker-step rules (precondition → ATT&CK technique) live in
[`packages/core/attack_rules.py`](packages/core/src/reachable_core/attack_rules.py).
Both the oracle and the later Cypher derivation implement this one spec, so they
can't silently disagree.
