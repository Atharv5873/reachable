# Comparison eval: five prioritisers, one oracle

Generated 2026-10-16T05:36:25+00:00 by `make eval`. Model for the three LLM prioritisers: `gemini/gemini-3.5-flash-lite` (temperature 0, provider seeds [1]). Dataset seed 42. K = 10. Every number below is recomputed from `evals/results/raw/` plus the labels by `python -m reachable_eval score`.

Scans: v1 of org_a / org_b / org_c (the scans the harness was developed against) and **held-out v2** of each (the week-later rescan, never looked at while building it).

## 1. Structural metrics (all six scans; mean ± sd over seeds)

Did the top 10 cover the real attack paths, stay off the decoys, and come with a fix set that cuts the paths? None of these depends on how the oracle weights priority, so none can be won by sharing its definition.

| prioritiser | path recall@10 | decoys@10 (lower better) | paths cut / fix | fix set cuts (share of paths) |
| --- | --- | --- | --- | --- |
| severity_sort | 0% | 0% | 0.00 | 0% |
| smart_score | 0% | 33% | 0.00 | 0% |
| vector_rag | 0% | 0% | 0.00 | 0% |
| sql_agent | 10% | 11% | 0.30 | 10% |
| **reachable** | 100% | 0% | 1.16 | 100% |
| *oracle* | 100% | 0% | 1.16 | 100% |

*path recall@10*: the share of planted attack paths with at least one of their findings in the top 10. *decoys@10*: the share of the three planted decoys (a critical KEV with no route, a WAF-mitigated critical, an exposed dead end) ranked in the top 10. *paths cut / fix*: paths cut by the prioritiser's own fix set (else its top M findings, M = the oracle min-cut size) per fix; the *oracle* row is the oracle's min cut, which cuts every path with the fewest fixes. The oracle row's path recall is its priority order's (not a ceiling: a list can cover every path without following priority order).

**Ablation** (org_a v1, `evals/results/ablation.md`): the same reachable agent with every graph tool answering "unavailable": path recall@10 100% -> 0%, fix set cuts 100% -> 0%, NDCG@10 1.00 -> 0.00. Same model, prompt and budget: the graph supplies the answer, not the model.

## 2. Agreement with the oracle's priority (secondary)

**Caveat.** reachable's ranker and the ground truth both define importance as reachability to the crown jewels (weighted by each target's sensitivity tier), so agreement between them is expected, not a discovery. The informative comparison is reachable vs the reachability-blind baselines, and the ablation isolates the graph's contribution.

| prioritiser | NDCG@10 | P@10 | NDCG@10 v1 | NDCG@10 v2 (held out) |
| --- | --- | --- | --- | --- |
| severity_sort | 0.00 | 0% | 0.00 | 0.00 |
| smart_score | 0.00 | 0% | 0.00 | 0.00 |
| vector_rag | 0.00 | 0% | 0.00 | 0.00 |
| sql_agent | 0.08 | 8% | 0.04 | 0.12 |
| **reachable** | 1.00 | 87% | 1.00 | 1.00 |
| *oracle order* | 1.00 | 87% | - | - |

Relevance is the oracle's priority: the sum, over the crown-jewel paths a finding lies on, of the target's tier weight (critical 1.0, high 0.6, medium 0.3; S9), normalised per scan. Every org has crown jewels of two or three tiers, so the ideal order is a real gradient (not just on-path vs off-path). P@10's ceiling is below 100% where a scan has fewer than 10 relevant findings (org_b has 7, org_c 9).

## 3. Cost and latency

| prioritiser | LLM calls / run | tokens in+out / run | $ / run | s / run (active) |
| --- | --- | --- | --- | --- |
| severity_sort | 0.0 | 0 | $0.0000 | 0.0 ±0.0 |
| smart_score | 0.0 | 0 | $0.0000 | 0.0 ±0.0 |
| vector_rag | 4.8 ±1.1 | 36,969 | $0.0123 | 10.9 ±5.8 |
| sql_agent | 6.0 | 27,756 | $0.0116 | 15.4 ±3.6 |
| **reachable** | 2.5 ±0.8 | 17,132 | $0.0068 | 8.8 ±3.8 |

*s / run (active)* is wall time minus the seconds spent waiting on the Gemini key's rate limit (raw files keep both).

## Development scans (v1) vs held-out scans (v2): structural

| prioritiser | path recall@10 v1 | path recall@10 v2 | decoys@10 v1 | decoys@10 v2 | paths cut / fix v1 | paths cut / fix v2 |
| --- | --- | --- | --- | --- | --- | --- |
| severity_sort | 0% | 0% | 0% | 0% | 0.00 | 0.00 |
| smart_score | 0% | 0% | 33% | 33% | 0.00 | 0.00 |
| vector_rag | 0% | 0% | 0% | 0% | 0.00 | 0.00 |
| sql_agent | 4% | 17% | 0% | 22% | 0.33 | 0.27 |
| reachable | 100% | 100% | 0% | 0% | 1.16 | 1.16 |

## Per scan (mean over seeds)

| scan | prioritiser | path recall@10 | decoys@10 | fix: cut / size | NDCG@10 | P@10 |
| --- | --- | --- | --- | --- | --- | --- |
| org_a | severity_sort | 0% | 0% | 0% / 7.0 | 0.00 | 0% |
| org_a | smart_score | 0% | 33% | 0% / 7.0 | 0.00 | 0% |
| org_a | vector_rag | 0% | 0% | 0% / 1.0 | 0.00 | 0% |
| org_a | sql_agent | 11% | 0% | 11% / 1.0 | 0.11 | 10% |
| org_a | reachable | 100% | 0% | 100% / 7.0 | 1.00 | 100% |
| org_a | *oracle order* | 100% | 0% | 14 relevant, 9 paths, cut 7 | 1.00 | 100% |
| org_b | severity_sort | 0% | 0% | 0% / 4.0 | 0.00 | 0% |
| org_b | smart_score | 0% | 33% | 0% / 4.0 | 0.00 | 0% |
| org_b | vector_rag | 0% | 0% | 0% / 1.0 | 0.00 | 0% |
| org_b | sql_agent | 0% | 0% | 0% / 20.0 | 0.00 | 0% |
| org_b | reachable | 100% | 0% | 100% / 4.0 | 1.00 | 70% |
| org_b | *oracle order* | 100% | 0% | 7 relevant, 4 paths, cut 4 | 1.00 | 70% |
| org_c | severity_sort | 0% | 0% | 0% / 5.0 | 0.00 | 0% |
| org_c | smart_score | 0% | 33% | 0% / 5.0 | 0.00 | 0% |
| org_c | vector_rag | 0% | 0% | 0% / 1.0 | 0.00 | 0% |
| org_c | sql_agent | 0% | 0% | 0% / 1.0 | 0.00 | 0% |
| org_c | reachable | 100% | 0% | 100% / 5.0 | 1.00 | 90% |
| org_c | *oracle order* | 100% | 0% | 9 relevant, 6 paths, cut 5 | 1.00 | 90% |
| org_a_v2 | severity_sort | 0% | 0% | 0% / 7.0 | 0.00 | 0% |
| org_a_v2 | smart_score | 0% | 33% | 0% / 7.0 | 0.00 | 0% |
| org_a_v2 | vector_rag | 0% | 0% | 0% / 5.0 | 0.00 | 0% |
| org_a_v2 | sql_agent | 33% | 0% | 33% / 4.0 | 0.29 | 30% |
| org_a_v2 | reachable | 100% | 0% | 100% / 7.0 | 1.00 | 100% |
| org_a_v2 | *oracle order* | 100% | 0% | 14 relevant, 9 paths, cut 7 | 1.00 | 100% |
| org_b_v2 | severity_sort | 0% | 0% | 0% / 4.0 | 0.00 | 0% |
| org_b_v2 | smart_score | 0% | 33% | 0% / 4.0 | 0.00 | 0% |
| org_b_v2 | vector_rag | 0% | 0% | 0% / 1.0 | 0.00 | 0% |
| org_b_v2 | sql_agent | 0% | 0% | 0% / 1.0 | 0.00 | 0% |
| org_b_v2 | reachable | 100% | 0% | 100% / 4.0 | 1.00 | 70% |
| org_b_v2 | *oracle order* | 100% | 0% | 7 relevant, 4 paths, cut 4 | 1.00 | 70% |
| org_c_v2 | severity_sort | 0% | 0% | 0% / 5.0 | 0.00 | 0% |
| org_c_v2 | smart_score | 0% | 33% | 0% / 5.0 | 0.00 | 0% |
| org_c_v2 | vector_rag | 0% | 0% | 0% / 1.0 | 0.00 | 0% |
| org_c_v2 | sql_agent | 17% | 67% | 17% / 18.0 | 0.08 | 10% |
| org_c_v2 | reachable | 100% | 0% | 100% / 5.0 | 1.00 | 90% |
| org_c_v2 | *oracle order* | 100% | 0% | 9 relevant, 6 paths, cut 5 | 1.00 | 90% |

## Where reachable does not win

- No headline metric, on any scan or split.
- Cost and latency: reachable (like the other two LLM prioritisers) costs model calls and seconds; severity_sort and smart_score cost nothing and answer in milliseconds.

### On the NDCG result

reachable's NDCG@10 is 1.00, and we do not lead with it. Its ranker and the oracle's ground truth define importance the same way: a finding matters in proportion to the number of Internet -> crown-jewel paths it lies on, weighted by the target's sensitivity tier. They are computed independently (the oracle by networkx over the generator's raw dataset; the ranker by FalkorDB over the derived ATTACK_STEP layer at runtime, with no access to labels: `test_eval_leakage.py`), so 1.00 does check that the derivation is right. It is not a discovery, though. The evidence that carries the claim is structural: the top 10 covers every planted path (100% vs 0-10% for the reachability-blind baselines), avoids every decoy (smart_score puts one in every top 10), and comes with a fix set that cuts every path at the oracle's minimum (1.16 paths per fix vs 0-0.30). And the ablation: the same agent with the graph tools switched off falls from 100% to 0% path recall. The graph supplies the priority; the model does not.

### What S9 changed

S8 ended with every crown jewel at the same sensitivity, so 13 of org_a's 14 relevant findings tied and NDCG only measured "on a path or not". S9 gives each org crown jewels of two or three tiers (critical 1.0, high 0.6, medium 0.3 in the oracle), assigned per route from its story before this re-run, and changes nothing else: the attack paths and the min cut are identical to S8's (`tests/test_sensitivity.py` pins the pre-S9 fingerprints; Gate A's recall, path counts, min-cut sizes, max flows and sets are unchanged). The baselines no longer see the tier (the eval views drop `datastores.sensitivity`); they still see which stores are crown jewels.

| reachable | S8 (3 seeds, one tier) | S9 (1 seed, 2-3 tiers per org) |
|---|---|---|
| path recall@10 | 100% | 100% |
| decoys@10 | 0% | 0% |
| paths cut / fix (oracle 1.16) | 1.16 | 1.16 |
| fix set cuts every path | 100% | 100% |
| NDCG@10 (all / held-out v2) | 1.00 / 1.00 | 1.00 / 1.00 |
| P@10 (ceiling 87%) | 87% | 87% |
| $ / run, LLM calls / run | $0.0058, 2.4 | $0.0068, 2.5 |
| ablation, graph off (path recall / NDCG) | 0% / 0.00 | 0% / 0.00 |

- **1.00 now means more than it did.** With tiers, the ideal order is a real gradient inside the top 10. Run offline over the oracle's paths, the same path-criticality ranker with the tier weights ignored scores NDCG@10 0.95 (org_c 0.91, org_b 0.97, org_a 0.97); with them, 1.00. So the ranker is now being tested on the sensitivity gradient, not just on/off-path, and it passes. The gap is small because a tier only reorders findings that are all relevant already.
- **The ranker's tier weights are not the oracle's** (1.0 / 0.7 / 0.4 in `criticality.py`, fixed in S8, vs 1.0 / 0.6 / 0.3). Neither was changed. They agree on every ordering in this data; they would disagree on three medium-tier routes through one finding vs one critical route, and we would report that loss.
- **Data-design constraint, stated.** org_a has 14 on-path findings for 9 routes; a lower tier on a route with one or two findings would push them below rank 10 of the oracle's own order and make path recall@10 < 100% by definition. Its lower tier therefore sits on the routes with the most findings (the CI funnel and the IMDS route). Written next to `ROUTE_TIER` in `planters.py`.
- **One seed.** The headline is one provider seed (`SEEDS="1 2 3" make eval` for the spread, about 3x the cost). reachable had zero spread over three seeds in S8; the LLM baselines did not, so their single-seed numbers move (below).

### Why the baselines score what they score

- **severity_sort: 0 everywhere.** Each scan has more than 3,000 open findings at CVSS 9.0+, and 12 of org_a's 14 relevant findings are 7.5 or lower, so none reach the top 10.
- **smart_score: 0, plus a decoy in every top 10.** Its top ranks are Internet-facing load balancers with KEV 9.8 findings that lead nowhere; the planted dead-end decoy is one of them (decoys@10 = 33% on every scan). Exposure is a property of one node; reachability is a property of paths.
- **vector_rag: 0% (S8, 3 seeds: 3%).** It named one finding in 4 of 6 runs, usually from the scanner's top list in the CONTEXT. Similar text is not connected text: each hop of a path is a fresh search among ~8,600 documents.
- **sql_agent: 10% (S8, 3 seeds: 4%), and a decoy rate for the first time.** Its hits come from SQL that walks one or two hops back from the crown jewels: on org_a_v2 it joined `datastores` (crown_jewel) -> `edges` (UNLOCKS, CAN, ASSUMES) -> the assets holding those secrets or roles, and named the exposed findings on three of them (3 of 9 paths). That is partial reachability done by hand, and it is the only thing that scores. On org_c_v2 it named 18 findings and two of them were decoys (67%). This is one seed; S8's three-seed spread for it was ±6 points.
- **A generator artefact helps the text baselines, not us.** Planted hosts have kinds background hosts rarely have (`web_server`, `db_host`); a baseline that filters on them gets a hint a real estate would not give.
- **Hiding the tier does not explain their scores.** It can only affect the order inside their top 10; their path recall is low because they do not find the routes at all.

### Remaining gaps

- **Cost and latency (baselines win).** severity_sort and smart_score are free and instant. reachable is about $0.007 and 9 s of active time a run (2.5 model calls). Still the cheapest LLM prioritiser (vector_rag $0.012, sql_agent $0.012).
- **The model's own list is still short.** The model named 7-14 findings; S8's graph step fills the head from the graph, so this is harmless, but the model alone would under-fill.
- **Synthetic data is the limit.** Every number here is on three generated estates. A differently generated estate is the next honest test.

## Variance

| prioritiser | runs | NDCG@10 (min-max over seeds) | path recall@10 (min-max) | model answered | invalid ids / run |
| --- | --- | --- | --- | --- | --- |
| severity_sort | 6 | 0.000-0.000 | 0%-0% | - | 0.0 |
| smart_score | 6 | 0.000-0.000 | 0%-0% | - | 0.0 |
| vector_rag | 6 | 0.000-0.000 | 0%-0% | 6/6 | 0.0 |
| sql_agent | 6 | 0.081-0.081 | 10%-10% | 6/6 | 0.0 |
| reachable | 6 | 1.000-1.000 | 100%-100% | 6/6 | 0.0 |

## Spend

Matrix: 80 LLM calls, 474,591 input + 16,549 output tokens, $0.1838 (includes vector_rag's query embeddings). RAG index build: 638 embedding tokens, $0.0000 (cached on disk after the first build).

## Method

- One finding universe per scan: its open findings (`universe.sha` in every raw file).
- LLM prioritisers name up to 20 findings; the rest of their order is the same severity tail (CVSS desc, hash tie-break). Ids that are not open findings are dropped and counted (`invalid ids`).
- Same model, temperature, system prompt, CONTEXT, output schema, 6 turns, 8 model calls, 24 tool calls and 6,000-char tool results for all three; only the toolbox differs (pgvector search / read-only SQL / FalkorDB tools over MCP).
- Baselines read the eval views only (no company layer, no memory, no label or path field); `tests/test_eval_leakage.py` proves it.
- Baselines see which data stores are crown jewels, not their sensitivity tier (S9: the views drop `datastores.sensitivity`; reachable reads it from the graph).
- See `learning/S07.md` for what each metric measures and why, `learning/S09.md` for why the structural metrics lead.
