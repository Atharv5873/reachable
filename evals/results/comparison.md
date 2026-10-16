# Comparison eval: five prioritisers, one oracle

Generated 2026-10-16T04:38:37+00:00 by `make eval`. Model for the three LLM prioritisers: `gemini/gemini-3.5-flash-lite` (temperature 0, provider seeds [1, 2, 3]). Dataset seed 42. K = 10. Every number below is recomputed from `evals/results/raw/` plus the labels by `python -m reachable_eval score`.

Scans: v1 of org_a / org_b / org_c (the scans the harness was developed against) and **held-out v2** of each (the week-later rescan, never looked at while building it).

## Overall (all six scans; mean ± sd over seeds)

| prioritiser | NDCG@10 | P@10 | path recall@10 | decoys@10 (lower better) | paths cut / fix | LLM calls / run | tokens in+out / run | $ / run | s / run (active) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| severity_sort | 0.00 | 0% | 0% | 0% | 0.00 | 0.0 | 0 | $0.0000 | 0.0 |
| smart_score | 0.00 | 0% | 0% | 33% | 0.00 | 0.0 | 0 | $0.0000 | 0.0 |
| vector_rag | 0.04 ±0.01 | 2% ±1 | 3% ±1 | 0% | 0.14 ±0.04 | 5.6 ±0.6 | 34,370 | $0.0111 | 23.1 ±12.3 |
| sql_agent | 0.03 ±0.04 | 2% ±3 | 4% ±6 | 0% | 0.09 ±0.13 | 6.0 | 25,243 | $0.0101 | 16.9 ±12.1 |
| **reachable** | 1.00 | 87% | 100% | 0% | 1.16 | 2.4 ±0.5 | 14,660 | $0.0058 | 6.0 ±1.6 |
| *oracle order* | 1.00 | 87% | 96% | 0% | 1.16 | - | - | - | - |

*oracle order* ranks by the oracle's own priority: the ceiling for NDCG and P@10 (P@10's is below 100% where a scan has fewer than 10 relevant findings: org_b has 7), but not for path recall, which a list can max out without following priority order (priority ties leave org_a's top 10 one path short). *s / run (active)* is wall time minus the seconds spent waiting on the Gemini key's rate limit (raw files keep both). *paths cut / fix* uses the prioritiser's own fix set when it gave one, else its top M findings with M = the oracle min-cut size; the oracle row uses the oracle's min cut.

## Development scans (v1) vs held-out scans (v2)

| prioritiser | NDCG@10 v1 | NDCG@10 v2 | path recall@10 v1 | path recall@10 v2 | decoys@10 v1 | decoys@10 v2 |
| --- | --- | --- | --- | --- | --- | --- |
| severity_sort | 0.00 | 0.00 | 0% | 0% | 0% | 0% |
| smart_score | 0.00 | 0.00 | 0% | 0% | 33% | 33% |
| vector_rag | 0.02 ±0.02 | 0.06 ±0.04 | 1% ±2 | 4% ±3 | 0% | 0% |
| sql_agent | 0.02 ±0.03 | 0.03 ±0.04 | 3% ±4 | 6% ±8 | 0% | 0% |
| reachable | 1.00 | 1.00 | 100% | 100% | 0% | 0% |

## Per scan (mean over seeds)

| scan | prioritiser | NDCG@10 | P@10 | path recall@10 | decoys@10 | fix: cut / size |
| --- | --- | --- | --- | --- | --- | --- |
| org_a | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 7.0 |
| org_a | smart_score | 0.00 | 0% | 0% | 33% | 0% / 7.0 |
| org_a | vector_rag | 0.05 ±0.07 | 3% ±5 | 4% ±5 | 0% | 4% ±5 / 4.3 ±3.4 |
| org_a | sql_agent | 0.05 ±0.07 | 3% ±5 | 4% ±5 | 0% | 4% ±5 / 5.7 ±6.6 |
| org_a | reachable | 1.00 | 100% | 100% | 0% | 100% / 7.0 |
| org_a | *oracle order* | 1.00 | 100% | 89% | 0% | 14 relevant, 9 paths, cut 7 |
| org_b | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 4.0 |
| org_b | smart_score | 0.00 | 0% | 0% | 33% | 0% / 4.0 |
| org_b | vector_rag | 0.00 | 0% | 0% | 0% | 0% / 1.0 |
| org_b | sql_agent | 0.00 | 0% | 0% | 0% | 0% / 1.3 ±0.5 |
| org_b | reachable | 1.00 | 70% | 100% | 0% | 100% / 4.0 |
| org_b | *oracle order* | 1.00 | 70% | 100% | 0% | 7 relevant, 4 paths, cut 4 |
| org_c | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 5.0 |
| org_c | smart_score | 0.00 | 0% | 0% | 33% | 0% / 5.0 |
| org_c | vector_rag | 0.00 | 0% | 0% | 0% | 0% / 2.7 ±1.7 |
| org_c | sql_agent | 0.02 ±0.03 | 3% ±5 | 6% ±8 | 0% | 6% ±8 / 7.3 ±6.3 |
| org_c | reachable | 1.00 | 90% | 100% | 0% | 100% / 5.0 |
| org_c | *oracle order* | 1.00 | 90% | 100% | 0% | 9 relevant, 6 paths, cut 5 |
| org_a_v2 | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 7.0 |
| org_a_v2 | smart_score | 0.00 | 0% | 0% | 33% | 0% / 7.0 |
| org_a_v2 | vector_rag | 0.08 ±0.12 | 7% ±9 | 4% ±5 | 0% | 4% ±5 / 2.3 ±1.2 |
| org_a_v2 | sql_agent | 0.00 | 0% | 0% | 0% | 0% / 2.0 ±0.8 |
| org_a_v2 | reachable | 1.00 | 100% | 100% | 0% | 100% / 7.0 |
| org_a_v2 | *oracle order* | 1.00 | 100% | 89% | 0% | 14 relevant, 9 paths, cut 7 |
| org_b_v2 | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 4.0 |
| org_b_v2 | smart_score | 0.00 | 0% | 0% | 33% | 0% / 4.0 |
| org_b_v2 | vector_rag | 0.09 ±0.13 | 3% ±5 | 8% ±12 | 0% | 8% ±12 / 1.0 |
| org_b_v2 | sql_agent | 0.09 ±0.12 | 7% ±9 | 17% ±24 | 0% | 17% ±24 / 2.0 ±1.4 |
| org_b_v2 | reachable | 1.00 | 70% | 100% | 0% | 100% / 4.0 |
| org_b_v2 | *oracle order* | 1.00 | 70% | 100% | 0% | 7 relevant, 4 paths, cut 4 |
| org_c_v2 | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 5.0 |
| org_c_v2 | smart_score | 0.00 | 0% | 0% | 33% | 0% / 5.0 |
| org_c_v2 | vector_rag | 0.00 | 0% | 0% | 0% | 0% / 3.7 ±1.9 |
| org_c_v2 | sql_agent | 0.00 | 0% | 0% | 0% | 6% ±8 / 9.7 ±6.9 |
| org_c_v2 | reachable | 1.00 | 90% | 100% | 0% | 100% / 5.0 |
| org_c_v2 | *oracle order* | 1.00 | 90% | 100% | 0% | 9 relevant, 6 paths, cut 5 |

## Where reachable does not win

- No headline metric, on any scan or split.
- Cost and latency: reachable (like the other two LLM prioritisers) costs model calls and seconds; severity_sort and smart_score cost nothing and answer in milliseconds.

### What changed in S8, and the before/after

S7 left three reachable gaps, all agent behaviour on top of a correct graph answer. S8 closed them with a **ranking step the run makes after the model answers** (`graph_finalise` in `reachable.py`), the same thing the product's run does, through the same toolbox the model has (so the graph-off ablation gets nothing from it):

1. **Order by path-criticality** (`reachable_graph/criticality.py`). A finding's rank is the sensitivity-weighted number of distinct Internet -> crown-jewel paths its step lies on; ties go first to a finding on a route the list has not covered yet, then to the likelier path, then Internet-facing, then a hash. `scan_findings` now sorts by it, and the step puts every on-path finding first in that order, then the model's other picks. Computed from FalkorDB's paths at runtime; nothing reads labels (`test_eval_leakage.py` checks the imports and strings of every signal module, and runs the step with the label files unreadable).
2. **Fill the head from the graph.** The truncation was not `max_tokens`: the short runs used 487-744 of 4,096 output tokens and stopped with a final answer, after naming exactly the 7 findings `min_cut` had shown. The model still does this (it named 5-9 findings per run in S8, 7 in all three org_a_v2 seeds); the step fills the head with every on-path finding.
3. **Fix plan = min_cut's set** (fewest; the cheapest cut when it has as few), proved by `simulate_fix`; the model's tokens are added only if a crown jewel stayed reachable (never needed: 18/18 verified, 0 expanded). The model's own set was larger than min_cut's in 2 of 18 runs (org_c: 6 vs 5).

| reachable (18 runs, seeds 1-3) | S7 | S8 | oracle order |
|---|---|---|---|
| NDCG@10, all scans | 0.82 ±0.03 | **1.00** ±0 | 1.00 |
| NDCG@10, held-out v2 | 0.81 ±0.03 | **1.00** ±0 | 1.00 |
| P@10 | 78% ±3 | **87%** ±0 | 87% |
| P@10, org_a_v2 | 80% ±14 | **100%** ±0 | 100% |
| path recall@10 | 100% | 100% | 96% |
| decoys@10 | 0% | 0% | 0% |
| paths cut / fix | 1.09 ±0.03 | **1.16** | 1.16 |
| $ / run, LLM calls / run | $0.0063, 2.5 | $0.0058, 2.4 | - |

The run's own calls (scan_findings, min_cut x2, simulate_fix) add 4 tool calls a run (7.2 in all vs 3.3 in S7); they are outside the model's budget, which stays identical for all three LLM prioritisers. Ablation (org_a v1, seeds 1-3): graph on 100% / 1.00, graph off 0% / 0.00.

### How to read 1.00 (and why it is not overfitting)

- **It is close to by construction, and we say so.** The oracle's relevance is "how many crown-jewel paths a finding lies on, weighted by target sensitivity". The new signal measures the same thing, because that is what "fix first" means. The two are computed independently: the oracle by networkx over the generator's raw dataset (S1), the signal by FalkorDB over the derived ATTACK_STEP layer at runtime (S2). They agree because the derivation reproduces the oracle's paths (Gate A), not because one reads the other.
- **Nothing was tuned.** The ordering keys were fixed before the re-run, from the definition of the job, and nothing was changed after seeing its result. The one choice that matters here, breaking criticality ties by uncovered route, was made knowing S7's published table: the oracle's own order leaves org_a's top 10 one path short (89% path recall), and plain criticality order would have done the same. It is a rule about the objective (close as many distinct routes as possible), not a fit to label values.
- **Held out moved with development.** v2 went 0.81 -> 1.00 like v1 (0.82 -> 1.00), including org_a_v2's new path, which no prompt or rule was written against.
- **What it does not show.** Every crown jewel here has the same sensitivity, so the weighting is never exercised; and NDCG@10 is now at the ceiling for reachable, so this dataset can no longer tell a better ranker from this one. The next honest test is a differently generated estate, not this one.

### Remaining gaps

- **Cost and latency (baselines win).** severity_sort and smart_score are free and instant. reachable is about $0.006 and 6 s a run (2.4 model calls, 7.2 tool calls). Still the cheapest LLM prioritiser (vector_rag $0.011, sql_agent $0.010).
- **The model's own list is still short.** It names 5-9 findings; the graph step makes that harmless, but the model's head alone would still under-fill.
- **Hallucinated ids, rarely.** In org_b_v2 seed 3 the model invented an ATTACK_STEP key for `why_step`, in S7 and again in S8 (`local_privesc|...06525|asset:01627|asset:01628`); the tool refused it and the run went on. In S8 org_a seed 2 the model also named `org_a:finding:06856chno` (a garbled id): it was dropped and counted as invalid (1 in 18 runs; 0 in S7), and the real 06856 was ranked first by the graph step anyway.

### Why the baselines score what they score

- **severity_sort: 0 everywhere.** Each scan has more than 3,000 open findings at CVSS 9.0+, and 12 of org_a's 14 relevant findings are 7.5 or lower, so none reach the top 10.
- **smart_score: 0, plus a decoy in every top 10.** Its top ranks are Internet-facing load balancers with KEV 9.8 findings that lead nowhere. The planted dead-end decoy is one of them (decoys@10 = 1 of 3 = 33% on every scan). The best relevant finding sits at rank 13 (org_c) and 19 (org_a). Exposure is a property of one node; reachability is a property of paths.
- **vector_rag: 3% path recall.** About 4.6 searches a run, 0 errors, but it names 1.7 findings a run, often copied from the scanner's top-25 list in the CONTEXT. Similar text is not connected text: each hop of a path is a fresh search among ~8,600 documents.
- **sql_agent: 4% path recall.** The run is turn-bound: one query per turn, about 5 queries before the 6-turn cap forces an answer, 17 SQL errors across 18 runs, mostly spent learning the schema. Recursive SQL could walk the edges, but only by re-deriving the attack rules inside one query.
- **A generator artefact helps the text baselines, not us.** Planted hosts have kinds that background hosts rarely have (`web_server`, `db_host`). A text baseline that searches or filters on those kinds gets a hint a real estate would not give. If anything, this inflates their few hits.
- **The oracle order is not the path-recall ceiling.** On org_a, sorting by priority gives 89% path recall@10, while reachable gets 100%. Priority ties stack findings of the same paths, and reachable spreads its top 10 across all 9 paths.

## Variance

| prioritiser | runs | NDCG@10 (min-max over seeds) | path recall@10 (min-max) | model answered | invalid ids / run |
| --- | --- | --- | --- | --- | --- |
| severity_sort | 6 | 0.000-0.000 | 0%-0% | - | 0.0 |
| smart_score | 6 | 0.000-0.000 | 0%-0% | - | 0.0 |
| vector_rag | 18 | 0.025-0.046 | 2%-4% | 18/18 | 0.0 |
| sql_agent | 18 | 0.000-0.077 | 0%-13% | 18/18 | 0.0 |
| reachable | 18 | 1.000-1.000 | 100%-100% | 18/18 | 0.1 ±0.2 |

## Spend

Matrix: 253 LLM calls, 1,297,643 input + 39,286 output tokens, $0.4875 (includes vector_rag's query embeddings). RAG index build: 0 embedding tokens, $0.0000 (cached on disk after the first build).

## Method

- One finding universe per scan: its open findings (`universe.sha` in every raw file).
- LLM prioritisers name up to 20 findings; the rest of their order is the same severity tail (CVSS desc, hash tie-break). Ids that are not open findings are dropped and counted (`invalid ids`).
- Same model, temperature, system prompt, CONTEXT, output schema, 6 turns, 8 model calls, 24 tool calls and 6,000-char tool results for all three; only the toolbox differs (pgvector search / read-only SQL / FalkorDB tools over MCP).
- Baselines read the eval views only (no company layer, no memory, no label or path field); `tests/test_eval_leakage.py` proves it.
- See `learning/S07.md` for what each metric measures and why.
