# Comparison eval (S7): five prioritisers, one oracle

Generated 2026-10-16T03:56:32+00:00 by `make eval`. Model for the three LLM prioritisers: `gemini/gemini-3.5-flash-lite` (temperature 0, provider seeds [1, 2, 3]). Dataset seed 42. K = 10. Every number below is recomputed from `evals/results/raw/` plus the labels by `python -m reachable_eval score`.

Scans: v1 of org_a / org_b / org_c (the scans the harness was developed against) and **held-out v2** of each (the week-later rescan, never looked at while building it).

## Overall (all six scans; mean ± sd over seeds)

| prioritiser | NDCG@10 | P@10 | path recall@10 | decoys@10 (lower better) | paths cut / fix | LLM calls / run | tokens in+out / run | $ / run | s / run (active) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| severity_sort | 0.00 | 0% | 0% | 0% | 0.00 | 0.0 | 0 | $0.0000 | 0.0 |
| smart_score | 0.00 | 0% | 0% | 33% | 0.00 | 0.0 | 0 | $0.0000 | 0.0 |
| vector_rag | 0.04 ±0.01 | 2% ±1 | 3% ±1 | 0% | 0.14 ±0.04 | 5.6 ±0.6 | 34,370 | $0.0111 | 23.1 ±12.3 |
| sql_agent | 0.03 ±0.04 | 2% ±3 | 4% ±6 | 0% | 0.09 ±0.13 | 6.0 | 25,243 | $0.0101 | 16.9 ±12.1 |
| **reachable** | 0.82 ±0.03 | 78% ±3 | 100% | 0% | 1.09 ±0.03 | 2.5 ±0.5 | 16,083 | $0.0063 | 6.2 ±4.9 |
| *oracle order* | 1.00 | 87% | 96% | 0% | 1.16 | - | - | - | - |

*oracle order* ranks by the oracle's own priority: the ceiling for NDCG and P@10 (P@10's is below 100% where a scan has fewer than 10 relevant findings: org_b has 7), but not for path recall, which a list can max out without following priority order (priority ties leave org_a's top 10 one path short). *s / run (active)* is wall time minus the seconds spent waiting on the Gemini key's rate limit (raw files keep both). *paths cut / fix* uses the prioritiser's own fix set when it gave one, else its top M findings with M = the oracle min-cut size; the oracle row uses the oracle's min cut.

## Development scans (v1) vs held-out scans (v2)

| prioritiser | NDCG@10 v1 | NDCG@10 v2 | path recall@10 v1 | path recall@10 v2 | decoys@10 v1 | decoys@10 v2 |
| --- | --- | --- | --- | --- | --- | --- |
| severity_sort | 0.00 | 0.00 | 0% | 0% | 0% | 0% |
| smart_score | 0.00 | 0.00 | 0% | 0% | 33% | 33% |
| vector_rag | 0.02 ±0.02 | 0.06 ±0.04 | 1% ±2 | 4% ±3 | 0% | 0% |
| sql_agent | 0.02 ±0.03 | 0.03 ±0.04 | 3% ±4 | 6% ±8 | 0% | 0% |
| reachable | 0.82 ±0.03 | 0.81 ±0.03 | 100% | 100% | 0% | 0% |

## Per scan (mean over seeds)

| scan | prioritiser | NDCG@10 | P@10 | path recall@10 | decoys@10 | fix: cut / size |
| --- | --- | --- | --- | --- | --- | --- |
| org_a | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 7.0 |
| org_a | smart_score | 0.00 | 0% | 0% | 33% | 0% / 7.0 |
| org_a | vector_rag | 0.05 ±0.07 | 3% ±5 | 4% ±5 | 0% | 4% ±5 / 4.3 ±3.4 |
| org_a | sql_agent | 0.05 ±0.07 | 3% ±5 | 4% ±5 | 0% | 4% ±5 / 5.7 ±6.6 |
| org_a | reachable | 0.71 ±0.02 | 97% ±5 | 100% | 0% | 100% / 7.0 |
| org_a | *oracle order* | 1.00 | 100% | 89% | 0% | 14 relevant, 9 paths, cut 7 |
| org_b | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 4.0 |
| org_b | smart_score | 0.00 | 0% | 0% | 33% | 0% / 4.0 |
| org_b | vector_rag | 0.00 | 0% | 0% | 0% | 0% / 1.0 |
| org_b | sql_agent | 0.00 | 0% | 0% | 0% | 0% / 1.3 ±0.5 |
| org_b | reachable | 0.94 ±0.09 | 63% ±9 | 100% | 0% | 100% / 4.0 |
| org_b | *oracle order* | 1.00 | 70% | 100% | 0% | 7 relevant, 4 paths, cut 4 |
| org_c | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 5.0 |
| org_c | smart_score | 0.00 | 0% | 0% | 33% | 0% / 5.0 |
| org_c | vector_rag | 0.00 | 0% | 0% | 0% | 0% / 2.7 ±1.7 |
| org_c | sql_agent | 0.02 ±0.03 | 3% ±5 | 6% ±8 | 0% | 6% ±8 / 7.3 ±6.3 |
| org_c | reachable | 0.82 ±0.09 | 80% ±14 | 100% | 0% | 100% / 6.0 ±0.8 |
| org_c | *oracle order* | 1.00 | 90% | 100% | 0% | 9 relevant, 6 paths, cut 5 |
| org_a_v2 | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 7.0 |
| org_a_v2 | smart_score | 0.00 | 0% | 0% | 33% | 0% / 7.0 |
| org_a_v2 | vector_rag | 0.08 ±0.12 | 7% ±9 | 4% ±5 | 0% | 4% ±5 / 2.3 ±1.2 |
| org_a_v2 | sql_agent | 0.00 | 0% | 0% | 0% | 0% / 2.0 ±0.8 |
| org_a_v2 | reachable | 0.67 ±0.02 | 80% ±14 | 100% | 0% | 100% / 7.0 |
| org_a_v2 | *oracle order* | 1.00 | 100% | 89% | 0% | 14 relevant, 9 paths, cut 7 |
| org_b_v2 | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 4.0 |
| org_b_v2 | smart_score | 0.00 | 0% | 0% | 33% | 0% / 4.0 |
| org_b_v2 | vector_rag | 0.09 ±0.13 | 3% ±5 | 8% ±12 | 0% | 8% ±12 / 1.0 |
| org_b_v2 | sql_agent | 0.09 ±0.12 | 7% ±9 | 17% ±24 | 0% | 17% ±24 / 2.0 ±1.4 |
| org_b_v2 | reachable | 0.87 ±0.09 | 57% ±9 | 100% | 0% | 100% / 4.3 ±0.5 |
| org_b_v2 | *oracle order* | 1.00 | 70% | 100% | 0% | 7 relevant, 4 paths, cut 4 |
| org_c_v2 | severity_sort | 0.00 | 0% | 0% | 0% | 0% / 5.0 |
| org_c_v2 | smart_score | 0.00 | 0% | 0% | 33% | 0% / 5.0 |
| org_c_v2 | vector_rag | 0.00 | 0% | 0% | 0% | 0% / 3.7 ±1.9 |
| org_c_v2 | sql_agent | 0.00 | 0% | 0% | 0% | 6% ±8 / 9.7 ±6.9 |
| org_c_v2 | reachable | 0.89 | 90% | 100% | 0% | 100% / 6.3 ±1.9 |
| org_c_v2 | *oracle order* | 1.00 | 90% | 100% | 0% | 9 relevant, 6 paths, cut 5 |

## Where reachable does not win

- No headline metric, on any scan or split.
- Cost and latency: reachable (like the other two LLM prioritisers) costs model calls and seconds; severity_sort and smart_score cost nothing and answer in milliseconds.

### Why, gap by gap (read from the raw outputs)

Nothing beats reachable on a headline metric, so these are the places where it is **short of the oracle** or **loses on something else**, each with the reason found in `raw/`.

- **Cost and latency (baselines win).** severity_sort and smart_score are free and instant. reachable is about $0.006 and 6 s a run (2.5 model calls, 3.3 tool calls). That is still the cheapest of the three LLM prioritisers (vector_rag $0.011, sql_agent $0.010), because one `attack_paths` + `min_cut` call answers what the other two spend every turn hunting for.
- **NDCG@10 is 0.82, not 1.0.** The order inside the top 10 is off. org_a's highest-priority finding (`org_a:finding:06856`, the CI-runner funnel on 3 of 9 paths, priority 1.0) lands at rank 9 or 13, or outside the model's named list. `scan_findings` sorts Internet-facing steps first and the funnel sits on an internal host, so the model reads it late. The *set* is right (P@10 97%, every path represented); the *order* by priority is not. This is a tool-ordering issue, not missing reachability.
- **P@10 on org_a_v2 is 80% ±14.** In seeds 2 and 3 the model named only 7 findings and stopped, and the remaining slots fall to the shared CVSS tail, which holds no relevant findings. The model under-fills, but no path is lost (path recall 100%).
- **Fix efficiency is 1.09 paths per fix vs the oracle's 1.16.** On org_c (and org_b_v2 and org_c_v2 in some seeds) the model sometimes writes its own fix set of one finding per path (6–9 fixes) instead of adopting `min_cut`'s answer (5 fixes, four of them `step:db` credential rotations). Every fix set still cuts 100% of the paths; some are just larger than the minimum. The deterministic product run (S5) always uses `min_cut`'s set; the eval lets the model choose, and this is the cost.
- **One hallucinated tool argument in 54 runs.** In org_b_v2 seed 3 the model invented an ATTACK_STEP key for `why_step`. The tool refused it (`no ATTACK_STEP with key ...`) and the run went on. No id it ranked was invalid (0 invalid ids across the matrix).

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
| reachable | 18 | 0.792-0.855 | 100%-100% | 18/18 | 0.0 |

## Spend

Matrix: 254 LLM calls, 1,322,542 input + 39,988 output tokens, $0.4967 (includes vector_rag's query embeddings). RAG index build: 0 embedding tokens, $0.0000 (cached on disk after the first build).

## Method

- One finding universe per scan: its open findings (`universe.sha` in every raw file).
- LLM prioritisers name up to 20 findings; the rest of their order is the same severity tail (CVSS desc, hash tie-break). Ids that are not open findings are dropped and counted (`invalid ids`).
- Same model, temperature, system prompt, CONTEXT, output schema, 6 turns, 8 model calls, 24 tool calls and 6,000-char tool results for all three; only the toolbox differs (pgvector search / read-only SQL / FalkorDB tools over MCP).
- Baselines read the eval views only (no company layer, no memory, no label or path field); `tests/test_eval_leakage.py` proves it.
- See `learning/S07.md` for what each metric measures and why.
