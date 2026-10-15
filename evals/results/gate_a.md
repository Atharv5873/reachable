# Gate A - graph tools vs ground truth (no LLM)

Generated 2026-10-15 15:09:21. attack_paths budget k=10. Latency reps per tool: 20.

## Verdict

| org | recall_easy_medium_1.0 | min_cut_disconnects | min_cut_le_oracle | evidence_100 | no_decoy_in_top_paths |
|---|---|---|---|---|---|
| org_a | PASS | PASS | PASS | PASS | PASS |
| org_b | PASS | PASS | PASS | PASS | PASS |
| org_c | PASS | PASS | PASS | PASS | PASS |

**Overall: PASS**

## Planted-path recall and decoys

| org | easy | medium | hard | hard (from seeds) | precision vs planted | decoy precision | decoys in top paths |
|---|---|---|---|---|---|---|---|
| org_a | 1/1 (1.00) | 1/1 (1.00) | 4/4 (1.00) | 4/4 | 1.00 | 1.00 | 0 |
| org_b | 1/1 (1.00) | 1/1 (1.00) | 2/2 (1.00) | 2/2 | 1.00 | 1.00 | 0 |
| org_c | 1/1 (1.00) | 1/1 (1.00) | 2/2 (1.00) | 2/2 | 1.00 | 1.00 | 0 |

## min_cut vs oracle

| org | prefer | size | max flow | oracle size | size <= oracle | same set as oracle | simulate_fix disconnects all |
|---|---|---|---|---|---|---|---|
| org_a | entry | 6 | 6 | 6 | True | False | True |
| org_a | crown | 6 | 6 | 6 | True | True | True |
| org_b | entry | 4 | 4 | 4 | True | False | True |
| org_b | crown | 4 | 4 | 4 | True | True | True |
| org_c | entry | 4 | 4 | 4 | True | False | True |
| org_c | crown | 4 | 4 | 4 | True | True | True |

## Evidence validity (separate Cypher pass)

| org | nodes checked | edges checked | validity |
|---|---|---|---|
| org_a | 328 | 225 | 1.0000 |
| org_b | 423 | 299 | 1.0000 |
| org_c | 194 | 177 | 1.0000 |

## Latency (ms)

| tool | org_a p50 / p95 | org_b p50 / p95 | org_c p50 / p95 |
|---|---|---|---|
| attack_paths | 16.48 / 17.49 | 47.21 / 49.76 | 68.05 / 71.75 |
| attack_paths (from a seed asset) | 0.57 / 0.78 | 1.0 / 1.29 | 1.76 / 3.01 |
| blast_radius | 2.79 / 3.61 | 5.5 / 8.96 | 6.81 / 9.4 |
| choke_points | 4.82 / 5.59 | 4.08 / 5.45 | 3.9 / 5.19 |
| exposure_surface | 5.05 / 11.75 | 6.63 / 9.25 | 2.44 / 3.61 |
| min_cut | 21.37 / 24.72 | 17.74 / 25.4 | 16.81 / 20.8 |
| run_cypher_readonly | 0.85 / 1.1 | 0.99 / 1.32 | 0.76 / 1.22 |
| simulate_fix | 358.86 / 382.1 | 210.03 / 225.75 | 229.36 / 236.53 |
| vuln_intel | 3.9 / 5.4 | 4.45 / 6.79 | 3.57 / 4.67 |
| why_step | 8.18 / 11.58 | 9.1 / 11.55 | 8.82 / 10.34 |

## Scale check (org_a x3.0)

- 5234 assets, 55833 nodes, 145841 edges -> 91201 ATTACK_STEP edges, 8012 fix tokens
- generate 1.3 s, load 5.5 s, derive 1.77 s
- GRAPH.MEMORY USAGE: 130 MB
- paths found 6, min_cut 6 (disconnects all: True)

Three slowest tools (p95):

- `simulate_fix`: p50 995.39 ms, p95 1060.84 ms
- `exposure_surface`: p50 17.56 ms, p95 110.26 ms
- `min_cut`: p50 43.89 ms, p95 55.3 ms
