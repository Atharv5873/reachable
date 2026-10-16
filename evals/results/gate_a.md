# Gate A - graph tools vs ground truth (no LLM)

Generated 2026-10-16 00:21:58. attack_paths budget k=10. Latency reps per tool: 20.

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
| org_a | 1/1 (1.00) | 1/1 (1.00) | 7/7 (1.00) | 7/7 | 1.00 | 1.00 | 0 |
| org_b | 1/1 (1.00) | 1/1 (1.00) | 2/2 (1.00) | 2/2 | 1.00 | 1.00 | 0 |
| org_c | 1/1 (1.00) | 2/2 (1.00) | 3/3 (1.00) | 3/3 | 1.00 | 1.00 | 0 |

## min_cut vs oracle

| org | prefer | size | max flow | oracle size | size <= oracle | same set as oracle | simulate_fix disconnects all |
|---|---|---|---|---|---|---|---|
| org_a | entry | 7 | 7 | 7 | True | False | True |
| org_a | crown | 7 | 7 | 7 | True | True | True |
| org_b | entry | 4 | 4 | 4 | True | False | True |
| org_b | crown | 4 | 4 | 4 | True | True | True |
| org_c | entry | 5 | 5 | 5 | True | False | True |
| org_c | crown | 5 | 5 | 5 | True | True | True |

## Evidence validity (separate Cypher pass)

| org | nodes checked | edges checked | validity |
|---|---|---|---|
| org_a | 341 | 237 | 1.0000 |
| org_b | 423 | 299 | 1.0000 |
| org_c | 202 | 186 | 1.0000 |

## Latency (ms)

| tool | org_a p50 / p95 | org_b p50 / p95 | org_c p50 / p95 |
|---|---|---|---|
| attack_paths | 17.8 / 20.07 | 49.36 / 51.54 | 70.47 / 73.21 |
| attack_paths (from a seed asset) | 0.91 / 1.18 | 0.49 / 0.86 | 0.81 / 1.76 |
| blast_radius | 2.8 / 3.32 | 4.5 / 7.62 | 4.81 / 5.58 |
| choke_points | 4.66 / 7.94 | 3.67 / 4.48 | 3.61 / 5.08 |
| exposure_surface | 5.17 / 7.04 | 5.37 / 5.87 | 2.4 / 2.9 |
| min_cut | 24.49 / 31.2 | 17.62 / 19.4 | 17.27 / 19.45 |
| run_cypher_readonly | 0.69 / 0.92 | 0.82 / 1.03 | 0.76 / 1.07 |
| simulate_fix | 392.59 / 411.68 | 236.76 / 271.64 | 272.24 / 296.99 |
| vuln_intel | 3.86 / 5.41 | 3.99 / 5.33 | 3.82 / 4.54 |
| why_step | 7.4 / 10.88 | 7.63 / 9.92 | 7.02 / 9.44 |
