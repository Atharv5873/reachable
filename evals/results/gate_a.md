# Gate A - graph tools vs ground truth (no LLM)

Generated 2026-10-16 10:08:44. attack_paths budget k=10. Latency reps per tool: 20.

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
| attack_paths | 17.1 / 18.84 | 48.47 / 51.51 | 70.18 / 75.89 |
| attack_paths (from a seed asset) | 0.61 / 1.07 | 0.46 / 0.92 | 1.03 / 1.58 |
| blast_radius | 2.47 / 3.33 | 5.0 / 8.59 | 5.68 / 8.64 |
| choke_points | 4.5 / 7.74 | 3.55 / 4.54 | 3.53 / 4.68 |
| exposure_surface | 4.94 / 7.25 | 5.38 / 9.13 | 2.16 / 4.14 |
| min_cut | 23.33 / 30.48 | 17.07 / 20.17 | 17.18 / 22.68 |
| run_cypher_readonly | 0.62 / 0.88 | 0.73 / 1.01 | 0.72 / 1.11 |
| simulate_fix | 332.29 / 381.25 | 213.78 / 246.43 | 238.42 / 255.25 |
| vuln_intel | 3.08 / 4.92 | 3.64 / 4.82 | 3.25 / 4.29 |
| why_step | 6.65 / 10.41 | 7.79 / 10.92 | 6.56 / 9.5 |
