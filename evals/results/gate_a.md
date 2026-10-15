# Gate A - graph tools vs ground truth (no LLM)

Generated 2026-10-15 16:05:21. attack_paths budget k=10. Latency reps per tool: 20.

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
| attack_paths | 17.37 / 19.29 | 48.62 / 55.19 | 70.43 / 73.45 |
| attack_paths (from a seed asset) | 0.58 / 0.85 | 0.52 / 0.84 | 1.99 / 2.76 |
| blast_radius | 2.7 / 3.26 | 4.93 / 7.41 | 5.14 / 7.85 |
| choke_points | 4.69 / 6.94 | 3.51 / 5.11 | 3.72 / 4.52 |
| exposure_surface | 4.95 / 6.33 | 6.21 / 10.26 | 2.23 / 3.68 |
| min_cut | 23.93 / 33.1 | 17.69 / 22.09 | 16.43 / 21.65 |
| run_cypher_readonly | 0.75 / 1.09 | 0.75 / 1.42 | 0.82 / 1.05 |
| simulate_fix | 348.37 / 393.16 | 215.75 / 225.07 | 244.77 / 250.97 |
| vuln_intel | 3.89 / 5.26 | 3.67 / 5.98 | 3.59 / 4.67 |
| why_step | 8.05 / 10.75 | 7.61 / 10.76 | 7.57 / 9.73 |
