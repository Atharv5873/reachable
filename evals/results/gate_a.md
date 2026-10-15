# Gate A - graph tools vs ground truth (no LLM)

Generated 2026-10-15 16:11:02. attack_paths budget k=10. Latency reps per tool: 20.

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
| attack_paths | 17.54 / 18.46 | 47.63 / 51.37 | 68.8 / 76.44 |
| attack_paths (from a seed asset) | 0.53 / 0.68 | 0.47 / 0.79 | 1.79 / 2.81 |
| blast_radius | 2.61 / 4.06 | 4.84 / 10.17 | 5.83 / 12.84 |
| choke_points | 4.63 / 7.36 | 3.51 / 5.38 | 3.82 / 5.75 |
| exposure_surface | 4.78 / 7.91 | 6.4 / 11.39 | 2.38 / 3.71 |
| min_cut | 22.17 / 38.3 | 16.73 / 24.52 | 17.34 / 23.65 |
| run_cypher_readonly | 0.67 / 1.1 | 0.88 / 1.34 | 0.81 / 1.2 |
| simulate_fix | 374.36 / 387.89 | 216.43 / 224.07 | 235.16 / 287.66 |
| vuln_intel | 3.53 / 6.9 | 3.97 / 6.0 | 3.52 / 5.33 |
| why_step | 7.33 / 14.21 | 7.3 / 13.0 | 6.73 / 11.15 |
