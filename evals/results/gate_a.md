# Gate A - graph tools vs ground truth (no LLM)

Generated 2026-10-15 23:06:07. attack_paths budget k=10. Latency reps per tool: 20.

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
| attack_paths | 17.75 / 19.85 | 48.9 / 51.56 | 70.95 / 75.17 |
| attack_paths (from a seed asset) | 0.54 / 0.76 | 1.04 / 1.55 | 0.88 / 1.18 |
| blast_radius | 2.76 / 4.02 | 4.46 / 6.56 | 5.21 / 6.18 |
| choke_points | 4.96 / 6.58 | 3.53 / 4.82 | 3.75 / 4.76 |
| exposure_surface | 5.1 / 7.91 | 5.37 / 6.24 | 2.25 / 3.33 |
| min_cut | 24.41 / 30.04 | 16.3 / 20.11 | 18.0 / 19.61 |
| run_cypher_readonly | 0.85 / 1.12 | 0.76 / 1.07 | 0.74 / 1.11 |
| simulate_fix | 407.38 / 438.77 | 247.04 / 278.81 | 251.67 / 271.5 |
| vuln_intel | 4.04 / 5.22 | 3.96 / 5.07 | 3.97 / 5.03 |
| why_step | 7.79 / 9.53 | 7.48 / 9.98 | 7.62 / 10.25 |
