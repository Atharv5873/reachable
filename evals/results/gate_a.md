# Gate A - graph tools vs ground truth (no LLM)

Generated 2026-10-15 15:45:16. attack_paths budget k=10. Latency reps per tool: 20.

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
| attack_paths | 16.9 / 19.03 | 46.55 / 51.68 | 67.02 / 71.83 |
| attack_paths (from a seed asset) | 0.64 / 0.99 | 0.58 / 1.18 | 1.1 / 1.86 |
| blast_radius | 2.73 / 3.31 | 5.65 / 6.98 | 6.63 / 10.97 |
| choke_points | 4.8 / 5.95 | 3.79 / 5.93 | 3.53 / 4.56 |
| exposure_surface | 5.1 / 6.22 | 6.23 / 13.64 | 2.21 / 4.73 |
| min_cut | 21.37 / 28.46 | 17.77 / 26.34 | 17.38 / 19.37 |
| run_cypher_readonly | 0.75 / 1.4 | 0.81 / 1.41 | 0.78 / 1.28 |
| simulate_fix | 362.38 / 381.71 | 206.82 / 219.4 | 233.11 / 249.82 |
| vuln_intel | 3.99 / 5.27 | 3.97 / 8.47 | 3.54 / 4.93 |
| why_step | 7.55 / 11.57 | 8.59 / 15.88 | 7.46 / 11.76 |
