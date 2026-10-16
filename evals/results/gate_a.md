# Gate A - graph tools vs ground truth (no LLM)

Generated 2026-10-16 10:53:38. attack_paths budget k=10. Latency reps per tool: 20.

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
| org_a | 342 | 237 | 1.0000 |
| org_b | 424 | 299 | 1.0000 |
| org_c | 204 | 186 | 1.0000 |

## Latency (ms)

| tool | org_a p50 / p95 | org_b p50 / p95 | org_c p50 / p95 |
|---|---|---|---|
| attack_paths | 31.74 / 35.5 | 94.82 / 98.92 | 209.5 / 216.64 |
| attack_paths (from a seed asset) | 0.67 / 1.02 | 0.73 / 1.37 | 0.79 / 1.37 |
| blast_radius | 3.15 / 4.5 | 4.95 / 8.64 | 5.78 / 8.76 |
| choke_points | 4.47 / 5.56 | 3.59 / 4.68 | 3.9 / 6.99 |
| exposure_surface | 5.04 / 6.14 | 5.74 / 7.16 | 2.41 / 3.09 |
| min_cut | 25.52 / 31.19 | 17.67 / 19.87 | 18.2 / 23.46 |
| run_cypher_readonly | 0.82 / 1.04 | 0.75 / 1.16 | 0.8 / 1.17 |
| simulate_fix | 376.7 / 401.43 | 241.58 / 245.85 | 256.22 / 303.41 |
| vuln_intel | 4.05 / 6.16 | 3.81 / 5.06 | 3.71 / 6.19 |
| why_step | 8.05 / 9.95 | 8.57 / 11.53 | 7.48 / 11.58 |
