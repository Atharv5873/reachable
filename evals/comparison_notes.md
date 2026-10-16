### On the NDCG result

reachable's NDCG@10 is 1.00, and we do not lead with it. Its ranker and the oracle's ground truth define importance the same way: a finding matters in proportion to the number of Internet -> crown-jewel paths it lies on, weighted by the target's sensitivity tier. They are computed independently (the oracle by networkx over the generator's raw dataset; the ranker by FalkorDB over the derived ATTACK_STEP layer at runtime, with no access to labels: `test_eval_leakage.py`), so 1.00 does check that the derivation is right. It is not a discovery, though. The evidence that carries the claim is structural: the top 10 covers every planted path (100% vs 0-10% for the reachability-blind baselines), avoids every decoy (smart_score puts one in every top 10), and comes with a fix set that cuts every path at the oracle's minimum (1.16 paths per fix vs 0-0.30). And the ablation: the same agent with the graph tools switched off falls from 100% to 0% path recall. The graph supplies the priority; the model does not.

### What S9 changed

S8 ended with every crown jewel at the same sensitivity, so 13 of org_a's 14 relevant findings tied and NDCG only measured "on a path or not". S9 gives each org crown jewels of two or three tiers (critical 1.0, high 0.6, medium 0.3 in the oracle), assigned per route from its story before this re-run, and changes nothing else: the attack paths and the min cut are identical to S8's (`tests/test_sensitivity.py` pins the pre-S9 fingerprints; Gate A's recall, path counts, min-cut sizes, max flows and sets are unchanged). The baselines no longer see the tier (the eval views drop `datastores.sensitivity`); they still see which stores are crown jewels.

| reachable | S8 (3 seeds, one tier) | S9 (1 seed, 2-3 tiers per org) |
|---|---|---|
| path recall@10 | 100% | 100% |
| decoys@10 | 0% | 0% |
| paths cut / fix (oracle 1.16) | 1.16 | 1.16 |
| fix set cuts every path | 100% | 100% |
| NDCG@10 (all / held-out v2) | 1.00 / 1.00 | 1.00 / 1.00 |
| P@10 (ceiling 87%) | 87% | 87% |
| $ / run, LLM calls / run | $0.0058, 2.4 | $0.0068, 2.5 |
| ablation, graph off (path recall / NDCG) | 0% / 0.00 | 0% / 0.00 |

- **1.00 now means more than it did.** With tiers, the ideal order is a real gradient inside the top 10. Run offline over the oracle's paths, the same path-criticality ranker with the tier weights ignored scores NDCG@10 0.95 (org_c 0.91, org_b 0.97, org_a 0.97); with them, 1.00. So the ranker is now being tested on the sensitivity gradient, not just on/off-path, and it passes. The gap is small because a tier only reorders findings that are all relevant already.
- **The ranker's tier weights are not the oracle's** (1.0 / 0.7 / 0.4 in `criticality.py`, fixed in S8, vs 1.0 / 0.6 / 0.3). Neither was changed. They agree on every ordering in this data; they would disagree on three medium-tier routes through one finding vs one critical route, and we would report that loss.
- **Data-design constraint, stated.** org_a has 14 on-path findings for 9 routes; a lower tier on a route with one or two findings would push them below rank 10 of the oracle's own order and make path recall@10 < 100% by definition. Its lower tier therefore sits on the routes with the most findings (the CI funnel and the IMDS route). Written next to `ROUTE_TIER` in `planters.py`.
- **One seed.** The headline is one provider seed (`SEEDS="1 2 3" make eval` for the spread, about 3x the cost). reachable had zero spread over three seeds in S8; the LLM baselines did not, so their single-seed numbers move (below).

### Why the baselines score what they score

- **severity_sort: 0 everywhere.** Each scan has more than 3,000 open findings at CVSS 9.0+, and 12 of org_a's 14 relevant findings are 7.5 or lower, so none reach the top 10.
- **smart_score: 0, plus a decoy in every top 10.** Its top ranks are Internet-facing load balancers with KEV 9.8 findings that lead nowhere; the planted dead-end decoy is one of them (decoys@10 = 33% on every scan). Exposure is a property of one node; reachability is a property of paths.
- **vector_rag: 0% (S8, 3 seeds: 3%).** It named one finding in 4 of 6 runs, usually from the scanner's top list in the CONTEXT. Similar text is not connected text: each hop of a path is a fresh search among ~8,600 documents.
- **sql_agent: 10% (S8, 3 seeds: 4%), and a decoy rate for the first time.** Its hits come from SQL that walks one or two hops back from the crown jewels: on org_a_v2 it joined `datastores` (crown_jewel) -> `edges` (UNLOCKS, CAN, ASSUMES) -> the assets holding those secrets or roles, and named the exposed findings on three of them (3 of 9 paths). That is partial reachability done by hand, and it is the only thing that scores. On org_c_v2 it named 18 findings and two of them were decoys (67%). This is one seed; S8's three-seed spread for it was ±6 points.
- **A generator artefact helps the text baselines, not us.** Planted hosts have kinds background hosts rarely have (`web_server`, `db_host`); a baseline that filters on them gets a hint a real estate would not give.
- **Hiding the tier does not explain their scores.** It can only affect the order inside their top 10; their path recall is low because they do not find the routes at all.

### Remaining gaps

- **Cost and latency (baselines win).** severity_sort and smart_score are free and instant. reachable is about $0.007 and 9 s of active time a run (2.5 model calls). Still the cheapest LLM prioritiser (vector_rag $0.012, sql_agent $0.012).
- **The model's own list is still short.** The model named 7-14 findings; S8's graph step fills the head from the graph, so this is harmless, but the model alone would under-fill.
- **Synthetic data is the limit.** Every number here is on three generated estates. A differently generated estate is the next honest test.
