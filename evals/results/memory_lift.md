# Gate B: memory lift (org_a, scan v2)

Same agents, same rescan, same model and budgets; only the memory differs.

* **cold**: fresh memory namespace: no earlier runs, verdicts, risk acceptances or patterns; starter playbooks only (and no carry-over from v1).
* **warm**: memory after the agents triaged scan v1 (run `lift_org_a:run:c34e6cf70db8`): its verdicts and routing, the risk acceptances, the patterns it learned; carried into the v2 graph by the Sentinel.

Model: ['primary=gemini/gemini-3.5-flash-lite', 'fallback=groq/qwen/qwen3.8-27b']. Graphs: fresh `lift_org_a` / `lift_org_a_v2` (seed 42, scale 1.0), memory reset before each v2 run.

| | cold | warm |
|---|---:|---:|
| findings investigated | 9 | 1 |
| skipped by memory (carried verdicts) | 0 | 8 |
| flagged on arrival by a learned pattern | 0 | 4 |
| LLM calls | 7 | 7 |
| tool calls (real MCP calls) | 27 | 14 |
| tokens in | 27156 | 25175 |
| tokens out | 2777 | 2194 |
| wall time (s) | 66.4 | 79.0 |
| approx cost (USD, LiteLLM price map) | 0.01509 | 0.01304 |
| fix set (size) | cheapest (7) | cheapest (7) |
| simulate_fix disconnects every crown jewel | True | True |
| fix-set size = oracle min cut | True | True |
| run status | complete | complete |

**Gate B: PASS**: warm does strictly less work: True; both fix sets correct: True.

## Where the work went (per agent: LLM calls / tool calls / tokens in)

| agent | cold | warm |
|---|---:|---:|
| sentinel | 0 / 3 / 0 | 0 / 3 / 0 |
| triage | 2 / 4 / 6348 | 2 / 3 / 5418 |
| pathfinder | 2 / 4 / 8736 | 2 / 2 / 7243 |
| fixer | 2 / 16 / 9035 | 2 / 6 / 9143 |
| reporter | 1 / 0 / 3037 | 1 / 0 / 3371 |

## What memory changed (warm)

* Episodic: 8 candidate(s) carried on a standing verdict, not re-investigated: {'org_a:finding:06857': 'schedule', 'org_a:finding:06848': 'fix_now', 'org_a:finding:06850': 'fix_now', 'org_a:finding:06851': 'fix_now', 'org_a:finding:06853': 'fix_now', 'org_a:finding:06858': 'schedule', 'org_a:finding:06855': 'fix_now', 'org_a:finding:06859': 'schedule'}.
* Semantic: flagged on arrival, before any path search: ['org_a:finding:06868', 'org_a:finding:06871', 'org_a:finding:06876', 'org_a:finding:06879'].
* Memory events in the trace: {'carry_over': 1, 'pattern_flags': 1, 'carried_verdicts': 1, 'remembered_routes': 1, 'patterns_learned': 1}.
* Investigated cold: ['org_a:finding:06879', 'org_a:finding:06857', 'org_a:finding:06848', 'org_a:finding:06850', 'org_a:finding:06851', 'org_a:finding:06853', 'org_a:finding:06858', 'org_a:finding:06855', 'org_a:finding:06859']
* Investigated warm: ['org_a:finding:06879']
* Fix sets: cold ['org_a:finding:06848', 'org_a:finding:06850', 'org_a:finding:06851', 'org_a:finding:06853', 'org_a:finding:06855', 'org_a:finding:06879', 'step:usekey:org_a:secret:00008:org_a:ident:00006']; warm ['org_a:finding:06848', 'org_a:finding:06850', 'org_a:finding:06851', 'org_a:finding:06853', 'org_a:finding:06855', 'org_a:finding:06879', 'step:usekey:org_a:secret:00008:org_a:ident:00006'].
* Alert (new crown path) raised in both: cold lift_org_a_v2:alert:70a422c229b6, warm lift_org_a_v2:alert:b913cbf3f434.

Runs: cold `lift_org_a_v2:run:041c72ac1b95`, warm `lift_org_a_v2:run:6e1d571ed6cd` (runs/*.md).
