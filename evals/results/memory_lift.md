# Gate B: memory lift (org_a, scan v2)

Same agents, same rescan, same model and budgets; only the memory differs.

* **cold**: fresh memory namespace: no earlier runs, verdicts, risk acceptances or patterns; starter playbooks only (and no carry-over from v1).
* **warm**: memory after the agents triaged scan v1 (run `lift_org_a:run:ce51959db04e`): its verdicts and routing, the risk acceptances, the patterns it learned; carried into the v2 graph by the Sentinel.

Model: ['primary=gemini/gemini-3.5-flash-lite', 'fallback=groq/qwen/qwen3.8-27b']. Graphs: fresh `lift_org_a` / `lift_org_a_v2` (seed 42, scale 1.0), memory reset before each v2 run.

| | cold | warm |
|---|---:|---:|
| findings investigated | 9 | 1 |
| skipped by memory (carried verdicts) | 0 | 8 |
| flagged on arrival by a learned pattern | 0 | 4 |
| LLM calls | 7 | 6 |
| tool calls (real MCP calls) | 28 | 15 |
| tokens in | 25349 | 20293 |
| tokens out | 3000 | 2031 |
| wall time (s) | 16.5 | 13.1 |
| approx cost (USD, LiteLLM price map) | 0.0151 | 0.01117 |
| fix set (size) | cheapest (7) | cheapest (7) |
| simulate_fix disconnects every crown jewel | True | True |
| fix-set size = oracle min cut | True | True |
| run status | complete | complete |
| healthy (S8: status, tokens, trace, tools) | yes | yes |

**Gate B: PASS**: warm does strictly less work: True; both fix sets correct: True; all three runs healthy: True.

## Where the work went (per agent: LLM calls / tool calls / tokens in)

| agent | cold | warm |
|---|---:|---:|
| sentinel | 0 / 3 / 0 | 0 / 3 / 0 |
| triage | 3 / 4 / 9026 | 2 / 3 / 5128 |
| pathfinder | 2 / 4 / 8748 | 2 / 2 / 7255 |
| fixer | 1 / 17 / 4515 | 1 / 7 / 4539 |
| reporter | 1 / 0 / 3060 | 1 / 0 / 3371 |

## What memory changed (warm)

* Episodic: 8 candidate(s) carried on a standing verdict, not re-investigated: {'org_a:finding:06850': 'fix_now', 'org_a:finding:06851': 'fix_now', 'org_a:finding:06855': 'fix_now', 'org_a:finding:06848': 'fix_now', 'org_a:finding:06853': 'fix_now', 'org_a:finding:06857': 'schedule', 'org_a:finding:06858': 'schedule', 'org_a:finding:06859': 'schedule'}.
* Semantic: flagged on arrival, before any path search: ['org_a:finding:06868', 'org_a:finding:06871', 'org_a:finding:06876', 'org_a:finding:06879'].
* Memory events in the trace: {'carry_over': 1, 'pattern_flags': 1, 'carried_verdicts': 1, 'remembered_routes': 1, 'patterns_learned': 1}.
* Investigated cold: ['org_a:finding:06879', 'org_a:finding:06857', 'org_a:finding:06850', 'org_a:finding:06851', 'org_a:finding:06855', 'org_a:finding:06848', 'org_a:finding:06853', 'org_a:finding:06858', 'org_a:finding:06859']
* Investigated warm: ['org_a:finding:06879']
* Fix sets: cold ['org_a:finding:06848', 'org_a:finding:06850', 'org_a:finding:06851', 'org_a:finding:06853', 'org_a:finding:06855', 'org_a:finding:06879', 'step:usekey:org_a:secret:00008:org_a:ident:00006']; warm ['org_a:finding:06848', 'org_a:finding:06850', 'org_a:finding:06851', 'org_a:finding:06853', 'org_a:finding:06855', 'org_a:finding:06879', 'step:usekey:org_a:secret:00008:org_a:ident:00006'].
* Alert (new crown path) raised in both: cold lift_org_a_v2:alert:ce8cd1ecf549, warm lift_org_a_v2:alert:3de8b3de7eed.

Runs: cold `lift_org_a_v2:run:15bf291ed335`, warm `lift_org_a_v2:run:7f2ab450e786` (runs/*.md).
