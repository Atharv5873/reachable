# Ablation: the same agent, graph tools on vs off

Generated 2026-10-16T05:36:25+00:00 by `make ablation`. org_a scan v1, model `gemini/gemini-3.5-flash-lite`, seeds [1]. Identical prompt, CONTEXT, budgets and tool schemas; graph-off, every FalkorDB tool call answers *unavailable*, so the agent can only reason from the CONTEXT (the scanner's top findings by CVSS, the crown jewels, counts).

|  | path recall@10 | NDCG@10 | P@10 | decoys@10 | fix set cuts | tool calls answered | tokens in / run |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **graph ON** | 100% | 1.00 | 100% | 0% | 100% | 8.0 | 31,115 |
| **graph OFF** | 0% | 0.00 | 0% | 0% | 0% | 0 (unavailable) | 16,523 |
| **drop** | **+100 pts** | **+1.00** | +100 pts | +0 pts | +100 pts |  |  |

Positive drop = what taking FalkorDB away costs (for decoys, a negative drop means more decoys reached the top 10 without the graph).
