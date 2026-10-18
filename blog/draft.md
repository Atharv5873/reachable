# Severity is a number. Reachability is a graph.

*First draft for the Graph Hacks "best blog post" prize. Repo: https://github.com/Atharv5873/reachable · Live: https://reachable-web-sand.vercel.app*

Every security team I've seen triages the same way: export the scanner's findings, sort by
CVSS, patch from the top. It feels rigorous. It's a number, it comes from NIST, and a 9.8
is obviously worse than a 7.5.

Except it isn't, necessarily. CVSS describes a bug in a vacuum. What you actually care
about is whether an attacker can get from the Internet, through your machines, keys and
roles, to the data that would end up in a breach notice. That's not a property of one
node. It's a property of *paths*. And once you say "paths", you're talking about a graph.

So for Graph Hacks I built **Reachable**: it puts a company's infrastructure into
FalkorDB, derives every possible attacker step as an edge, and has agents find the real
attack paths and the smallest set of fixes that cuts all of them.

## The moment that makes the point

In the demo org there are 6,862 open findings. Only 14 lie on any path from the Internet
to a crown-jewel data store.

Reachable's number one is a CVSS 7.5 that the scanner ranks **#4,175**. It's on an internal
CI runner. Three different Internet-facing web servers can each reach that runner by
exploiting this one bug, and the runner holds a cloud key that can read the deploy bucket.
Three attack paths, one bug: patch it and all three close.

Better still, the same 9.8 Ghostcat CVE appears at scanner ranks #1,487 and #1,488. One
copy, on an edge web server, starts an attack path. The other sits in a quarantine zone
that nothing leads to. Same CVE, same score, opposite answers. A severity sort can't tell
them apart. A graph can't confuse them.

![Three attack paths through one CI runner](https://raw.githubusercontent.com/Atharv5873/reachable/main/docs/attack-paths.png)

## The data model: make the attacker's moves first-class

The core decision was to **materialise attacker steps as edges**, rather than compute
reachability on the fly in application code.

The raw graph is what a scanner and a cloud inventory tell you: `Asset -[:CAN_REACH
{port}]-> Asset`, `Asset -[:RUNS]-> Software -[:HAS_VULN]-> Vuln`, `Finding -[:ON]->
Asset`, `Asset -[:HOLDS]-> Secret -[:UNLOCKS]-> ...`, identities, roles, data stores,
mitigating controls. Nine rules, each a single Cypher `MATCH ... MERGE`, turn those facts
into `ATTACK_STEP` edges: "an attacker on A can exploit finding F to land on B", tagged with
the MITRE ATT&CK technique, a likelihood, the `fix_token` that would remove the step, and
`because`, the ids of the facts that justify it.

![The data model](https://raw.githubusercontent.com/Atharv5873/reachable/main/docs/data-model.svg)

Two small choices made everything downstream fall out of FalkorDB's built-in algorithms:

* **cost = -ln(likelihood).** Probabilities multiply along a path; negative logs add. So
  the *shortest* path under `algo.SPpaths` is the *most likely* attack path. No custom
  search code.
* **A node-split flow layer.** Every fix token becomes a `FixIn -[:FLOW {cap: 1}]-> FixOut`
  gate, and each step routes through its token's gate. Run `algo.maxFlow` from the Internet
  to the crown jewels and the max-flow value *is* the minimum number of fixes that
  disconnects them (max-flow/min-cut). Swap capacity 1 for an effort score and you get the
  cheapest fix set instead. The cut is recovered from the residual graph, and the tool
  refuses to answer unless the cut's size equals the max flow.

Before any fix set is recommended, `simulate_fix` does a `GRAPH.COPY` to a scratch graph,
deletes the fixed steps, and re-runs the path search. The UI's "Simulate" button is that
check, live.

Each tenant (and each rescan) is its own graph, with the company layer (teams, on-call,
decision records, tickets) and the agents' memory living right next to the infrastructure.
That's what lets a fix plan say not just "patch this" but "Edge & Ingress owns it, Avrel is
on call, and ADR-001 opened this port, approved by the engineering manager in 2022."

## The agents, briefly

Four LLM agents (Triage, Pathfinder, Fixer, Reporter) plus a no-LLM Sentinel for rescans,
in a LangGraph pipeline. They pick their tools over MCP, never call each other, and hand
off through a `Run` node in the graph; every tool call is recorded with the Cypher it ran,
which is what the UI streams and replays. Memory is in the graph too: verdicts carry over
to the next scan, accepted risks expire, learned patterns flag new hosts on arrival, and an
analyst's correction becomes a new playbook version. On the rescan, memory cut the work
from 9 findings investigated to 1, and from 28 tool calls to 16, with the same verified fix
set.

## Does the graph actually earn its place?

The hackathon rules say it plainly: if the product still works without FalkorDB, the graph
is decoration. So I built the eval to answer exactly that.

An independent networkx oracle (never touching FalkorDB) computes the ground truth from the
generator's raw data. Then the same findings are ranked five ways: CVSS; a "smart" score
(CVSS + EPSS + KEV + Internet exposure); a vector-RAG agent and a SQL agent, both with the
same LLM, prompt and budget as Reachable; and Reachable. Six scans, three of them held out.

| prioritiser | attack-path recall@10 | decoys@10 | paths cut per fix |
|---|---|---|---|
| CVSS sort | 0% | 0% | 0.00 |
| smart score | 0% | 33% | 0.00 |
| vector RAG | 0% | 0% | 0.00 |
| SQL agent | 10% | 11% | 0.30 |
| **Reachable** | **100%** | **0%** | **1.16** (= the oracle's min cut) |

The smart score is my favourite failure: it puts a decoy in *every* top 10, an exposed,
exploitable host that leads nowhere. Exposure is a property of one node. Reachability is a
property of paths.

And the ablation: the exact same agent, same model, same prompt, with every graph tool
answering "unavailable". Path recall drops from **100% to 0%**. The graph supplies the
answer; the model doesn't.

## War story 1: my best metric was my weakest evidence

Halfway through, a ranking change took NDCG@10 from 0.82 to 1.00. Perfect score. I should
have been thrilled; instead it bothered me, for two reasons.

First, **it was saturated.** Every org had one crown jewel, so the ground truth's priority
was basically "how many paths does this finding lie on": 13 of org_a's 14 relevant findings
tied. NDCG only rewards putting higher relevance above lower, so any order of those 13 was
"ideal". The metric had stopped measuring ranking quality.

Second, and worse, **it was circular.** My ranker and my ground truth define importance the
same way: weighted reachability to the crown jewels. They're computed independently (the
oracle in networkx over raw data, the ranker in FalkorDB at runtime with no access to
labels, and a leakage test enforces that), so 1.00 does prove the derivation is right. But
it isn't a discovery, and a judge would be right to say so.

What I did about it:

* gave the crown jewels **sensitivity tiers** (customer data critical, deploy secrets high,
  logs medium), so the ground truth has a real gradient. The paths and min cut stayed
  byte-identical; a test pins the old fingerprints. A tier-blind version of my ranker now
  scores 0.95, so 1.00 means the gradient is handled;
* **led with structural metrics instead**: path recall, decoys, paths cut per fix. You
  can't score well on those by sharing a definition; you can't cover nine paths without
  finding them;
* kept the **held-out rescans** honest: they score the same as the development scans;
* walled the tier off from the baselines (the eval views drop the column, and the leakage
  test checks every column, prompt and RAG document they can see);
* printed the caveat **next to the NDCG table**, in the repo and in the UI.

And when the SQL agent did *better* on the re-run (10% path recall, up from 4%, by writing
SQL that walked two hops back from the crown jewels: partial reachability by hand), that
went in the report as-is.

## War story 2: a CSRF hole in a security tool

The UI never holds the API key. The browser calls `/api/r/*` on its own origin, and a
server-side Next.js route handler adds the key and forwards the request. Clean, until an
automated security review of the first cut pointed out the obvious thing I'd missed: **a
proxy that adds a credential to whatever reaches it is a confused deputy.** Any other site
open in the same browser could form-post to `localhost:3000/api/r/runs` and start billed
agent runs on my key.

The fix is small and worth knowing: a POST must be `application/json` (a cross-site HTML
form can't send that, and a cross-site `fetch` with it triggers a CORS preflight the route
never approves) **and** must be same-origin (`Sec-Fetch-Site: same-origin`, or an `Origin`
whose host matches). Everything else gets a 403 before the backend is ever called. On the
live site: cross-site POST 403, `text/plain` POST 403, same-origin POST 200, off-allowlist
path 404. Shipping a CSRF bug in a tool whose whole pitch is "think like an attacker" would
have been a special kind of embarrassing.

## What I'd do next

Everything here runs on three generated estates, which is the honest limit: the next test
is a differently generated (or real, redacted) estate. And a real scanner feed instead of a
synthetic one.

But the thesis held up under every test I could build against it: severity is a number,
and reachability is a graph. Put the attacker's moves in the database, let the database's
own algorithms do the searching and the cutting, and the agent's job becomes explaining
and acting, not guessing.

*Built for Graph Hacks: Context for AI Agents (WeMakeDevs × FalkorDB). All company data is
synthetic; threat intel from CISA KEV, FIRST EPSS, NIST NVD and MITRE ATT&CK®. Built with
AI coding assistants (Claude and Claude Code), disclosed in the README.*
