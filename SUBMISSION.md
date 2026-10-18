# Submission copy (WeMakeDevs form)

Paste-ready. Fill the video URL once it's uploaded.

**Project name:** Reachable

**Tagline:** Security triage by what an attacker can actually reach, not by CVSS.

**Tracks:** Agents That Act on Connected Data · Agent Memory and Coordination · Company Brain

**Repository:** https://github.com/Atharv5873/reachable

**Live deployment:** https://reachable-web-sand.vercel.app

**Demo video:** `<VIDEO URL>`

**Description (one paragraph):**

Scanners sort thousands of findings by CVSS, but risk is a property of paths, not of one
bug: can an attacker get from the Internet, through your hosts, keys and roles, to the data
that matters? Reachable loads a company's infrastructure, identities, secrets and findings
into FalkorDB (one graph per tenant and scan), derives every attacker step as an
`ATTACK_STEP` edge with nine Cypher rules tagged with MITRE ATT&CK, and gives agents typed
graph tools over MCP: `algo.SPpaths` for the most likely attack paths (cost = -ln p),
`algo.maxFlow` on a node-split layer for the minimum set of fixes that cuts every path,
`algo.bfs` and `algo.betweenness` for blast radius and choke points, and `GRAPH.COPY` to
prove a fix set works before recommending it. The same graph holds the company brain (owners,
on-call, the decision records that opened each exposure) and the agents' episodic, semantic
and procedural memory, so a rescan starts from last week's verdicts, accepted risks and
learned patterns. In the demo org, Reachable's #1 is a CVSS 7.5 the scanner ranks #4,175,
because three attack paths funnel through it. Against an independent oracle it covers 100%
of planted attack paths in its top 10 (CVSS, an EPSS/KEV score, vector RAG and a SQL agent:
0-10%), and with its graph tools switched off the same agent drops to 0%. All company data
is synthetic; threat intel is public (CISA KEV, FIRST EPSS, NVD, MITRE ATT&CK).

**AI-use disclosure (one line):**

Built with AI coding assistants: Claude drafted each session's implementation prompt and
Claude Code (Opus) implemented it; I set the scope and the design decisions, reviewed every
session, and can explain the graph model, the Cypher and the architecture (details in the
README).

**Short version (if a field is length-limited, ~280 chars):**

Reachable ranks security findings by attack-path reachability in FalkorDB: Cypher-derived
ATTACK_STEP edges, SPpaths + maxFlow min cut over MCP, company brain and agent memory in the
same graph. 100% attack-path recall vs 0-10% for CVSS/RAG/SQL; graph off -> 0%.
