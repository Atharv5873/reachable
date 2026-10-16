# Demo video script (target 2:50, hard limit 3:00)

**Record from a laptop**, browser at 1440x900 or larger, zoom 100%. A phone clips the
headline cards and the wide tables. Every URL below pins a run recorded on the VPS
(`deploy/demo_runs.json`) with `&run=<id>`, so the video always shows the same run and no
model call fires mid-recording. The top bar must say **Replay**.

Before recording: open each URL once (warms Vercel), close other tabs, hide bookmarks, and
set the replay speed on 04 to 4x.

| # | URLs (base `https://reachable-web.vercel.app`) |
|---|---|
| A | `/findings?org=org_a&scan=v1&run=org_a:run:d83515921bd8` |
| B | `/paths?org=org_a&scan=v1&run=org_a:run:d83515921bd8&f=org_a:finding:06856` |
| C | `/fixes?org=org_a&scan=v1&run=org_a:run:d83515921bd8` |
| D | `/live?org=org_a&scan=v1&run=org_a:run:d83515921bd8` |
| E | `/ask?org=org_c&scan=v1&run=org_c:run:f973097ae0e6` |
| F | `/drift?org=org_a&scan=v2&run=org_a_v2:run:6fe91bc3bdbf` |
| G | `/evals?org=org_a&scan=v1&run=org_a:run:d83515921bd8` |

---

### 0:00-0:15 The problem (title card, or A with the cards out of frame)

> Your scanner found 6,862 vulnerabilities and sorts them by severity. But severity
> describes one bug. Risk is whether an attacker can get from the Internet to your data.
> That's a path, and paths live in a graph.

### 0:15-0:40 The two headline cards (A)

Hold on the two cards. Point at the left one, then the right one.

> This is Reachable. Left: Ghostcat, CVSS 9.8, known exploited, high on any severity list.
> But it's in quarantine; nothing leads there. Reachable's number one: a 7.5 the scanner ranks
> four-thousand-one-hundred-and-seventy-fifth.

Click **Sorted by severity**, then **Sorted by reachability** (the rows slide).

> Only 14 of 6,862 findings lie on any attack path. The same Ghostcat CVE appears twice:
> one copy starts a path, the other leads nowhere. Same score, opposite answers.

### 0:40-1:10 Why it's number one: the attack paths (B)

Let the paths draw themselves (about 2 s).

> The 7.5 is on the CI runner. Three different web servers can each reach it through this
> one bug, and the runner holds a cloud key to the deploy bucket. Three paths, one bug.
> Each edge is an attacker step with its ATT&CK technique.

Click the **T1210** edge into `onyx-harbor-ci-221`; hold on the evidence panel.

> Every step shows the facts behind it. Cypher rules derive the steps inside FalkorDB, and
> FalkorDB's shortest-path algorithm finds the likeliest paths.

### 1:10-1:40 One fix, many paths: the min cut (C)

> What to fix? Max-flow, min-cut on the attack graph: seven fixes cut all nine paths.

Point at **One fix, many paths** (the cloud-key card, "cuts 3 paths").

> Revoking one cloud key cuts three at once. Each fix comes with its owner, who's on call,
> and the decision record that opened the exposure.

Click **Simulate these 7 fixes**; hold until both crown jewels flip to SAFE.

> Simulate applies the fixes to a copy of the graph and re-runs the search. Both crown
> jewels: safe. The 9.8 was never needed.

### 1:40-1:55 The agents at work (D)

Press play (4x). Let the feed scroll.

> Agents did this: Triage, Pathfinder, Fixer, Reporter, choosing graph tools over MCP.
> Every call is recorded with its Cypher; this is the real run, replayed from the graph.

### 1:55-2:10 The company brain (E)

Click the first suggestion ("Why is port 22 open on the vendor gateway...").

> The same graph knows the company: why the vendor gateway is exposed, and who approved
> it. It even corrects the question: the port is 443, not 22.

### 2:10-2:35 Memory and drift (F)

Point at **NEW CROWN PATH**, then the memory panel.

> A week later, a rescan. With no model, the Sentinel diffs the paths: one closed, one
> new, one alert. Memory carries seven verdicts, keeps an accepted risk suppressed until
> it expires, and flags four arrivals by patterns it learned last time.

### 2:35-2:55 The evidence (G)

Scroll to the structural table, then the ablation.

> Does the graph earn its place? Against an independent answer key, CVSS, exploit scores,
> vector search and a SQL agent cover zero to ten percent of the real attack paths.
> Reachable covers all of them, with a minimal fix set. Switch the graph off, same agent,
> same model: 100 percent drops to zero.

### 2:55-3:00 Close (G, or the end card)

> Reachable. Fix what an attacker can actually reach.

End card: `reachable-web.vercel.app` · `github.com/Atharv5873/reachable` · FalkorDB · Graph Hacks 2026

---

**Timing check:** about 380 words of narration: about 2:30 spoken at 150 wpm, leaving
room for the clicks and pauses. If you run long, cut D to 10 s.

**Facts used (verified against the live API, 2026-10-16):** org_a v1 has 6,862 open
findings, 14 on a crown path, 9 paths, min cut 7 (cheapest set: effort 8). 06856 =
CVE-2014-3666 on `onyx-harbor-ci-221`, CVSS 7.5, scanner #4,175, lies on paths #4, #8 and
#9. Headline unreachable = 06860, CVE-2020-1938 on `zephyr-sol-quarantine-01`, scanner
#1,488; its twin 06857 on `ember-willow-edge-187` (#1,487) starts path #4. v2 run:
1 new path, 1 closed, 7 verdicts carried, 06859 accepted until 2024-03-31, 4 flagged on
arrival. Eval numbers: `evals/results/comparison.md`, `ablation.md`.
