# data/orgs/

Generated synthetic org data. **Gitignored** except the tiny `sample/`.

Per org (`org_a`, `org_b`, `org_c`), `make seed` loads the graph into FalkorDB
and writes here:

- `labels.json`  — ground truth for scan v1: planted attack paths (hop by hop,
  with rule + ATT&CK technique per hop), decoys by type, the shared
  infrastructure funnels (`shared_infra`), the min-cut fix set, and the
  per-finding priority ground truth.
- `labels_v2.json` — ground truth for scan v2 (a week later): some findings
  fixed (including one planted entry, `fixed_findings_v2`, whose paths are gone:
  `removed_paths_v2`), some new, and the ONE new path a config change opened.

**Labels are never loaded into FalkorDB.** They are the answer key the agents
(S2+) are graded against. The graph itself lives in FalkorDB, not on disk.

The committed `sample/` holds a tiny (scale 0.02) `labels.json` + `summary.json`
so the repo shows the shape of the ground truth without running anything.
