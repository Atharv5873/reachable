import { describe, expect, it } from "vitest";

import { crownPhrase, crownTargets, placements, whyLine } from "./labels";
import type { BoardRow, CrownJewel, GEdge, GNode, GPath, Subgraph } from "./types";

const critical: CrownJewel = { id: "org_a:ds:00001", name: "bucket", tier: "critical" };
const high: CrownJewel = { id: "org_a:ds:00004", name: "bucket", tier: "high" };

describe("crownPhrase", () => {
  it("names clashing crown jewels by tier", () => {
    expect(crownPhrase([critical, high])).toBe("the critical bucket and the high-tier bucket");
  });
  it("puts the most sensitive first", () => {
    expect(crownPhrase([high, critical])).toBe("the critical bucket and the high-tier bucket");
  });
  it("judges the clash on the full list even when naming one", () => {
    expect(crownPhrase([critical, high], [high])).toBe("the high-tier bucket");
  });
  it("leaves distinct names alone", () => {
    const db: CrownJewel = { id: "org_b:ds:00001", name: "orders-db", tier: "critical" };
    expect(crownPhrase([db])).toBe("the orders-db");
    expect(crownPhrase([db, high])).toBe("the orders-db and the bucket");
  });
  it("falls back when there is nothing to name", () => {
    expect(crownPhrase([])).toBe("the crown jewel");
  });
});

const row = (over: Partial<BoardRow>): BoardRow => ({
  finding: "org_a:finding:06856",
  asset: "org_a:asset:01752",
  hostname: "onyx-harbor-ci-221",
  cve: "CVE-2014-3666",
  cvss: 7.5,
  epss: 0.04,
  kev: false,
  zone: "ci",
  scanner_rank: 4175,
  reach_rank: 1,
  score: 0.0281,
  status: "reachable",
  why: "Hop 2 of path #4 to the bucket (p=0.040)",
  targets: ["org_a:ds:00004"],
  target_tier: "high",
  attack_steps: 3,
  verdict: "schedule",
  headline: "reachable",
  ...over,
});

// Paths #4, #8, #9 (index 3, 7, 8) all take the finding's step as hop 2;
// path #1 never touches it.
const F = "org_a:finding:06856";
const edge = (id: string, fix_token: string | null): GEdge =>
  ({ id, source: "a", target: "b", fix_token, paths: [] }) as unknown as GEdge;
const path = (index: number, target: string, steps: string[]): GPath => ({ index, target, likelihood: 0.04, nodes: [], steps });
const node = (id: string, name: string, tier: GNode["tier"]): GNode =>
  ({ id, name, kind: "datastore", crown: true, tier, paths: [] }) as unknown as GNode;
const g = {
  nodes: [node(critical.id, "bucket", "critical"), node(high.id, "bucket", "high")],
  edges: [edge("s0", "org_a:finding:00001"), edge("s1", F), edge("s2", "org_a:secret:00009")],
  paths: [
    path(0, critical.id, ["s0", "s2"]),
    path(3, high.id, ["s0", "s1", "s2"]),
    path(7, high.id, ["s0", "s1"]),
    path(8, critical.id, ["s2", "s1"]),
  ],
  total_paths: 9,
} as unknown as Subgraph;

describe("placements", () => {
  it("finds the finding's hop on each path it lies on", () => {
    expect(placements(g, F)).toEqual([
      { path: 4, hop: 2 },
      { path: 8, hop: 2 },
      { path: 9, hop: 2 },
    ]);
  });
  it("is empty without a subgraph or a match", () => {
    expect(placements(undefined, F)).toEqual([]);
    expect(placements(g, "org_a:finding:99999")).toEqual([]);
  });
});

describe("crownTargets", () => {
  it("reads each target's name and tier from the subgraph", () => {
    expect(crownTargets(g)).toEqual([critical, high]);
    expect(crownPhrase([critical, high], crownTargets(g))).toBe("the critical bucket and the high-tier bucket");
  });
});

describe("whyLine", () => {
  it("leads with the path count when a finding sits on several paths", () => {
    expect(whyLine(row({}), placements(g, F), 9)).toBe("On 3 of 9 attack paths — hop 2 of paths #4, #8, #9");
  });
  it("splits by hop when the step sits at different depths", () => {
    const on = [
      { path: 1, hop: 1 },
      { path: 4, hop: 2 },
      { path: 6, hop: 2 },
      { path: 9, hop: 3 },
    ];
    expect(whyLine(row({}), on, 9)).toBe("On 4 of 9 attack paths — starts path #1; hop 2 of paths #4, #6; hop 3 of path #9");
  });
  it("drops the total when it is unknown", () => {
    expect(whyLine(row({}), placements(g, F))).toBe("On 3 attack paths — hop 2 of paths #4, #8, #9");
  });
  it("keeps the backend line for a single path, or no path data", () => {
    expect(whyLine(row({}), [{ path: 4, hop: 2 }], 9)).toBe("Hop 2 of path #4 to the bucket (p=0.040)");
    expect(whyLine(row({}))).toBe("Hop 2 of path #4 to the bucket (p=0.040)");
  });
  it("never touches an unreachable row", () => {
    const r = row({ status: "unreachable", why: "Not reachable" });
    expect(whyLine(r, placements(g, F), 9)).toBe("Not reachable");
  });
});
