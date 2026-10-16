import { describe, expect, it } from "vitest";

import { crownLabel, onPathsByFinding, whyLine } from "./labels";
import type { BoardRow, CrownJewel, RunDump } from "./types";

const critical: CrownJewel = { id: "org_a:ds:00001", name: "bucket", tier: "critical" };
const high: CrownJewel = { id: "org_a:ds:00004", name: "bucket", tier: "high" };

describe("crownLabel", () => {
  it("appends tiers when two crown jewels share a name", () => {
    expect(crownLabel([critical, high])).toBe("bucket (critical) / bucket (high)");
  });
  it("judges the clash on the full list even when naming one", () => {
    expect(crownLabel([critical, high], [high])).toBe("bucket (high)");
  });
  it("leaves distinct names alone", () => {
    const db: CrownJewel = { id: "org_b:ds:00001", name: "orders-db", tier: "critical" };
    expect(crownLabel([db, high])).toBe("orders-db, bucket");
  });
  it("falls back when there is nothing to name", () => {
    expect(crownLabel([])).toBe("crown jewel");
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

describe("whyLine", () => {
  it("leads with the path count when a finding sits on several paths", () => {
    expect(whyLine(row({}), 3)).toBe("On 3 attack paths · Hop 2 of path #4 to the bucket (p=0.040)");
  });
  it("keeps the backend line for a single path, or no count", () => {
    expect(whyLine(row({}), 1)).toBe("Hop 2 of path #4 to the bucket (p=0.040)");
    expect(whyLine(row({}))).toBe("Hop 2 of path #4 to the bucket (p=0.040)");
  });
  it("never touches an unreachable row", () => {
    const r = row({ status: "unreachable", why: "Not reachable" });
    expect(whyLine(r, 3)).toBe("Not reachable");
  });
});

describe("onPathsByFinding", () => {
  it("reads on_paths from the run's ranking", () => {
    const run = {
      outputs: {
        PathAnalysis: {
          payload: {
            ranked: [
              { finding: "org_a:finding:06856", on_paths: 3 },
              { finding: "org_a:finding:06850", on_paths: 1 },
            ],
          },
        },
      },
    } as unknown as RunDump;
    const m = onPathsByFinding(run);
    expect(m.get("org_a:finding:06856")).toBe(3);
    expect(m.get("org_a:finding:06850")).toBe(1);
  });
  it("is empty without a run or a ranking", () => {
    expect(onPathsByFinding(undefined).size).toBe(0);
    expect(onPathsByFinding({ outputs: {} } as unknown as RunDump).size).toBe(0);
  });
});
