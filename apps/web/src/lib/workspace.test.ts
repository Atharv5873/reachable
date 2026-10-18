import { describe, expect, it } from "vitest";

import type { RunHead, ScanInfo } from "./types";
import { defaultRun } from "./workspace";

const run = (id: string, started: number, extra: Partial<RunHead> = {}): RunHead => ({
  id,
  kind: "agent_triage",
  scan: "v1",
  status: "complete",
  started,
  models: ["primary=gemini/x:6"],
  ...extra,
});

const scan = (recent_runs: RunHead[], demo_run: string | null = null): ScanInfo => ({
  scan: "v1",
  graph: "org_a",
  info: null,
  recent_runs,
  demo_run,
  alerts: [],
});

describe("defaultRun", () => {
  const pinned = run("org_a:run:pinned", 1);
  const visitor = run("org_a:run:visitor", 9); // a live run a visitor started later

  it("opens the newest finished real-model run off the demo", () => {
    const stub = run("org_a:run:stub", 10, { models: ["primary=fake:3"] });
    const running = run("org_a:run:running", 11, { status: "running" });
    expect(defaultRun(scan([pinned, visitor, stub, running]), false)).toBe("org_a:run:visitor");
  });

  it("opens the pinned run on the read-only demo, never the newest", () => {
    expect(defaultRun(scan([visitor, pinned], "org_a:run:pinned"), true)).toBe("org_a:run:pinned");
  });

  it("opens nothing on the read-only demo when the scan has no pin", () => {
    expect(defaultRun(scan([visitor]), true)).toBeNull();
    expect(defaultRun(undefined, true)).toBeNull();
  });
});
