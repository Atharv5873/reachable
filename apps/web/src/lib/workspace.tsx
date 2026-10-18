"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { createContext, useCallback, useContext, useMemo } from "react";

import { type ApiError, useApi } from "./api";
import type { OrgInfo, RunHead, ScanInfo } from "./types";

/**
 * The workspace: which org, which scan, which run, which finding, and whether
 * we replay a finished run or start live ones. All of it lives in the URL
 * (?org=&scan=&run=&f=&mode=), so a selection made on one screen is the
 * selection on every screen, links are shareable, and a reload (or the demo
 * video) lands exactly where it was.
 *
 * Replay is the default: every screen reads a finished run from the graph,
 * and nothing calls a model. Live starts real runs and streams them.
 */

export type Mode = "replay" | "live";
export type Scan = "v1" | "v2";

export const ORG_LABEL: Record<string, string> = {
  org_a: "Cloud SaaS",
  org_b: "Retail web",
  org_c: "Hybrid",
};

type Patch = Partial<{
  org: string;
  scan: Scan;
  run: string | null;
  f: string | null;
  mode: Mode;
  watch: "1" | null; // Investigation: stream this run live
}>;

type Workspace = {
  org: string;
  scan: Scan;
  mode: Mode;
  finding: string | null;
  runId: string | null; // the run every screen reads (explicit, else defaultRun)
  readonly: boolean; // the public demo: pinned runs, no verdicts
  runs: RunHead[]; // agent runs of this org + scan, newest first
  scanInfo: ScanInfo | undefined;
  orgs: OrgInfo[] | undefined;
  orgsError: ApiError | undefined;
  orgsLoading: boolean;
  reloadOrgs: () => void;
  set: (patch: Patch, opts?: { push?: boolean }) => void;
  href: (path: string, patch?: Patch) => string;
};

const Ctx = createContext<Workspace | null>(null);

export function isStub(r: RunHead): boolean {
  return !!r.models?.some((m) => m.includes("fake"));
}

/** The run replay opens for a scan: on the read-only demo its pinned run (never
 *  whatever a visitor ran last), else the newest finished run made with a real
 *  model, so a stub-model test run never silently becomes what the demo shows. */
export function defaultRun(scan: ScanInfo | undefined, readonly: boolean): string | null {
  if (readonly) return scan?.demo_run ?? null;
  const done = (scan?.recent_runs ?? []).filter((r) => r.kind === "agent_triage" && r.status === "complete");
  done.sort((a, b) => (b.started ?? 0) - (a.started ?? 0));
  return (done.find((r) => !isStub(r)) ?? done[0])?.id ?? null;
}

export function useWorkspace(): Workspace {
  const ws = useContext(Ctx);
  if (!ws) throw new Error("useWorkspace outside <WorkspaceProvider>");
  return ws;
}

function nextParams(current: URLSearchParams, patch: Patch): URLSearchParams {
  const p = new URLSearchParams(current);
  if ((patch.org && patch.org !== p.get("org")) || (patch.scan && patch.scan !== (p.get("scan") ?? "v1"))) {
    // A different scan graph: its runs and findings are different ones.
    p.delete("run");
    p.delete("f");
    p.delete("watch");
  }
  for (const [k, v] of Object.entries(patch)) {
    if (v === null || v === undefined || v === "") p.delete(k);
    else p.set(k, String(v));
  }
  return p;
}

/** A URL param without the zero-width characters and whitespace a copied link
 *  picks up (chat apps append U+200B), which would otherwise miss every id. */
function param(sp: URLSearchParams, k: string): string | null {
  return sp.get(k)?.replace(/[\s​-‍⁠﻿]/g, "") || null;
}

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const sp = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const org = param(sp, "org") || "org_a";
  const scan: Scan = param(sp, "scan") === "v2" ? "v2" : "v1";
  const mode: Mode = param(sp, "mode") === "live" ? "live" : "replay";
  const finding = param(sp, "f");
  const orgsQ = useApi<OrgInfo[]>("orgs");

  const scanInfo = orgsQ.data?.find((o) => o.org === org)?.scans.find((s) => s.scan === scan);
  const runs = useMemo(
    () =>
      (scanInfo?.recent_runs ?? [])
        .filter((r) => r.kind === "agent_triage")
        .sort((a, b) => (b.started ?? 0) - (a.started ?? 0)),
    [scanInfo],
  );
  const readonly = !!orgsQ.data?.find((o) => o.org === org)?.readonly;
  const runId = param(sp, "run") || defaultRun(scanInfo, readonly);

  const href = useCallback(
    (path: string, patch: Patch = {}) => {
      const q = nextParams(sp, patch).toString();
      return q ? `${path}?${q}` : path;
    },
    [sp],
  );
  const set = useCallback(
    (patch: Patch, opts?: { push?: boolean }) => {
      const url = href(pathname, patch);
      if (opts?.push) router.push(url, { scroll: false });
      else router.replace(url, { scroll: false });
    },
    [href, pathname, router],
  );

  const value: Workspace = {
    org,
    scan,
    mode,
    finding,
    runId,
    readonly,
    runs,
    scanInfo,
    orgs: orgsQ.data,
    orgsError: orgsQ.error,
    orgsLoading: orgsQ.loading,
    reloadOrgs: orgsQ.reload,
    set,
    href,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
