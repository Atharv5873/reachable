"use client";

import { ArrowRight, MousePointerClick } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";

import { Seg, shortId } from "@/components/bits";
import { WhyStepPanel } from "@/components/evidence";
import { AttackGraph, GraphLegend } from "@/components/graph/attack-graph";
import { EmptyState, ErrorState, LoadingRows, Shimmer } from "@/components/states";
import { useApi } from "@/lib/api";
import type { Board, GEdge, Subgraph } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useWorkspace } from "@/lib/workspace";

import { useBoard } from "./findings";

export function useSubgraph(opts: { finding?: string | null; context?: boolean; run?: string | null } = {}) {
  const ws = useWorkspace();
  const run = opts.run === undefined ? ws.runId : opts.run;
  const qs = new URLSearchParams();
  if (opts.finding) qs.set("finding", opts.finding);
  if (opts.context) qs.set("context", "true");
  const q = run ? `runs/${encodeURIComponent(run)}/subgraph${qs.size ? `?${qs}` : ""}` : null;
  return useApi<Subgraph>(q);
}

/** What a run-based screen shows when there is no run to read: the backend's
 *  error, a loading state, or how to get a first run. */
export function NoRunState() {
  const ws = useWorkspace();
  if (ws.orgsError) return <ErrorState error={ws.orgsError} retry={ws.reloadOrgs} what="the workspace" />;
  if (!ws.orgs) return <LoadingRows label="Loading the workspace" />;
  return <NoRun />;
}

export function NoRun() {
  const ws = useWorkspace();
  return (
    <EmptyState title={`No finished run for ${ws.org} scan ${ws.scan} yet`}>
      Replay reads a finished run from the graph. Start one from{" "}
      <Link className="text-fg underline" href={ws.href("/live", { mode: "live" })}>
        Investigation
      </Link>{" "}
      or run <code className="mono text-fg">make triage ORG={ws.org} SCAN={ws.scan}</code>.
    </EmptyState>
  );
}

function PathList({
  g,
  focus,
  setFocus,
  onStep,
  selected,
}: {
  g: Subgraph;
  focus: number | null;
  setFocus: (i: number | null) => void;
  onStep: (key: string) => void;
  selected: string | null;
}) {
  const names = new Map(g.nodes.map((n) => [n.id, n.kind === "internet" ? "Internet" : n.name]));
  const edges = new Map(g.edges.map((e) => [e.id, e]));
  return (
    <ol className="space-y-2 p-4">
      {g.paths.map((p) => (
        <li key={p.index}>
          <button
            onClick={() => setFocus(focus === p.index ? null : p.index)}
            data-testid="path-item"
            className={cn(
              "w-full rounded-md border px-3 py-2.5 text-left transition-colors",
              focus === p.index ? "border-ember/60 bg-raised" : "border-line hover:bg-panel-2",
            )}
          >
            <div className="flex items-baseline justify-between">
              <span className="text-sm font-medium">Path #{p.index + 1}</span>
              <span className="mono num text-xs text-fg-2">p = {p.likelihood.toFixed(3)}</span>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-x-1 gap-y-1 text-2xs">
              {p.nodes.map((n, i) => (
                <span key={n + i} className="flex items-center gap-1">
                  {i > 0 && (
                    <span
                      role="button"
                      onClick={(ev) => {
                        ev.stopPropagation();
                        onStep(p.steps[i - 1]);
                      }}
                      className={cn(
                        "mono rounded-sm px-1 text-ember hover:bg-ember/15",
                        selected === p.steps[i - 1] && "bg-ember/20",
                      )}
                      title="Why this step?"
                    >
                      {edges.get(p.steps[i - 1])?.technique ?? "→"}
                    </span>
                  )}
                  <span className="mono text-fg-2">{names.get(n) ?? shortId(n)}</span>
                </span>
              ))}
            </div>
          </button>
        </li>
      ))}
    </ol>
  );
}

export function PathsScreen() {
  const ws = useWorkspace();
  // A new run or a new selected finding starts a fresh view of the graph.
  return <PathsView key={`${ws.runId}|${ws.finding}`} />;
}

function PathsView() {
  const ws = useWorkspace();
  const board = useBoard();
  const [scope, setScopeState] = useState<"finding" | "all">(ws.finding ? "finding" : "all");
  const [context, setContext] = useState(false);
  const [focus, setFocus] = useState<number | null>(null);
  const [edge, setEdge] = useState<string | null>(null);
  const finding = scope === "finding" ? ws.finding : null;
  const sub = useSubgraph({ finding, context });

  const setScope = (s: "finding" | "all") => {
    setScopeState(s);
    setFocus(null);
    setEdge(null);
  };

  const row = ws.finding ? board.data?.findings[ws.finding] : undefined;
  const node = useSearchParams().get("node"); // from the company brain: an asset to point at
  const crown = board.data?.crown_jewels.map((c) => c.name).join(", ") ?? "crown jewel";
  const view = useMemo(
    () => ({ focusPaths: focus === null ? null : [focus], selectedEdge: edge, focusNode: node ?? row?.asset ?? null }),
    [focus, edge, row?.asset, node],
  );

  if (!ws.runId) return <NoRunState />;

  const g = sub.data;
  const title =
    scope === "finding" && row
      ? row.status === "reachable"
        ? `${g?.paths.length ?? "…"} path${g?.paths.length === 1 ? "" : "s"} through ${row.hostname} to the ${crown}`
        : `Nothing an attacker holds reaches ${row.hostname}`
      : `Every way in: ${g?.total_paths ?? "…"} attack paths from the Internet to the ${crown}`;

  return (
    <div className="flex h-full min-h-[720px] flex-col px-8 pt-6 pb-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">02 · Attack paths</p>
          <h1 className="mt-2 text-[26px] leading-tight font-semibold tracking-tight" data-testid="paths-title">
            {title}
          </h1>
          {scope === "finding" && row && (
            <p className="mt-1 text-sm text-fg-2">
              <span className="mono text-fg">{row.cve}</span> · CVSS {row.cvss?.toFixed(1)} · {row.why}
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          <Seg
            value={scope}
            onChange={(s) => setScope(s)}
            options={[
              { value: "finding", label: ws.finding ? `Selected: ${shortId(ws.finding)}` : "Selected finding" },
              { value: "all", label: `All paths to the ${crown}` },
            ]}
          />
          <label className="flex items-center gap-2 text-xs text-fg-2">
            <input type="checkbox" checked={context} onChange={(e) => setContext(e.target.checked)} className="accent-[var(--fg-2)]" />
            +1 hop of context
          </label>
        </div>
      </div>

      <div className="mt-5 grid min-h-0 flex-1 grid-cols-[minmax(0,1fr)_400px] gap-4">
        <div className="panel relative min-h-[560px] overflow-hidden">
          {sub.error ? (
            <ErrorState error={sub.error} retry={sub.reload} what="the attack graph" />
          ) : scope === "finding" && !ws.finding ? (
            <EmptyState title="No finding selected">
              Pick one on{" "}
              <Link className="text-fg underline" href={ws.href("/findings")}>
                Findings
              </Link>
              , or show all paths.
            </EmptyState>
          ) : !g ? (
            <div className="grid h-full place-items-center">
              <Shimmer className="h-40 w-2/3" />
            </div>
          ) : g.paths.length === 0 ? (
            <EmptyState title={row ? `No attack path reaches ${row.hostname}` : "No attack path in this run"}>
              {row?.why ?? "The derived attack layer has no Internet → crown-jewel walk."} A CVSS-first list would
              still put it near the top.
              <div className="mt-4">
                <button onClick={() => setScope("all")} className="text-fg underline">
                  Show every path instead
                </button>
              </div>
            </EmptyState>
          ) : (
            <>
              <AttackGraph
                graph={g}
                view={view}
                onEdge={(e: GEdge) => setEdge(e.id)}
                onNode={(n) => {
                  const p = n.paths[0];
                  if (p !== undefined && n.paths.length === 1) setFocus(p);
                }}
              />
              <div className="pointer-events-none absolute top-3 left-4">
                <GraphLegend />
              </div>
            </>
          )}
        </div>

        <aside className="panel flex min-h-0 flex-col overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-4 py-3">
            <p className="text-sm font-medium">{edge ? "Step evidence" : "Paths"}</p>
            {edge && (
              <button onClick={() => setEdge(null)} className="text-xs text-fg-3 hover:text-fg">
                Back to paths
              </button>
            )}
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            {edge ? (
              <WhyStepPanel stepKey={edge} />
            ) : g && g.paths.length ? (
              <>
                <p className="flex items-center gap-2 px-4 pt-4 text-xs text-fg-3">
                  <MousePointerClick className="size-3.5" /> Click a technique (or an edge) to see the evidence
                  behind that step.
                </p>
                <PathList g={g} focus={focus} setFocus={setFocus} onStep={setEdge} selected={edge} />
              </>
            ) : (
              !sub.error && !g && <LoadingRows rows={4} />
            )}
          </div>
          {g && g.paths.length > 0 && (
            <Link
              href={ws.href("/fixes")}
              className="flex items-center justify-between border-t border-line px-4 py-3 text-sm hover:bg-panel-2"
            >
              <span>
                The fewest fixes that cut all {g.total_paths} paths
              </span>
              <ArrowRight className="size-4" />
            </Link>
          )}
        </aside>
      </div>
    </div>
  );
}

export type { Board };
