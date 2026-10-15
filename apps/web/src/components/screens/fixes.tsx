"use client";

import { Check, ChevronRight, FlaskConical, GitMerge, RotateCcw, ShieldCheck, Ticket, UserRound } from "lucide-react";
import { useMemo, useState } from "react";

import { Effort, Seg, shortId } from "@/components/bits";
import { CypherBlock } from "@/components/evidence";
import { AttackGraph, GraphLegend } from "@/components/graph/attack-graph";
import { ErrorState, LoadingRows, Shimmer } from "@/components/states";
import { type ApiError, api, useApi } from "@/lib/api";
import type { Fix, FixPlan, SimResult } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useWorkspace } from "@/lib/workspace";

import { NoRunState, useSubgraph } from "./paths";

type Mode = "fewest" | "cheapest";

function useFixPlan(mode: Mode) {
  const ws = useWorkspace();
  return useApi<FixPlan>(ws.runId ? `runs/${encodeURIComponent(ws.runId)}/fixplan?mode=${mode}` : null);
}

function FixCard({ fix, i, active, onClick }: { fix: Fix; i: number; active: boolean; onClick: () => void }) {
  const [open, setOpen] = useState(false);
  const many = fix.paths_cut > 1;
  const adr = fix.adrs[fix.adrs.length - 1];
  return (
    <li
      data-testid="fix-card"
      data-token={fix.token}
      className={cn(
        "rounded-lg border bg-panel transition-colors",
        active ? "border-fg-3 bg-panel-2" : many ? "border-cut/40" : "border-line",
      )}
    >
      <button onClick={onClick} className="w-full px-4 pt-3.5 pb-3 text-left">
        <div className="flex items-start gap-3">
          <span className="mono mt-0.5 text-xs text-fg-3">{String(i + 1).padStart(2, "0")}</span>
          <div className="min-w-0 flex-1">
            <p className="text-sm leading-snug font-medium">{fix.ticket.title}</p>
            <p className="mt-1 text-xs text-fg-3">
              {fix.hostname ? <span className="mono text-fg-2">{fix.hostname}</span> : <span className="mono text-fg-2">{shortId(fix.token)}</span>}
              {fix.cve && <> · <span className="mono">{fix.cve}</span></>}
            </p>
          </div>
          <div className="flex flex-col items-end gap-1.5">
            <span
              className={cn(
                "mono rounded-sm px-1.5 py-0.5 text-2xs whitespace-nowrap",
                many ? "bg-cut text-bg" : "border border-line-2 text-fg-2",
              )}
            >
              cuts {fix.paths_cut} path{fix.paths_cut === 1 ? "" : "s"}
            </span>
            <Effort n={fix.effort} />
          </div>
        </div>
      </button>
      <div className="grid grid-cols-2 gap-3 border-t border-line px-4 py-3 text-xs">
        <div className="min-w-0">
          <p className="eyebrow">Owner · on call</p>
          {fix.team ? (
            <>
              <p className="mt-1 truncate text-fg">{fix.team.name}</p>
              {fix.on_call && (
                <p className="mt-0.5 flex items-center gap-1 truncate text-fg-2">
                  <UserRound className="size-3" />
                  {fix.on_call.name}
                  <span className="text-fg-3">· {fix.on_call.role}</span>
                </p>
              )}
            </>
          ) : (
            <p className="mt-1 text-fg-3">No owning asset (a credential or role)</p>
          )}
        </div>
        <div className="min-w-0">
          <p className="eyebrow">Opened by</p>
          {adr ? (
            <>
              <p className="mt-1 truncate text-fg" title={adr.title}>
                {adr.title.split(":")[0]}
              </p>
              <p className="mt-0.5 truncate text-fg-2">
                {adr.approved_by} <span className="text-fg-3">· {adr.date}</span>
              </p>
            </>
          ) : (
            <p className="mt-1 text-fg-3">No recorded decision</p>
          )}
        </div>
      </div>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 border-t border-line px-4 py-2 text-left text-xs text-fg-2 hover:text-fg"
      >
        <ChevronRight className={cn("size-3.5 transition-transform", open && "rotate-90")} />
        <Ticket className="size-3.5" /> Drafted ticket
        <span className="ml-auto text-2xs text-fg-3">{fix.ticket.by === "llm" ? "by the Fixer (model)" : "from the template"}</span>
      </button>
      {open && (
        <div className="space-y-2 border-t border-line px-4 py-3 text-xs">
          <p className="font-medium text-fg">{fix.ticket.title}</p>
          <p className="leading-relaxed text-fg-2">{fix.ticket.body}</p>
          {adr && <p className="text-fg-3">{adr.title}</p>}
          <p className="mono text-2xs text-fg-3">{fix.action}</p>
        </div>
      )}
    </li>
  );
}

export function FixesScreen() {
  const ws = useWorkspace();
  // A different run is a different plan: start clean (no simulation shown).
  return <FixesView key={ws.runId ?? "none"} />;
}

function FixesView() {
  const ws = useWorkspace();
  const fewest = useFixPlan("fewest");
  const cheapest = useFixPlan("cheapest");
  const [mode, setModeState] = useState<Mode | null>(null);
  const sub = useSubgraph();
  const [sim, setSim] = useState<SimResult | null>(null);
  const [simErr, setSimErr] = useState<ApiError | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [activeToken, setActiveToken] = useState<string | null>(null);

  const chosen = (fewest.data?.chosen ?? cheapest.data?.chosen ?? "cheapest") as Mode;
  const m: Mode = mode ?? chosen;
  const plan = m === "fewest" ? fewest : cheapest;
  const g = sub.data;

  const setMode = (next: Mode) => {
    setModeState(next);
    setSim(null);
    setSimErr(null);
    setActiveToken(null);
  };

  // "One fix, many paths": the hops a single fix in this cut takes out of
  // several paths at once. They are where the paths converge.
  const hubs = useMemo(() => {
    if (!g) return [];
    const cut = new Set(g.cuts[m]);
    const out = new Set<string>();
    for (const e of g.edges) {
      if (e.fix_token && cut.has(e.fix_token) && e.token_paths > 1) {
        // the node the shared step leads into, or the shared node it leaves
        const into = g.nodes.find((n) => n.id === e.target);
        out.add((into?.shared ?? 0) > 1 ? e.target : e.source);
      }
    }
    return [...out];
  }, [g, m]);

  const focusPaths = useMemo(() => {
    if (!g || !activeToken) return null;
    const ps = new Set<number>();
    for (const e of g.edges) if (e.fix_token === activeToken) e.paths.forEach((p) => ps.add(p));
    return [...ps];
  }, [g, activeToken]);

  const view = useMemo(
    () => ({ cut: m, severed: !!sim?.data.all_crown_jewels_disconnected, hubs, focusPaths: sim ? null : focusPaths }),
    [m, sim, hubs, focusPaths],
  );

  if (!ws.runId) return <NoRunState />;
  const err = plan.error || sub.error;
  if (err) return <ErrorState error={err} retry={() => (plan.reload(), sub.reload())} what="the fix plan" />;

  const p = plan.data;
  const convergent = p?.fixes.filter((f) => f.paths_cut > 1) ?? [];
  const crown = p?.reachable_before ?? [];
  const crownName = (id: string) => g?.nodes.find((n) => n.id === id)?.name ?? shortId(id);

  const simulate = async () => {
    if (!p) return;
    setSimulating(true);
    setSimErr(null);
    try {
      setSim(await api<SimResult>(`orgs/${ws.org}/simulate`, { json: { scan: ws.scan, fix_tokens: p.fix_tokens } }));
    } catch (e) {
      setSimErr(e as ApiError);
    } finally {
      setSimulating(false);
    }
  };

  const label = (mm: Mode, q: typeof fewest) =>
    q.data ? (
      <span className="flex items-baseline gap-2">
        {mm === "fewest" ? "Fewest fixes" : "Cheapest fixes"}
        <span className="mono text-2xs text-fg-3">
          {q.data.fix_tokens.length} · effort {q.data.total_effort}
        </span>
        {q.data.chosen === mm && <Check className="size-3 text-fg-2" aria-label="the agents' choice" />}
      </span>
    ) : mm === "fewest" ? (
      "Fewest fixes"
    ) : (
      "Cheapest fixes"
    );

  return (
    <div className="flex h-full min-h-[760px] flex-col px-8 pt-6 pb-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">03 · Fix plan · minimum cut</p>
          <h1 className="mt-2 text-[26px] leading-tight font-semibold tracking-tight">
            {p ? (
              <>
                {p.fix_tokens.length} fixes cut all {p.paths} attack paths
                <span className="text-fg-3"> · total effort {p.total_effort}</span>
              </>
            ) : (
              "Computing the cut…"
            )}
          </h1>
          <p className="mt-1 line-clamp-2 max-w-5xl text-sm text-fg-2">
            Max-flow / min-cut on the attack graph: the smallest set of fixes that disconnects the Internet from every
            crown jewel.{" "}
            {p?.chosen && <span className="text-fg-3">The agents chose “{p.chosen}”{p.rationale ? `: ${p.rationale}` : "."}</span>}
          </p>
        </div>
        <Seg
          testid="cut-mode"
          value={m}
          onChange={setMode}
          options={[
            { value: "fewest", label: label("fewest", fewest), hint: "Capacity 1 per fix: the fewest fixes" },
            { value: "cheapest", label: label("cheapest", cheapest), hint: "Capacity = effort (1-5): the least work" },
          ]}
        />
      </div>

      <div className="mt-5 grid min-h-0 flex-1 grid-cols-[minmax(0,1fr)_440px] gap-4">
        <div className="flex min-h-0 flex-col gap-4">
          <div className="panel relative min-h-[460px] flex-1 overflow-hidden">
            {g ? (
              <>
                <AttackGraph graph={g} view={view} testid="fix-graph" />
                <div className="pointer-events-none absolute top-3 left-4">
                  <GraphLegend cut severed={!!sim} />
                </div>
              </>
            ) : (
              <div className="grid h-full place-items-center">
                <Shimmer className="h-40 w-2/3" />
              </div>
            )}
          </div>

          <div className="panel flex flex-wrap items-center gap-6 px-5 py-4" data-testid="simulate-panel">
            <div className="flex flex-wrap items-center gap-3">
              {crown.map((c) => {
                const safe = !!sim && !sim.data.reachable_after.includes(c);
                return (
                  <div
                    key={c}
                    data-testid="crown-status"
                    data-state={safe ? "safe" : "reachable"}
                    className={cn(
                      "flex items-center gap-3 rounded-md border px-3.5 py-2 transition-colors duration-500",
                      safe ? "border-safe/50 bg-safe/10" : "border-ember/50 bg-ember/10",
                    )}
                  >
                    {safe ? <ShieldCheck className="size-4 text-safe" /> : <span className="size-2.5 animate-pulse-ember rounded-full bg-ember" />}
                    <span className="text-sm font-medium">{crownName(c)}</span>
                    <span className={cn("mono text-xs font-semibold tracking-wider", safe ? "text-safe" : "text-ember")}>
                      {safe ? "SAFE" : "REACHABLE"}
                    </span>
                  </div>
                );
              })}
            </div>
            <div className="ml-auto flex items-center gap-3">
              {sim && (
                <p className="max-w-md text-xs text-fg-2" data-testid="simulate-summary">
                  {sim.summary}
                </p>
              )}
              {sim ? (
                <button
                  onClick={() => setSim(null)}
                  className="flex items-center gap-2 rounded-md border border-line-2 px-3 py-2 text-sm text-fg-2 hover:text-fg"
                >
                  <RotateCcw className="size-4" /> Reset
                </button>
              ) : (
                <button
                  data-testid="simulate-button"
                  disabled={!p || simulating}
                  onClick={simulate}
                  className="flex items-center gap-2 rounded-md bg-fg px-4 py-2 text-sm font-medium text-bg hover:bg-white disabled:opacity-50"
                >
                  <FlaskConical className="size-4" />
                  {simulating ? "Simulating on a copy of the graph…" : `Simulate these ${p?.fix_tokens.length ?? ""} fixes`}
                </button>
              )}
            </div>
            {simErr && <p className="w-full text-xs text-fg-2">Simulation failed: {simErr.message}</p>}
            {sim && (
              <div className="w-full">
                <CypherBlock queries={sim.queries} title="How it was proved (GRAPH.COPY, drop the cut steps, search again)" />
              </div>
            )}
          </div>
        </div>

        <aside className="flex min-h-0 flex-col gap-3 overflow-hidden">
          {convergent.length > 0 && (
            <div className="rounded-lg border border-cut/40 bg-panel-2 p-4" data-testid="convergence">
              <p className="flex items-center gap-2 text-sm font-medium">
                <GitMerge className="size-4" /> One fix, many paths
              </p>
              {convergent.map((f) => (
                <p key={f.token} className="mt-1.5 text-sm text-fg-2">
                  <span className="text-fg">{f.ticket.title}</span> cuts <span className="text-fg">{f.paths_cut} paths</span>{" "}
                  at once: they all converge on {f.hostname ? <span className="mono">{f.hostname}</span> : "one shared hop"}.
                </p>
              ))}
            </div>
          )}
          <ol className="min-h-0 flex-1 space-y-2.5 overflow-y-auto pr-1">
            {!p ? (
              <LoadingRows rows={5} />
            ) : (
              [...p.fixes].sort((a, b) => b.paths_cut - a.paths_cut).map((f, i) => (
                <FixCard
                  key={f.token}
                  fix={f}
                  i={i}
                  active={activeToken === f.token}
                  onClick={() => setActiveToken(activeToken === f.token ? null : f.token)}
                />
              ))
            )}
          </ol>
        </aside>
      </div>
    </div>
  );
}
