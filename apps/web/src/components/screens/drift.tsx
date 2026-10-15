"use client";

import { AlertOctagon, ArrowRight, BrainCircuit, CircleCheck, History, Play, ShieldOff, Sparkles } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";

import { Stat, Verdict, shortId, shortRun } from "@/components/bits";
import { AttackGraph, GraphLegend } from "@/components/graph/attack-graph";
import { EmptyState, ErrorState, LoadingRows, Shimmer } from "@/components/states";
import { type ApiError, api, invalidate, useApi } from "@/lib/api";
import type { RunDump, RunHead, Subgraph } from "@/lib/types";
import { cn } from "@/lib/utils";
import { isStub, useWorkspace } from "@/lib/workspace";

type DriftPath = { target: string; nodes: { id: string; name: string }[]; steps?: unknown[]; fixed_findings?: string[]; likelihood?: number };
type Drift = {
  summary: string;
  data: {
    arrived_findings: string[];
    left_findings: string[];
    new_paths: DriftPath[];
    closed_paths: DriftPath[];
    cost_changed: unknown[];
    unchanged: number;
    new_crown_path: boolean;
    paths_before: number;
    paths_after: number;
    from: { date: string };
    to: { date: string };
  };
};

type Lift = Record<string, number | string | boolean | null | object>;

function latest(runs: RunHead[] | undefined): RunHead | undefined {
  const done = (runs ?? []).filter((r) => r.kind === "agent_triage" && r.status === "complete");
  done.sort((a, b) => (b.started ?? 0) - (a.started ?? 0));
  return done.find((r) => !isStub(r)) ?? done[0];
}

function Hops({ p, struck }: { p: DriftPath; struck?: boolean }) {
  return (
    <p className={cn("mono flex flex-wrap items-center gap-x-1.5 gap-y-1 text-xs", struck ? "text-fg-3 line-through decoration-fg-3" : "text-fg")}>
      {p.nodes.map((n, i) => (
        <span key={n.id + i} className="flex items-center gap-1.5">
          {i > 0 && <ArrowRight className={cn("size-3", struck ? "text-fg-3" : "text-ember")} />}
          {n.id === "internet" ? "Internet" : n.name}
        </span>
      ))}
    </p>
  );
}

function MemoryLift() {
  const ev = useApi<{ results: Record<string, Record<string, Lift>> }>("evals");
  const lift = ev.data?.results?.memory_lift as Record<string, Lift> | undefined;
  if (ev.error) return null;
  if (!lift) return <Shimmer className="h-40" />;
  const cold = lift.cold as Lift;
  const warm = lift.warm as Lift;
  const rows: [string, string, (v: Lift) => string][] = [
    ["Findings investigated", "findings_investigated", (v) => String(v.findings_investigated)],
    ["Skipped by memory", "skipped_by_memory", (v) => String(v.skipped_by_memory)],
    ["Tool calls", "tool_calls", (v) => String(v.tool_calls)],
    ["Model calls", "llm_calls", (v) => String(v.llm_calls)],
    ["Input tokens", "tokens_in", (v) => Number(v.tokens_in).toLocaleString()],
    ["Cost (USD)", "usd", (v) => (v.usd != null ? `$${Number(v.usd).toFixed(4)}` : "-")],
  ];
  const gate = lift.gate_b as { pass?: boolean } | undefined;
  return (
    <div className="panel p-5" data-testid="memory-lift">
      <div className="flex items-baseline justify-between">
        <p className="flex items-center gap-2 text-sm font-medium">
          <BrainCircuit className="size-4" /> Memory lift (Gate B)
        </p>
        {gate && (
          <span className={cn("mono rounded-sm px-1.5 py-0.5 text-2xs", gate.pass ? "bg-safe/15 text-safe" : "bg-raised text-fg-2")}>
            {gate.pass ? "PASS" : "FAIL"}
          </span>
        )}
      </div>
      <p className="mt-1 text-xs text-fg-3">Same rescan, same model: without memory (cold) vs with v1&apos;s memory (warm).</p>
      <table className="mt-4 w-full text-sm">
        <thead>
          <tr className="text-left">
            <th className="eyebrow pb-2 font-medium" />
            <th className="eyebrow pb-2 text-right font-medium">cold</th>
            <th className="eyebrow pb-2 text-right font-medium">warm</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([label, , f]) => (
            <tr key={label} className="border-t border-line">
              <td className="py-1.5 text-fg-2">{label}</td>
              <td className="mono num py-1.5 text-right text-fg-2">{f(cold)}</td>
              <td className="mono num py-1.5 text-right font-medium text-fg">{f(warm)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-3 text-2xs text-fg-3">Both reach the same verified minimal fix set. From evals/results/memory_lift.json.</p>
    </div>
  );
}

function AnalystLoop({ v1Run }: { v1Run: RunHead | undefined }) {
  const ws = useWorkspace();
  const router = useRouter();
  const dump = useApi<RunDump>(v1Run ? `runs/${encodeURIComponent(v1Run.id)}` : null);
  const verdicts: { finding: string; decision: string }[] = dump.data?.outputs.Report?.payload?.verdicts ?? [];
  const choices = verdicts.filter((v) => v.decision !== "not_reachable");
  const [finding, setFinding] = useState<string>("");
  const [days, setDays] = useState(90);
  const [reason, setReason] = useState("Compensating control in place; vendor fix lands next quarter.");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<{ verdict: string; risk_acceptance?: { id: string; expires: number } } | null>(null);
  const [err, setErr] = useState<ApiError | null>(null);
  const [startErr, setStartErr] = useState<ApiError | null>(null);
  const pick = finding || choices[choices.length - 1]?.finding || "";

  const accept = async () => {
    if (!v1Run || !pick) return;
    setBusy(true);
    setErr(null);
    try {
      setDone(
        await api(`runs/${encodeURIComponent(v1Run.id)}/verdict`, {
          json: { finding: pick, decision: "accept", reason, accept_risk_days: days },
        }),
      );
    } catch (e) {
      setErr(e as ApiError);
    } finally {
      setBusy(false);
    }
  };

  const runV2 = async () => {
    setStartErr(null);
    try {
      const r = await api<{ run_id: string }>("runs", { json: { org: ws.org, scan: "v2" } });
      invalidate("orgs");
      router.push(ws.href("/live", { scan: "v2", run: r.run_id, mode: "live", watch: "1" }));
    } catch (e) {
      setStartErr(e as ApiError);
    }
  };

  return (
    <div className="panel p-5" data-testid="analyst-loop">
      <p className="text-sm font-medium">The analyst loop</p>
      <p className="mt-1 text-xs text-fg-3">
        Decide on v1 → rescan → the v2 run starts from that memory. In replay these steps are already recorded.
      </p>
      <ol className="mt-4 space-y-4">
        <li>
          <p className="eyebrow mb-2">1 · Accept a finding as a risk (v1 run {shortRun(v1Run?.id)})</p>
          {!v1Run ? (
            <p className="text-xs text-fg-3">No finished v1 run.</p>
          ) : (
            <div className="space-y-2">
              <div className="flex gap-2">
                <select
                  data-testid="accept-finding"
                  value={pick}
                  onChange={(e) => setFinding(e.target.value)}
                  className="mono h-9 flex-1 rounded-md border border-line bg-panel-2 px-2 text-xs"
                >
                  {choices.map((v) => (
                    <option key={v.finding} value={v.finding}>
                      {shortId(v.finding)} · agent said {v.decision.replace("_", " ")}
                    </option>
                  ))}
                </select>
                <select value={days} onChange={(e) => setDays(Number(e.target.value))} className="h-9 rounded-md border border-line bg-panel-2 px-2 text-xs">
                  {[30, 90, 180].map((d) => (
                    <option key={d} value={d}>
                      {d} days
                    </option>
                  ))}
                </select>
              </div>
              <input
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                className="h-9 w-full rounded-md border border-line bg-panel-2 px-3 text-xs outline-none focus:border-fg-3"
              />
              <button
                data-testid="accept-risk"
                onClick={accept}
                disabled={busy || ws.mode !== "live" || !!done}
                title={ws.mode !== "live" ? "Switch to Live to write to memory" : undefined}
                className="flex items-center gap-2 rounded-md border border-line-2 px-3 py-1.5 text-xs text-fg hover:bg-raised disabled:opacity-40"
              >
                <ShieldOff className="size-3.5" />
                {done ? "Accepted" : "Accept as risk (writes through /verdict)"}
              </button>
              {done?.risk_acceptance && (
                <p className="flex items-center gap-1.5 text-xs text-fg-2">
                  <CircleCheck className="size-3.5 text-safe" /> {done.risk_acceptance.id} until{" "}
                  {new Date(done.risk_acceptance.expires * 1000).toISOString().slice(0, 10)}
                </p>
              )}
              {err && <p className="text-xs text-fg-2">{err.message}</p>}
            </div>
          )}
        </li>
        <li>
          <p className="eyebrow mb-2">2 · Run the rescan (v2) with that memory</p>
          <button
            data-testid="run-v2"
            onClick={runV2}
            disabled={ws.mode !== "live"}
            title={ws.mode !== "live" ? "Switch to Live to start a run" : undefined}
            className="flex items-center gap-2 rounded-md bg-fg px-3 py-1.5 text-xs font-medium text-bg disabled:opacity-40"
          >
            <Play className="size-3.5" /> Start the v2 run and watch it
          </button>
          {startErr && (
            <p className="mt-2 text-xs text-fg-2">
              {startErr.status === 429 ? `Two runs already in progress; retry in ~${startErr.retryAfter ?? 30} s.` : startErr.message}
            </p>
          )}
        </li>
        <li>
          <p className="eyebrow">3 · What the v2 run recognised is on the left</p>
        </li>
      </ol>
    </div>
  );
}

export function DriftScreen() {
  const ws = useWorkspace();
  const drift = useApi<Drift>(`orgs/${ws.org}/drift`);
  const scans = ws.orgs?.find((o) => o.org === ws.org)?.scans;
  const v1Run = latest(scans?.find((s) => s.scan === "v1")?.recent_runs);
  const v2Run = (ws.scan === "v2" && ws.runId ? { id: ws.runId } : undefined) ?? latest(scans?.find((s) => s.scan === "v2")?.recent_runs);
  const v2 = useApi<RunDump>(v2Run ? `runs/${encodeURIComponent(v2Run.id)}` : null);
  const sub = useApi<Subgraph>(v2Run ? `runs/${encodeURIComponent(v2Run.id)}/subgraph` : null);

  const newPaths = useMemo(() => {
    const g = sub.data;
    if (!g) return null;
    return g.paths.filter((p) => p.steps.some((k) => g.edges.find((e) => e.id === k)?.new)).map((p) => p.index);
  }, [sub.data]);

  if (drift.error) return <ErrorState error={drift.error} retry={drift.reload} what="the drift between scans" />;
  const d = drift.data?.data;
  const tri = v2.data?.outputs.Triage?.payload;
  const dr = v2.data?.outputs.Drift?.payload;
  const carried: { finding: string; decision: string; decided: string; reason?: string; hostname?: string; verdict?: string }[] = tri?.carried ?? [];
  const suppressed: { finding: string; approved_by: string; expires_date: string; reason: string }[] = tri?.suppressed ?? [];
  const flagged: Record<string, { description: string; pattern: string }[]> = tri?.flagged_on_arrival ?? dr?.flagged_on_arrival ?? {};

  return (
    <div className="mx-auto max-w-[1560px] px-8 pt-6 pb-16">
      <p className="eyebrow">06 · Drift · v1 → v2</p>
      <h1 className="mt-2 text-[28px] leading-tight font-semibold tracking-tight">
        A week later: what changed <span className="text-fg-3">for an attacker</span>?
      </h1>
      <p className="mt-2 max-w-3xl text-base text-fg-2">
        The Sentinel diffs the two scans&apos; Internet → crown-jewel path sets, with no model. It alerts only on a path that
        did not exist before. Then memory decides what is worth looking at again.
      </p>

      {!d ? (
        <LoadingRows rows={3} />
      ) : (
        <div className="mt-6 flex flex-wrap gap-x-12 gap-y-4" data-testid="drift-stats">
          <Stat label="Crown-jewel paths" value={`${d.paths_before} → ${d.paths_after}`} sub={`${d.from.date} → ${d.to.date}`} />
          <Stat label="New paths" value={d.new_paths.length} tone={d.new_paths.length ? "ember" : undefined} sub={d.new_crown_path ? "alert raised" : "no alert"} />
          <Stat label="Closed paths" value={d.closed_paths.length} sub="fixed since v1" />
          <Stat label="Cost changed" value={d.cost_changed.length} sub={`${d.unchanged} unchanged`} />
          <Stat label="Findings" value={`+${d.arrived_findings.length} / −${d.left_findings.length}`} sub="arrived / left" />
        </div>
      )}

      <div className="mt-8 grid grid-cols-[minmax(0,1fr)_420px] gap-4">
        <div className="space-y-4">
          <div className="panel relative h-[520px] overflow-hidden">
            <div className="absolute top-3 left-4 z-10 flex items-center gap-3">
              {d?.new_crown_path && (
                <span className="flex items-center gap-1.5 rounded-sm bg-ember px-2 py-0.5 text-2xs font-semibold tracking-wider text-bg" data-testid="drift-alert">
                  <AlertOctagon className="size-3" /> NEW CROWN PATH
                </span>
              )}
              <GraphLegend showNew />
            </div>
            {!v2Run ? (
              <EmptyState title="No v2 run yet">Run the rescan (right) to see what it recognised.</EmptyState>
            ) : sub.error ? (
              <ErrorState error={sub.error} retry={sub.reload} what="the v2 graph" />
            ) : sub.data ? (
              <AttackGraph graph={sub.data} view={{ showNew: true, focusPaths: newPaths?.length ? newPaths : null }} testid="drift-graph" />
            ) : (
              <div className="grid h-full place-items-center">
                <Shimmer className="h-40 w-2/3" />
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="panel p-5">
              <p className="flex items-center gap-2 text-sm font-medium">
                <AlertOctagon className="size-4 text-ember" /> New since v1
              </p>
              <div className="mt-3 space-y-3">
                {d?.new_paths.map((p, i) => (
                  <div key={i}>
                    <Hops p={p} />
                  </div>
                ))}
                {d && !d.new_paths.length && <p className="text-xs text-fg-3">None: no alert.</p>}
              </div>
            </div>
            <div className="panel p-5">
              <p className="flex items-center gap-2 text-sm font-medium">
                <CircleCheck className="size-4 text-safe" /> Closed since v1
              </p>
              <div className="mt-3 space-y-3">
                {d?.closed_paths.map((p, i) => (
                  <div key={i}>
                    <Hops p={p} struck />
                    {p.fixed_findings?.length ? (
                      <p className="mt-1 text-2xs text-fg-3">fixed: {p.fixed_findings.map(shortId).join(", ")} · reported, never alerted</p>
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="panel p-5" data-testid="memory-recognised">
            <p className="flex items-center gap-2 text-sm font-medium">
              <History className="size-4" /> What the v2 run recognised from memory
              {v2Run && <span className="mono text-2xs text-fg-3">run {shortRun(v2Run.id)}</span>}
            </p>
            {!v2.data ? (
              <LoadingRows rows={3} />
            ) : (
              <div className="mt-4 grid grid-cols-3 gap-5">
                <div>
                  <p className="eyebrow mb-2">Carried verdicts · {carried.length}</p>
                  <ul className="space-y-1.5">
                    {carried.slice(0, 6).map((c) => (
                      <li key={c.finding} className="flex items-center gap-2 text-xs">
                        <span className="mono text-fg">{shortId(c.finding)}</span>
                        <Verdict v={c.decision} />
                        <span className="truncate text-fg-3">since {c.decided}</span>
                      </li>
                    ))}
                  </ul>
                  <p className="mt-2 text-2xs text-fg-3">Not re-investigated: nothing changed for them.</p>
                </div>
                <div>
                  <p className="eyebrow mb-2">Accepted risk · {suppressed.length}</p>
                  <ul className="space-y-2">
                    {suppressed.map((s) => (
                      <li key={s.finding} className="text-xs" data-testid="accepted-risk">
                        <p>
                          <span className="mono text-fg">{shortId(s.finding)}</span>{" "}
                          <span className="text-fg-3">until {s.expires_date}</span>
                        </p>
                        <p className="mt-0.5 text-fg-3">
                          {s.approved_by}: {s.reason}
                        </p>
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <p className="eyebrow mb-2">Flagged on arrival · {Object.keys(flagged).length}</p>
                  <ul className="space-y-2">
                    {Object.entries(flagged)
                      .slice(0, 3)
                      .map(([f, ps]) => (
                        <li key={f} className="text-xs">
                          <p className="flex items-center gap-1.5">
                            <Sparkles className="size-3 text-fg-2" />
                            <span className="mono text-fg">{shortId(f)}</span>
                          </p>
                          <p className="mt-0.5 line-clamp-2 text-fg-3">{ps[0]?.description}</p>
                        </li>
                      ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        </div>

        <aside className="space-y-4">
          <AnalystLoop v1Run={v1Run} />
          <MemoryLift />
          <Link href={ws.href("/findings", { scan: "v2" })} className="panel flex items-center justify-between p-4 text-sm hover:bg-panel-2">
            The v2 findings, re-ranked <ArrowRight className="size-4" />
          </Link>
        </aside>
      </div>
    </div>
  );
}
