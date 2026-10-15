"use client";

import { Hourglass } from "lucide-react";

import { EmptyState, ErrorState, LoadingRows } from "@/components/states";
import { useApi } from "@/lib/api";
import { cn } from "@/lib/utils";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Results = { results: Record<string, any> };

const pct = (v: unknown) => (typeof v === "number" ? `${Math.round(v * 100)}%` : "-");
const yes = (v: unknown) =>
  v === true ? <span className="text-safe">yes</span> : v === false ? <span className="text-fg">no</span> : <span className="text-fg-3">-</span>;

function Pass({ ok }: { ok: boolean | undefined }) {
  if (ok === undefined) return null;
  return (
    <span className={cn("mono rounded-sm px-1.5 py-0.5 text-2xs", ok ? "bg-safe/15 text-safe" : "bg-raised text-fg")}>
      {ok ? "PASS" : "FAIL"}
    </span>
  );
}

function Section({ title, sub, pass, children }: { title: string; sub: string; pass?: boolean; children: React.ReactNode }) {
  return (
    <section className="panel overflow-hidden" data-testid="eval-section">
      <div className="flex items-baseline justify-between border-b border-line px-5 py-4">
        <div>
          <p className="text-base font-medium">{title}</p>
          <p className="mt-0.5 text-xs text-fg-3">{sub}</p>
        </div>
        <Pass ok={pass} />
      </div>
      <div className="overflow-x-auto">{children}</div>
    </section>
  );
}

function Table({ head, rows }: { head: string[]; rows: React.ReactNode[][] }) {
  return (
    <table className="w-full text-sm">
      <thead>
        <tr>
          {head.map((h, i) => (
            <th key={h} className={cn("eyebrow px-5 py-2.5 font-medium", i === 0 ? "text-left" : "text-right")}>
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-t border-line">
            {r.map((c, j) => (
              <td key={j} className={cn("num px-5 py-2.5", j === 0 ? "text-left text-fg" : "mono text-right text-fg-2")}>
                {c}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function GateA({ d }: { d: any }) {
  const orgs = Object.values(d.orgs ?? {}) as any[];
  return (
    <Section title="Gate A: the graph tools, no model" sub={`Against the networkx oracle · ${d.reps} reps · ${d.generated}`} pass={d.overall_pass}>
      <Table
        head={["org", "paths", "recall easy", "recall medium", "recall hard", "decoys in top paths", "min cut = oracle size", "cut disconnects", "evidence valid", "attack_paths p50"]}
        rows={orgs.map((o) => [
          o.org,
          o.returned_paths,
          pct(o.recall_by_difficulty?.easy?.recall),
          pct(o.recall_by_difficulty?.medium?.recall),
          pct(o.recall_by_difficulty?.hard?.recall),
          o.decoys_in_top_paths,
          `${o.min_cut?.entry?.size} / ${o.min_cut?.entry?.oracle_size}`,
          yes(o.min_cut?.entry?.disconnects_all_crown_jewels),
          pct(o.evidence?.validity),
          `${o.latency?.attack_paths?.p50_ms ?? "-"} ms`,
        ])}
      />
    </Section>
  );
}

function GateB({ d }: { d: any }) {
  const keys: [string, string, (v: any) => React.ReactNode][] = [
    ["findings investigated", "findings_investigated", (v) => v],
    ["skipped by memory", "skipped_by_memory", (v) => v],
    ["model calls", "llm_calls", (v) => v],
    ["tool calls", "tool_calls", (v) => v],
    ["input tokens", "tokens_in", (v) => Number(v).toLocaleString()],
    ["output tokens", "tokens_out", (v) => Number(v).toLocaleString()],
    ["wall time", "wall_s", (v) => `${v} s`],
    ["cost (USD)", "usd", (v) => (v != null ? `$${Number(v).toFixed(4)}` : "-")],
  ];
  return (
    <Section title="Gate B: memory lift on the rescan" sub={`${d.org} · ${(d.model ?? []).join(", ")}`} pass={d.gate_b?.pass}>
      <Table head={["", "cold", "warm"]} rows={keys.map(([label, k, f]) => [label, f(d.cold?.[k]), f(d.warm?.[k])])} />
    </Section>
  );
}

function Pending() {
  const rows = [
    ["Attack-path recall vs a vector-search baseline (Postgres + pgvector)", "S7"],
    ["Triage precision@k: Reachable order vs CVSS order vs EPSS order", "S7"],
    ["Answer groundedness: claims backed by graph evidence", "S7"],
    ["Cost and latency per run, graph vs baseline", "S7"],
  ];
  return (
    <Section title="Coming in S7" sub="The comparison harness fills these rows; the table is wired to evals/results/*.json.">
      <Table head={["evaluation", "status"]} rows={rows.map(([e, s]) => [e, <span key={e} className="inline-flex items-center gap-1.5 text-fg-3"><Hourglass className="size-3" /> pending {s}</span>])} />
    </Section>
  );
}

function Generic({ name, d }: { name: string; d: any }) {
  const flat: [string, string][] = [];
  const walk = (v: any, p: string, depth: number) => {
    if (flat.length > 40) return;
    if (v && typeof v === "object" && !Array.isArray(v) && depth < 2) for (const [k, x] of Object.entries(v)) walk(x, p ? `${p}.${k}` : k, depth + 1);
    else flat.push([p, Array.isArray(v) ? `[${v.length}]` : typeof v === "object" ? "{…}" : String(v)]);
  };
  walk(d, "", 0);
  return (
    <Section title={name} sub="evals/results">
      <Table head={["key", "value"]} rows={flat} />
    </Section>
  );
}

export function EvalsScreen() {
  const q = useApi<Results>("evals");
  return (
    <div className="mx-auto max-w-[1400px] px-8 pt-7 pb-16">
      <p className="eyebrow">07 · Evals</p>
      <h1 className="mt-2 text-[28px] leading-tight font-semibold tracking-tight">Measured, not claimed</h1>
      <p className="mt-2 max-w-3xl text-base text-fg-2">
        Every number here is read from <code className="mono text-fg">evals/results/*.json</code>, written by the eval
        scripts. Synthetic orgs have an independent oracle (networkx), so &quot;correct&quot; means something.
      </p>
      <div className="mt-8 space-y-6">
        {q.error ? (
          <ErrorState error={q.error} retry={q.reload} what="the eval results" />
        ) : !q.data ? (
          <LoadingRows rows={6} />
        ) : !Object.keys(q.data.results).length ? (
          <EmptyState title="No eval results yet">Run <code className="mono text-fg">make gate-a</code> and <code className="mono text-fg">make memory-lift</code>.</EmptyState>
        ) : (
          <>
            {q.data.results.gate_a && <GateA d={q.data.results.gate_a} />}
            {q.data.results.memory_lift && <GateB d={q.data.results.memory_lift} />}
            {Object.entries(q.data.results)
              .filter(([k]) => k !== "gate_a" && k !== "memory_lift")
              .map(([k, v]) => (
                <Generic key={k} name={k} d={v} />
              ))}
            <Pending />
          </>
        )}
      </div>
    </div>
  );
}
