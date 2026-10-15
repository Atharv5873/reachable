"use client";

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

const num = (v: unknown, n = 2) => (typeof v === "number" ? v.toFixed(n) : "-");
const mean = (s: any) => (s && typeof s.mean === "number" ? s.mean : undefined);
const sdNote = (s: any, f: (v: number) => string) =>
  s && s.n > 1 && s.sd > 0 ? <span className="text-fg-3"> ±{f(s.sd)}</span> : null;
const pctSd = (s: any) => (
  <>
    {pct(mean(s))}
    {sdNote(s, (v) => `${Math.round(v * 100)}`)}
  </>
);
const numSd = (s: any) => (
  <>
    {num(mean(s))}
    {sdNote(s, (v) => v.toFixed(2))}
  </>
);

function Comparison({ d }: { d: any }) {
  const agg = d.aggregate ?? {};
  const ps: string[] = agg.prioritisers ?? [];
  const ceil = Object.values(agg.ceiling ?? {}) as any[];
  const avg = (k: string) => (ceil.length ? ceil.reduce((a, c) => a + (c[k] ?? 0), 0) / ceil.length : undefined);
  const lost: any[] = d.losses ?? [];
  const rows: React.ReactNode[][] = ps.map((p) => {
    const o = agg.overall?.[p]?.all ?? {};
    const c = agg.cost?.[p] ?? {};
    return [
      <span key={p} className={cn(p === "reachable" && "font-medium text-fg")}>{p}</span>,
      numSd(o["ndcg@10"]),
      pctSd(o["p@10"]),
      pctSd(o["path_recall@10"]),
      pctSd(o["decoy_rate@10"]),
      num(mean(o.fix_paths_per_fix)),
      num(mean(c.llm_calls), 1),
      mean(c.usd) != null ? `$${mean(c.usd).toFixed(4)}` : "-",
      `${num(mean(c.wall_s), 1)} s`,
    ];
  });
  rows.push([
    <span key="ceil" className="text-fg-3 italic">oracle ceiling</span>,
    num(avg("ndcg@10")),
    pct(avg("p@10")),
    pct(avg("path_recall@10")),
    pct(avg("decoy_rate@10")),
    num(avg("fix_paths_per_fix")),
    "-",
    "-",
    "-",
  ]);
  const held = (agg.scans ?? []).filter((s: any) => s.scan === "v2").length;
  return (
    <Section
      title="Comparison: five prioritisers, one oracle"
      sub={`${(agg.scans ?? []).length} scans (${held} held out) · ${d.model} · seeds ${(d.seeds ?? []).join(", ")} · K = ${d.k} · ${d.generated}`}
    >
      <Table
        head={["prioritiser", "NDCG@10", "P@10", "path recall@10", "decoys@10", "paths cut / fix", "LLM calls / run", "$ / run", "wall / run"]}
        rows={rows}
      />
      <div className="border-t border-line px-5 py-4 text-xs text-fg-2">
        <p className="eyebrow mb-2">Where reachable does not win ({lost.length})</p>
        {lost.length ? (
          <ul className="space-y-1">
            {lost.slice(0, 8).map((x, i) => (
              <li key={i} className="mono">
                {x.where} · {x.metric}: {x.winner} {num(x.winner_value, 3)} vs reachable {num(x.reachable_value, 3)}
              </li>
            ))}
            {lost.length > 8 && <li className="text-fg-3">… {lost.length - 8} more in evals/results/comparison.md</li>}
          </ul>
        ) : (
          <p>No headline metric, on any scan or split. (Cost and latency: the deterministic two are free and instant.)</p>
        )}
      </div>
    </Section>
  );
}

function Ablation({ d }: { d: any }) {
  const on = d.graph_on ?? {};
  const off = d.graph_off ?? {};
  const drop = d.drop ?? {};
  const pts = (v: unknown) => (typeof v === "number" ? `${v >= 0 ? "+" : ""}${Math.round(v * 100)} pts` : "-");
  return (
    <Section
      title="Ablation: the same agent, FalkorDB tools on vs off"
      sub={`${d.org} ${d.scan} · ${d.model} · seeds ${(d.seeds ?? []).join(", ")} · graph off = every tool answers "unavailable"`}
      pass={d.pass}
    >
      <Table
        head={["", "path recall@10", "NDCG@10", "P@10", "decoys@10", "fix set cuts"]}
        rows={[
          ["graph on", pctSd(on["path_recall@10"]), numSd(on["ndcg@10"]), pctSd(on["p@10"]), pctSd(on["decoy_rate@10"]), pctSd(on.fix_cut_share)],
          ["graph off", pctSd(off["path_recall@10"]), numSd(off["ndcg@10"]), pctSd(off["p@10"]), pctSd(off["decoy_rate@10"]), pctSd(off.fix_cut_share)],
          [
            <span key="drop" className="font-medium text-fg">drop</span>,
            pts(drop["path_recall@10"]),
            typeof drop["ndcg@10"] === "number" ? `${drop["ndcg@10"] >= 0 ? "+" : ""}${drop["ndcg@10"].toFixed(2)}` : "-",
            pts(drop["p@10"]),
            pts(drop["decoy_rate@10"]),
            pts(drop.fix_cut_share),
          ],
        ]}
      />
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
            {q.data.results.comparison && <Comparison d={q.data.results.comparison} />}
            {q.data.results.ablation && <Ablation d={q.data.results.ablation} />}
            {Object.entries(q.data.results)
              .filter(([k]) => !["gate_a", "memory_lift", "comparison", "ablation"].includes(k))
              .map(([k, v]) => (
                <Generic key={k} name={k} d={v} />
              ))}
          </>
        )}
      </div>
    </div>
  );
}
