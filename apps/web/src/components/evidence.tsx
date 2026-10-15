"use client";

import { ChevronRight, Code2 } from "lucide-react";
import { useState } from "react";

import { Id, shortId } from "@/components/bits";
import { ErrorState, LoadingRows } from "@/components/states";
import { useApi } from "@/lib/api";
import type { Query, WhyStep } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useWorkspace } from "@/lib/workspace";

export function CypherBlock({ queries, title = "Cypher it ran" }: { queries: Query[]; title?: string }) {
  const [open, setOpen] = useState(false);
  if (!queries?.length) return null;
  return (
    <div className="rounded-md border border-line">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs text-fg-2 hover:text-fg"
      >
        <ChevronRight className={cn("size-3.5 transition-transform", open && "rotate-90")} />
        <Code2 className="size-3.5" />
        {title}
        <span className="mono ml-auto text-fg-3">
          {queries.length} {queries.length === 1 ? "query" : "queries"} ·{" "}
          {queries.reduce((s, q) => s + (q.ms || 0), 0).toFixed(1)} ms
        </span>
      </button>
      {open && (
        <div className="space-y-2 border-t border-line p-2">
          {queries.map((q, i) => (
            <div key={i}>
              <pre className="mono max-h-56 overflow-auto rounded bg-bg p-2.5 text-2xs leading-relaxed whitespace-pre-wrap text-fg-2">
                {formatCypher(q.cypher)}
              </pre>
              <p className="mono mt-1 text-right text-2xs text-fg-3">
                {q.graph ? `${q.graph} · ` : ""}
                {q.ms?.toFixed(2)} ms
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const KEYWORDS = /\b(MATCH|OPTIONAL MATCH|WHERE|RETURN|WITH|ORDER BY|LIMIT|CALL|YIELD|UNWIND|AND|OR|NOT|DISTINCT|AS|IN|CASE|WHEN|THEN|ELSE|END)\b/g;

export function formatCypher(c: string): string {
  return c.replace(/\s+(MATCH|OPTIONAL MATCH|WHERE|RETURN|WITH|ORDER BY|LIMIT|CALL|YIELD|UNWIND)\b/g, "\n$1").trim();
}

export { KEYWORDS };

function props(p: Record<string, unknown>): string {
  const pick = ["hostname", "cve", "cvss", "kev", "cpe", "kind", "name", "port", "status", "role"];
  return pick
    .filter((k) => p[k] !== undefined && p[k] !== null && p[k] !== "")
    .map((k) => `${k} ${String(p[k])}`)
    .join(" · ");
}

export function WhyStepPanel({ stepKey }: { stepKey: string }) {
  const ws = useWorkspace();
  const q = useApi<WhyStep>(`orgs/${ws.org}/why_step?scan=${ws.scan}&key=${encodeURIComponent(stepKey)}`);
  if (q.error) return <ErrorState error={q.error} retry={q.reload} what="the evidence for this step" />;
  if (!q.data) return <LoadingRows rows={4} label="Tracing the step" />;
  const d = q.data.data;
  const name = (n: WhyStep["data"]["src"]) =>
    n ? String(n.props.hostname ?? n.props.name ?? n.props.kind ?? n.id) : "Internet";
  return (
    <div className="space-y-5 p-5" data-testid="why-step">
      <div>
        <p className="eyebrow">Why this step exists</p>
        <p className="mt-2 flex flex-wrap items-baseline gap-2">
          <span className="mono text-lg font-semibold text-ember">{d.technique.id}</span>
          <span className="text-base font-medium">{d.technique.name}</span>
        </p>
        {!!d.technique.tactics?.length && (
          <p className="mt-1 text-xs text-fg-3">tactic: {d.technique.tactics.join(", ")}</p>
        )}
      </div>
      <div className="rounded-md border border-line bg-panel-2 p-3">
        <p className="mono text-sm">
          <span className="text-fg">{name(d.src)}</span>
          <span className="mx-2 text-ember">→</span>
          <span className="text-fg">{name(d.dst)}</span>
        </p>
        <p className="mt-2 text-sm text-fg-2">{d.rule_text}</p>
        <div className="mt-3 flex items-center gap-3 text-xs text-fg-3">
          <span className="mono">{d.rule}</span>
          <span className="ml-auto">likelihood</span>
          <span className="relative h-1 w-20 overflow-hidden rounded-full bg-line">
            <span className="absolute inset-y-0 left-0 bg-ember" style={{ width: `${d.likelihood * 100}%` }} />
          </span>
          <span className="mono num text-fg">{d.likelihood.toFixed(2)}</span>
        </div>
      </div>
      <div>
        <p className="eyebrow mb-2">Because (the evidence the rule matched)</p>
        <ul className="space-y-1.5">
          {d.because.map((b) => (
            <li key={b.id} className="rounded-md border border-line px-3 py-2">
              <p className="flex items-center gap-2 text-sm">
                <span className="mono rounded-sm bg-raised px-1.5 text-2xs text-fg-2">{b.labels[0]}</span>
                <Id id={b.id} className="text-fg" />
              </p>
              <p className="mt-1 text-xs text-fg-3">{props(b.props)}</p>
            </li>
          ))}
        </ul>
      </div>
      {!!d.structural_edges.length && (
        <div>
          <p className="eyebrow mb-2">Facts in the graph</p>
          <ul className="mono space-y-1 text-2xs text-fg-2">
            {d.structural_edges.map((e, i) => (
              <li key={i}>
                {shortId(e.src)} <span className="text-fg-3">-[</span>
                <span className="text-fg">{e.rel}</span>
                {e.props?.port ? <span className="text-fg-3"> :{String(e.props.port)}</span> : null}
                <span className="text-fg-3">]→</span> {shortId(e.dst)}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="rounded-md border border-cut/30 p-3">
        <p className="eyebrow">The fix that removes it</p>
        <p className="mt-1.5 text-sm text-fg">{d.fix.action}</p>
        <p className="mono mt-1 text-2xs text-fg-3">{d.fix.token}</p>
      </div>
      <CypherBlock queries={q.data.queries} />
    </div>
  );
}
