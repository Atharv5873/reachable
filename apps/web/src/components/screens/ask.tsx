"use client";

import { ArrowRight, CornerDownLeft, FileCheck2, Network, UserRound, Users } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { CypherBlock } from "@/components/evidence";
import { ErrorState } from "@/components/states";
import { type ApiError, api } from "@/lib/api";
import type { AskAnswer } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useWorkspace } from "@/lib/workspace";

const SUGGEST: Record<string, string[]> = {
  org_a: [
    "Who approved letting services reach the shared CI runner?",
    "Who is on call for the shared CI runner right now?",
    "Why is ember-basalt-edge-183 exposed to the Internet?",
    "What's the fix history of larch-meadow-edge-182?",
  ],
  org_b: [
    "Why is the legacy jump host reachable from the DMZ, and who approved it?",
    "Who owns zephyr-harbor-dmz-224?",
    "Who is on call for the legacy jump host?",
  ],
  org_c: [
    "Why is port 22 open on the vendor gateway, and who approved it?",
    "Who approved storing the vendor SSH key on the gateway?",
    "Who is on call for the vendor gateway?",
  ],
};

const INTENT_LABEL: Record<string, string> = {
  who_owns: "who owns",
  who_is_on_call: "who is on call",
  why_exposed: "why exposed",
  who_approved: "who approved",
  fix_history: "fix history",
};

function Decisions({ a }: { a: AskAnswer }) {
  const ds = a.data?.decisions ?? [];
  if (!ds.length) return null;
  return (
    <div>
      <p className="eyebrow mb-2">Decision records</p>
      <ol className="space-y-2.5">
        {[...ds].reverse().map((d) => (
          <li key={d.adr} className="rounded-lg border border-line bg-panel-2 p-4" data-testid="adr-card">
            <div className="flex items-start gap-3">
              <FileCheck2 className="mt-0.5 size-4 shrink-0 text-fg-2" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{d.title}</p>
                <p className="mt-1.5 text-sm leading-relaxed text-fg-2">{d.decision}</p>
                <p className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
                  <span className="flex items-center gap-1.5 text-fg">
                    <UserRound className="size-3.5" />
                    approved by {d.approved_by.name}
                  </span>
                  <span className="text-fg-3">{d.approved_by.role}</span>
                  {d.approver_team && <span className="text-fg-3">· {d.approver_team.name}</span>}
                  <span className="mono text-fg-3">· {d.date}</span>
                  {d.port && <span className="mono text-fg-3">· port {d.port}</span>}
                  <span className="mono ml-auto text-fg-3">{d.adr}</span>
                </p>
              </div>
            </div>
          </li>
        ))}
      </ol>
      {!!a.data?.exposed_ports?.length && (
        <p className="mt-3 text-xs text-fg-2">
          Exposed to the Internet today on <span className="mono text-fg">{a.data.exposed_ports.join(", ")}</span>
        </p>
      )}
    </div>
  );
}

function People({ a }: { a: AskAnswer }) {
  const teams = a.data?.teams ?? [];
  const rota = a.data?.on_call ?? [];
  if (!teams.length && !rota.length) return null;
  return (
    <div className="grid grid-cols-2 gap-3">
      {teams.map((t) => (
        <div key={t.id} className="rounded-lg border border-line bg-panel-2 p-4">
          <p className="flex items-center gap-2 text-sm font-medium">
            <Users className="size-4 text-fg-2" />
            {t.name}
          </p>
          {t.on_call && (
            <p className="mt-2 text-xs text-fg-2">
              on call: <span className="text-fg">{t.on_call.name}</span> · {t.on_call.role} ·{" "}
              <span className="mono">{t.on_call.window}</span>
            </p>
          )}
        </div>
      ))}
      {rota.map((o, i) => (
        <div key={i} className="rounded-lg border border-line bg-panel-2 p-4">
          <p className="flex items-center gap-2 text-sm font-medium">
            <UserRound className="size-4 text-fg-2" />
            {o.name}
          </p>
          <p className="mt-2 text-xs text-fg-2">
            {o.team_name} · <span className="mono">{o.window}</span>
          </p>
        </div>
      ))}
    </div>
  );
}

function Tickets({ a }: { a: AskAnswer }) {
  const ts = a.data?.tickets ?? [];
  if (!ts.length) return null;
  return (
    <div>
      <p className="eyebrow mb-2">Tickets</p>
      <ul className="space-y-1.5">
        {ts.map((t) => (
          <li key={t.ticket} className="flex items-baseline gap-3 rounded-md border border-line px-3 py-2 text-sm">
            <span className="mono text-xs text-fg-3">{t.opened}</span>
            <span className="flex-1">{t.title}</span>
            <span className="mono text-xs text-fg-2">{t.status}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function AnswerCard({ a }: { a: AskAnswer }) {
  const ws = useWorkspace();
  const ev = a.evidence;
  const names = new Map(ev?.nodes.map((n) => [n.id, n.name]) ?? []);
  return (
    <article className="panel animate-rise overflow-hidden" data-testid="answer">
      <div className="border-b border-line px-6 py-4">
        <p className="text-sm text-fg-2">{a.question}</p>
        <div className="mt-2 flex flex-wrap items-center gap-2 text-2xs">
          {a.intent && (
            <span className="mono rounded-sm bg-raised px-1.5 py-0.5 text-fg">company_query · {INTENT_LABEL[a.intent] ?? a.intent}</span>
          )}
          <span className="mono rounded-sm border border-line-2 px-1.5 py-0.5 text-fg-2" data-testid="resolved-by">
            {a.resolved_by === "llm" ? `mapped by ${a.llm?.model ?? "the model"}` : "mapped by rules · no model"}
          </span>
          {a.ms != null && <span className="mono text-fg-3">{a.ms.toFixed(0)} ms</span>}
        </div>
      </div>
      <div className="space-y-5 px-6 py-5">
        {a.error ? (
          <div>
            <p className="text-base text-fg">{a.error}</p>
            {!!a.suggest?.length && (
              <p className="mt-2 text-sm text-fg-2">
                Try one of: <span className="mono text-fg">{a.suggest.join(", ")}</span>
              </p>
            )}
          </div>
        ) : (
          <>
            <p className="text-lg leading-snug font-medium" data-testid="answer-text">
              {a.answer?.replace(/^org_\w+:adr:\d+:\s*/, "")}
            </p>
            {a.note && <p className="rounded-md border border-line-2 bg-panel-2 px-3 py-2 text-sm text-fg-2">{a.note}</p>}
            {a.entity && (
              <div className="flex flex-wrap items-center gap-3 text-sm">
                <span className="text-fg-3">About</span>
                <span className="mono text-fg">{a.entity.name}</span>
                <span className="text-xs text-fg-3">{a.entity.kind?.replace(/_/g, " ")}</span>
                {a.entity.kind !== "team" && (
                  <Link
                    href={ws.href("/paths", {}) + `&node=${encodeURIComponent(a.entity.id)}`}
                    className="ml-auto flex items-center gap-1.5 text-xs text-fg-2 hover:text-fg"
                  >
                    <Network className="size-3.5" /> Show it on the attack graph <ArrowRight className="size-3" />
                  </Link>
                )}
              </div>
            )}
            <Decisions a={a} />
            <People a={a} />
            <Tickets a={a} />
            {!!ev?.edges.length && (
              <div>
                <p className="eyebrow mb-2">The evidence, as edges in the graph</p>
                <ul className="mono grid grid-cols-2 gap-x-6 gap-y-1 text-2xs text-fg-2">
                  {ev.edges.slice(0, 16).map((e, i) => (
                    <li key={i} className="truncate">
                      {names.get(e.src) ?? e.src} <span className="text-fg-3">-[</span>
                      <span className="text-fg">{e.rel}</span>
                      <span className="text-fg-3">]→</span> {names.get(e.dst) ?? e.dst}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {a.queries && <CypherBlock queries={a.queries} />}
          </>
        )}
      </div>
    </article>
  );
}

export function AskScreen() {
  const ws = useWorkspace();
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [answers, setAnswers] = useState<AskAnswer[]>([]);
  const [err, setErr] = useState<ApiError | null>(null);
  const suggestions = SUGGEST[ws.org] ?? [];

  const ask = async (question: string) => {
    if (question.trim().length < 3) return;
    setBusy(true);
    setErr(null);
    try {
      const a = await api<AskAnswer>(`orgs/${ws.org}/ask`, {
        json: { question, scan: ws.scan, mode: ws.mode === "replay" ? "rules" : "auto" },
      });
      setAnswers((xs) => [a, ...xs].slice(0, 6));
      setQ("");
    } catch (e) {
      setErr(e as ApiError);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-[1100px] px-8 pt-7 pb-16">
      <p className="eyebrow">05 · Company brain</p>
      <h1 className="mt-2 text-[28px] leading-tight font-semibold tracking-tight">Who owns it, who approved it, and why is it open?</h1>
      <p className="mt-2 max-w-3xl text-base text-fg-2">
        The graph holds the company too: teams, people, on-call, decision records, tickets. A question maps to one of five
        fixed, typed intents. Nothing is turned into free-form Cypher.{" "}
        <span className="text-fg-3">
          {ws.mode === "replay" ? "Replay mode: mapped by rules, no model." : "Live mode: a small model picks the intent."}
        </span>
      </p>

      <form
        className="mt-6"
        onSubmit={(e) => {
          e.preventDefault();
          ask(q);
        }}
      >
        <div className="flex items-center gap-2 rounded-lg border border-line-2 bg-panel px-4 py-1.5 focus-within:border-fg-3">
          <input
            data-testid="ask-input"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={suggestions[0] ?? "Ask about an asset or a team"}
            className="h-11 flex-1 bg-transparent text-base outline-none placeholder:text-fg-3"
          />
          <button
            type="submit"
            disabled={busy || q.trim().length < 3}
            className="flex items-center gap-2 rounded-md bg-fg px-3 py-1.5 text-sm font-medium text-bg disabled:opacity-40"
          >
            {busy ? "Asking…" : "Ask"} <CornerDownLeft className="size-3.5" />
          </button>
        </div>
      </form>
      <div className="mt-3 flex flex-wrap gap-2">
        {suggestions.map((s) => (
          <button
            key={s}
            data-testid="suggestion"
            onClick={() => ask(s)}
            disabled={busy}
            className={cn("rounded-full border border-line px-3 py-1.5 text-xs text-fg-2 hover:border-line-2 hover:text-fg")}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="mt-8 space-y-6">
        {err && <ErrorState error={err} what="an answer" />}
        {answers.map((a, i) => (
          <AnswerCard key={answers.length - i} a={a} />
        ))}
      </div>
    </div>
  );
}
