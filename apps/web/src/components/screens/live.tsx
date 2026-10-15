"use client";

import {
  AlertOctagon,
  Bot,
  BrainCircuit,
  ChevronRight,
  CircleCheck,
  FileText,
  GitCompareArrows,
  ListOrdered,
  Pause,
  Play,
  Radio,
  RotateCcw,
  Route,
  Scissors,
  Sparkles,
  Wrench,
} from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Seg, shortId, shortRun } from "@/components/bits";
import { formatCypher } from "@/components/evidence";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states";
import { type ApiError, api, invalidate, useApi } from "@/lib/api";
import type { RunEvent } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useWorkspace } from "@/lib/workspace";

const AGENTS: Record<string, { label: string; job: string }> = {
  sentinel: { label: "Sentinel", job: "What changed for an attacker since the last scan? No model." },
  triage: { label: "Triage", job: "Which of thousands of findings are worth a path search?" },
  pathfinder: { label: "Pathfinder", job: "Find the attack paths, rank the findings, explain the hops." },
  fixer: { label: "Fixer", job: "The minimum cut: the fewest fixes, owners, tickets, proven." },
  reporter: { label: "Reporter", job: "Verdicts, the report, and what to remember next time." },
};

const MEMORY_LABEL: Record<string, string> = {
  carry_over: "Carried the org's memory into this scan",
  pattern_flags: "Learned patterns flagged arriving findings",
  carried_verdicts: "Earlier verdicts still stand: not re-investigated",
  remembered_routes: "Reused last run's owner routing",
  playbook_rules_applied: "Applied the analyst's playbook rules",
  patterns_learned: "Learned patterns for next time",
};

const STREAM_TYPES = [
  "agent_entered",
  "tool_called",
  "llm_called",
  "memory",
  "drift_checked",
  "alert_raised",
  "triage_done",
  "path_found",
  "finding_ranked",
  "fix_chosen",
  "report_written",
  "report_ready",
  "run_failed",
];

type Item =
  | { kind: "event"; e: RunEvent; key: string }
  | { kind: "group"; type: "path_found" | "finding_ranked"; events: RunEvent[]; key: string };

function keyOf(e: RunEvent): string {
  return `${e.seq ?? "x"}:${e.type}:${e.rank ?? ""}:${e.finding ?? ""}`;
}

function toItems(events: RunEvent[]): Item[] {
  const out: Item[] = [];
  for (const e of events) {
    const last = out[out.length - 1];
    if ((e.type === "path_found" || e.type === "finding_ranked") && last?.kind === "group" && last.type === e.type) {
      last.events.push(e);
    } else if (e.type === "path_found" || e.type === "finding_ranked") {
      out.push({ kind: "group", type: e.type, events: [e], key: keyOf(e) });
    } else {
      out.push({ kind: "event", e, key: keyOf(e) });
    }
  }
  return out;
}

function Ms({ ms, max }: { ms?: number | null; max: number }) {
  if (ms == null) return <span className="w-28" />;
  return (
    <span className="flex w-28 shrink-0 items-center justify-end gap-2">
      <span className="relative h-1 w-12 overflow-hidden rounded-full bg-line">
        <span className="absolute inset-y-0 left-0 bg-fg-3" style={{ width: `${Math.max(4, Math.min(100, (ms / max) * 100))}%` }} />
      </span>
      <span className="mono num w-14 text-right text-2xs text-fg-2">
        {ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms.toFixed(ms < 10 ? 1 : 0)} ms`}
      </span>
    </span>
  );
}

function Line({
  icon: Icon,
  title,
  children,
  ms,
  max,
  tone,
  expand,
  type,
}: {
  icon: React.ElementType;
  title: React.ReactNode;
  children?: React.ReactNode;
  ms?: number | null;
  max: number;
  tone?: "ember" | "memory" | "done";
  expand?: React.ReactNode;
  type: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div data-testid="feed-event" data-type={type} className="animate-rise">
      <div
        onClick={() => expand && setOpen((o) => !o)}
        className={cn(
          "flex items-start gap-3 rounded-md px-3 py-2",
          expand && "cursor-pointer hover:bg-panel-2",
          tone === "ember" && "bg-ember/10",
        )}
      >
        <Icon
          className={cn(
            "mt-0.5 size-4 shrink-0",
            tone === "ember" ? "text-ember" : tone === "memory" ? "text-fg" : tone === "done" ? "text-safe" : "text-fg-3",
          )}
        />
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2 text-sm">
            {expand && <ChevronRight className={cn("size-3 shrink-0 self-center text-fg-3 transition-transform", open && "rotate-90")} />}
            {title}
          </div>
          {children && <div className="mt-0.5 text-xs text-fg-2">{children}</div>}
        </div>
        <Ms ms={ms} max={max} />
      </div>
      {open && expand && <div className="ml-10 pb-2">{expand}</div>}
    </div>
  );
}

function EventLine({ e, max }: { e: RunEvent; max: number }) {
  switch (e.type) {
    case "tool_called":
      return (
        <Line
          type={e.type}
          icon={Wrench}
          max={max}
          ms={e.ms}
          title={
            <>
              <span className="mono font-medium text-fg">{e.tool}</span>
              <span className="text-2xs text-fg-3">{e.by === "run" ? "run plumbing" : "chosen by the model"}</span>
              {e.cached && <span className="text-2xs text-fg-3">· cached</span>}
              {e.ok === false && <span className="text-2xs text-fg-2">· refused</span>}
            </>
          }
          expand={
            e.queries?.length ? (
              <div className="space-y-2">
                {e.queries.map((q, i) => (
                  <div key={i}>
                    <pre className="mono max-h-48 overflow-auto rounded bg-bg p-2.5 text-2xs leading-relaxed whitespace-pre-wrap text-fg-2">
                      {formatCypher(q.cypher)}
                    </pre>
                    <p className="mono mt-0.5 text-right text-2xs text-fg-3">
                      {q.graph} · {q.ms?.toFixed(2)} ms in FalkorDB
                    </p>
                  </div>
                ))}
              </div>
            ) : undefined
          }
        >
          <span className="line-clamp-1">{e.summary}</span>
        </Line>
      );
    case "llm_called":
      return (
        <Line
          type={e.type}
          icon={Sparkles}
          max={max}
          ms={e.ms}
          title={
            <>
              <span className="font-medium">Model call</span>
              <span className="mono text-2xs text-fg-3">{e.model}</span>
            </>
          }
        >
          {e.tokens_in?.toLocaleString()} tokens in · {e.tokens_out?.toLocaleString()} out
          {e.tool_calls?.length ? (
            <>
              {" "}· chose <span className="mono text-fg">{e.tool_calls.join(", ")}</span>
            </>
          ) : (
            " · answered"
          )}
        </Line>
      );
    case "memory":
      return (
        <Line
          type={e.type}
          icon={BrainCircuit}
          tone="memory"
          max={max}
          title={
            <>
              <span className="mono rounded-sm border border-fg-3 px-1 text-2xs tracking-wider text-fg">MEMORY</span>
              <span className="font-medium">{MEMORY_LABEL[e.action ?? ""] ?? e.action}</span>
            </>
          }
          expand={
            e.detail ? (
              <pre className="mono max-h-48 overflow-auto rounded bg-bg p-2.5 text-2xs whitespace-pre-wrap text-fg-2">
                {JSON.stringify(e.detail, null, 1).slice(0, 2500)}
              </pre>
            ) : undefined
          }
        >
          {memorySummary(e)}
        </Line>
      );
    case "drift_checked":
      return (
        <Line type={e.type} icon={GitCompareArrows} max={max} title={<span className="font-medium">Drift checked: path sets of v1 and v2 compared</span>}>
          {e.new_paths?.length ?? 0} new · {e.closed_paths?.length ?? 0} closed
          {e.new_paths?.[0] && (
            <span className="mono ml-2 text-ember">new: {e.new_paths[0].join(" → ")}</span>
          )}
        </Line>
      );
    case "alert_raised":
      return (
        <Line type={e.type} icon={AlertOctagon} tone="ember" max={max} title={<span className="font-medium text-ember">Alert: a brand-new path to a crown jewel</span>}>
          {e.summary}
        </Line>
      );
    case "triage_done":
      return (
        <Line type={e.type} icon={ListOrdered} max={max} title={<span className="font-medium">Triage decided what to investigate</span>}>
          investigate {e.investigate?.length ?? 0} · carried from memory {e.carried?.length ?? 0} · suppressed (accepted risk){" "}
          {e.suppressed?.length ?? 0}
        </Line>
      );
    case "fix_chosen":
      return (
        <Line
          type={e.type}
          icon={Scissors}
          max={max}
          title={
            <>
              <span className="font-medium">Fix set chosen: {e.chosen}</span>
              {e.verified && (
                <span className="flex items-center gap-1 text-2xs text-safe">
                  <CircleCheck className="size-3" /> proven by simulate_fix
                </span>
              )}
            </>
          }
        >
          {e.fix_tokens?.length} fixes · effort {e.total_effort} ·{" "}
          {e.fixes?.slice(0, 3).map((f) => f.team).filter(Boolean).join(", ")}
        </Line>
      );
    case "report_written":
      return (
        <Line type={e.type} icon={FileText} max={max} title={<span className="font-medium">Report written</span>}>
          {e.headline}
        </Line>
      );
    default:
      return null;
  }
}

function memorySummary(e: RunEvent): string {
  const d = e.detail as Record<string, unknown> | undefined;
  if (!d || typeof d !== "object") return "";
  const parts: string[] = [];
  for (const [k, v] of Object.entries(d)) {
    if (Array.isArray(v)) parts.push(`${k.replace(/_/g, " ")}: ${v.length}`);
    else if (typeof v === "number" || typeof v === "string") parts.push(`${k.replace(/_/g, " ")}: ${v}`);
    else if (v && typeof v === "object") parts.push(`${k.replace(/_/g, " ")}: ${Object.keys(v).length}`);
    if (parts.length >= 4) break;
  }
  return parts.join(" · ");
}

function Group({ item }: { item: Extract<Item, { kind: "group" }> }) {
  const [open, setOpen] = useState(false);
  const paths = item.type === "path_found";
  const top = open ? item.events : item.events.slice(0, 3);
  return (
    <div data-testid="feed-event" data-type={item.type} className="animate-rise rounded-md px-3 py-2">
      <div className="flex items-center gap-3 text-sm">
        {paths ? <Route className="size-4 text-ember" /> : <ListOrdered className="size-4 text-fg-3" />}
        <span className="font-medium">
          {paths ? `Found ${item.events.length} attack path${item.events.length === 1 ? "" : "s"}` : `Ranked ${item.events.length} findings by what they reach`}
        </span>
        {item.events.length > 3 && (
          <button onClick={() => setOpen((o) => !o)} className="text-2xs text-fg-3 hover:text-fg">
            {open ? "less" : `all ${item.events.length}`}
          </button>
        )}
      </div>
      <ol className="mt-1.5 ml-7 space-y-1">
        {top.map((e) => (
          <li key={keyOf(e)} className="flex items-baseline gap-2 text-xs">
            <span className="mono num w-6 text-fg-3">#{e.rank}</span>
            {paths ? (
              <>
                <span className="mono truncate text-fg-2">{e.hops?.join(" → ")}</span>
                <span className="mono ml-auto shrink-0 text-fg-3">p={e.likelihood?.toFixed(3)}</span>
              </>
            ) : (
              <>
                <span className="mono text-fg">{shortId(e.finding)}</span>
                <span className="truncate text-fg-2">{e.why}</span>
              </>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}

function useAutoScroll(dep: unknown) {
  const ref = useRef<HTMLDivElement>(null);
  const stick = useRef(true);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const on = () => (stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80);
    el.addEventListener("scroll", on);
    return () => el.removeEventListener("scroll", on);
  }, []);
  useEffect(() => {
    const el = ref.current;
    if (el && stick.current) el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }, [dep]);
  return ref;
}

function Feed({ events, done }: { events: RunEvent[]; done: RunEvent | null }) {
  const items = useMemo(() => toItems(events), [events]);
  const max = useMemo(() => Math.max(1000, ...events.map((e) => e.ms ?? 0)), [events]);
  const ref = useAutoScroll(events.length);
  return (
    <div ref={ref} className="min-h-0 flex-1 overflow-y-auto px-3 py-3" data-testid="feed">
      {items.map((it) => {
        if (it.kind === "event" && it.e.type === "agent_entered") {
          const a = AGENTS[it.e.agent ?? ""] ?? { label: it.e.agent, job: "" };
          return (
            <div key={it.key} className="animate-rise mt-4 mb-1 flex items-baseline gap-3 border-t border-line px-3 pt-4 first:mt-0 first:border-t-0 first:pt-1" data-testid="feed-event" data-type="agent_entered">
              <Bot className="size-4 self-center text-fg-2" />
              <span className="text-base font-semibold">{a.label}</span>
              <span className="text-xs text-fg-3">{a.job}</span>
            </div>
          );
        }
        if (it.kind === "group") return <Group key={it.key} item={it} />;
        return <EventLine key={it.key} e={it.e} max={max} />;
      })}
      {done && (
        <div
          data-testid="feed-event"
          data-type={done.type}
          className={cn(
            "animate-rise mt-4 rounded-lg border p-4",
            done.type === "report_ready" ? "border-line-2 bg-panel-2" : "border-fg-3",
          )}
        >
          <p className="flex items-center gap-2 text-sm font-medium">
            <CircleCheck className="size-4 text-safe" />
            {done.type === "report_ready" ? `Report ready · ${done.status}` : `Run ended: ${done.status}`}
            {done.risk && <span className="mono ml-auto text-2xs text-fg-3">risk {done.risk}</span>}
          </p>
          {done.headline && <p className="mt-2 text-base text-fg">{done.headline}</p>}
        </div>
      )}
    </div>
  );
}

function Stats({ events }: { events: RunEvent[] }) {
  const tools = events.filter((e) => e.type === "tool_called");
  const llm = events.filter((e) => e.type === "llm_called");
  const per: Record<string, number> = {};
  for (const e of events) if (e.agent && e.ms) per[e.agent] = (per[e.agent] ?? 0) + e.ms;
  const total = Object.values(per).reduce((a, b) => a + b, 0) || 1;
  const dbMs = tools.reduce((s, e) => s + (e.queries ?? []).reduce((a, q) => a + (q.ms || 0), 0), 0);
  const rows: [string, React.ReactNode][] = [
    ["Tool calls", `${tools.length} (${tools.filter((t) => t.by === "run").length} plumbing)`],
    ["Model calls", llm.length],
    ["Tokens in / out", `${llm.reduce((s, e) => s + (e.tokens_in ?? 0), 0).toLocaleString()} / ${llm.reduce((s, e) => s + (e.tokens_out ?? 0), 0).toLocaleString()}`],
    ["Time in the model", `${(llm.reduce((s, e) => s + (e.ms ?? 0), 0) / 1000).toFixed(1)} s`],
    ["Time in FalkorDB", `${(dbMs / 1000).toFixed(2)} s`],
    ["Memory events", events.filter((e) => e.type === "memory").length],
  ];
  return (
    <div className="space-y-5 p-5">
      <dl className="space-y-2.5">
        {rows.map(([k, v]) => (
          <div key={k} className="flex items-baseline justify-between gap-3 text-sm">
            <dt className="text-fg-3">{k}</dt>
            <dd className="mono num text-fg">{v}</dd>
          </div>
        ))}
      </dl>
      <div>
        <p className="eyebrow mb-2">Where the time went</p>
        <div className="flex h-2 overflow-hidden rounded-full bg-line">
          {Object.entries(per).map(([a, ms], i) => (
            <span key={a} style={{ width: `${(ms / total) * 100}%`, opacity: 1 - i * 0.15 }} className="bg-fg-2" title={a} />
          ))}
        </div>
        <ul className="mt-3 space-y-1">
          {Object.entries(per).map(([a, ms]) => (
            <li key={a} className="flex justify-between text-xs">
              <span className="text-fg-2">{AGENTS[a]?.label ?? a}</span>
              <span className="mono text-fg-3">{(ms / 1000).toFixed(1)} s</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

type Speed = "1" | "4" | "max";

export function LiveScreen() {
  const ws = useWorkspace();
  // Live mode streams the run in the URL when ?watch=1 (set by "Start" here or
  // on Drift); the view is keyed by what it shows, so switching starts clean.
  const watch = useSearchParams().get("watch");
  const liveRun = ws.mode === "live" && watch ? ws.runId : null;
  return <LiveView key={`${ws.mode}|${ws.mode === "replay" ? ws.runId : liveRun}`} liveRun={liveRun} />;
}

function LiveView({ liveRun }: { liveRun: string | null }) {
  const ws = useWorkspace();
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [done, setDone] = useState<RunEvent | null>(null);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<Speed>("4");
  const [startErr, setStartErr] = useState<ApiError | null>(null);
  const [streamState, setStreamState] = useState<"idle" | "connecting" | "open" | "reconnecting" | "closed">(
    liveRun ? "connecting" : "idle",
  );
  const [fake, setFake] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cursor = useRef(0);

  const replaySource = useApi<RunEvent[]>(ws.mode === "replay" && ws.runId ? `runs/${encodeURIComponent(ws.runId)}/events` : null);

  const reset = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    cursor.current = 0;
    setEvents([]);
    setDone(null);
    setPlaying(false);
  }, []);


  // Replay: play the recorded events with their real latencies (a model call
  // that took 6 s waits 6 s at 1x), so the video shows the real rhythm with
  // no model behind it.
  useEffect(() => {
    if (!playing || !replaySource.data) return;
    const all = replaySource.data;
    const step = () => {
      const i = cursor.current;
      if (i >= all.length) {
        setPlaying(false);
        return;
      }
      const e = all[i];
      cursor.current = i + 1;
      if (e.type === "report_ready" || e.type === "run_failed") setDone(e);
      else setEvents((xs) => [...xs, e]);
      const next = all[i + 1];
      const f = speed === "max" ? 0 : Number(speed);
      const wait = !next || f === 0 ? 0 : Math.min(6000, Math.max(90, next.ms ?? (next.type === "agent_entered" ? 500 : 140))) / f;
      timer.current = setTimeout(step, wait);
    };
    timer.current = setTimeout(step, 150);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [playing, replaySource.data, speed]);

  // Live: the browser subscribes to OUR origin; the route handler adds the key
  // and relays the backend's text/event-stream (EventSource cannot send headers).
  useEffect(() => {
    if (!liveRun) return;
    const es = new EventSource(`/api/r/runs/${encodeURIComponent(liveRun)}/stream`);
    const seen = new Set<string>();
    const on = (m: MessageEvent) => {
      const e = JSON.parse(m.data) as RunEvent;
      const k = keyOf(e);
      if (seen.has(k)) return;
      seen.add(k);
      if (e.type === "report_ready" || e.type === "run_failed") {
        setDone(e);
        es.close();
        setStreamState("closed");
        invalidate("orgs");
        ws.reloadOrgs();
      } else setEvents((xs) => [...xs, e]);
    };
    STREAM_TYPES.forEach((t) => es.addEventListener(t, on as EventListener));
    es.onopen = () => setStreamState("open");
    es.onerror = () => setStreamState(es.readyState === EventSource.CLOSED ? "closed" : "reconnecting");
    return () => es.close();
  }, [liveRun]); // eslint-disable-line react-hooks/exhaustive-deps

  const start = async () => {
    reset();
    setStartErr(null);
    try {
      const r = await api<{ run_id: string }>("runs", { json: { org: ws.org, scan: ws.scan, fake } });
      ws.set({ run: r.run_id, watch: "1" });
    } catch (e) {
      setStartErr(e as ApiError);
    }
  };

  const watching = ws.mode === "live" ? liveRun : ws.runId;

  return (
    <div className="flex h-full min-h-[720px] flex-col px-8 pt-6 pb-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">04 · Investigation</p>
          <h1 className="mt-2 text-[26px] leading-tight font-semibold tracking-tight">Watch it reason</h1>
          <p className="mt-1 text-sm text-fg-2">
            Every step the four agents take, as it happens: which tool, the Cypher it ran in FalkorDB and how long it took,
            what memory changed, what the model decided.
          </p>
        </div>
        {ws.mode === "replay" ? (
          <div className="flex items-center gap-3" data-testid="replay-controls">
            <span className="text-xs text-fg-3">
              Replaying run <span className="mono text-fg-2">{shortRun(ws.runId)}</span> from the graph · no model calls
            </span>
            <Seg size="sm" value={speed} onChange={setSpeed} options={[{ value: "1", label: "1×" }, { value: "4", label: "4×" }, { value: "max", label: "instant" }]} />
            <button
              data-testid="replay-play"
              disabled={!replaySource.data}
              onClick={() => {
                if (done || cursor.current >= (replaySource.data?.length ?? 0)) reset();
                setPlaying((p) => !p);
              }}
              className="flex items-center gap-2 rounded-md bg-fg px-3.5 py-2 text-sm font-medium text-bg disabled:opacity-40"
            >
              {playing ? <Pause className="size-4" /> : <Play className="size-4" />}
              {playing ? "Pause" : events.length ? "Resume" : "Replay"}
            </button>
            <button onClick={reset} className="rounded-md border border-line-2 p-2 text-fg-2 hover:text-fg" aria-label="Restart">
              <RotateCcw className="size-4" />
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-3" data-testid="live-controls">
            {streamState !== "idle" && (
              <span className="flex items-center gap-2 text-xs text-fg-2">
                <Radio className={cn("size-3.5", streamState === "open" && "text-ember")} />
                {streamState === "connecting" ? "connecting…" : streamState === "open" ? "streaming (SSE)" : streamState === "reconnecting" ? "reconnecting with Last-Event-ID…" : "stream closed"}
              </span>
            )}
            <Seg
              size="sm"
              value={fake ? "stub" : "model"}
              onChange={(v) => setFake(v === "stub")}
              options={[
                { value: "model", label: "real model", hint: "Gemini via LiteLLM" },
                { value: "stub", label: "stub model", hint: "Deterministic, no LLM: tools and graph are real" },
              ]}
            />
            <button data-testid="start-run" onClick={start} className="flex items-center gap-2 rounded-md bg-fg px-3.5 py-2 text-sm font-medium text-bg">
              <Play className="size-4" /> Start a {ws.scan} run on {ws.org}
            </button>
          </div>
        )}
      </div>
      {startErr && (
        <p className="mt-3 rounded-md border border-line-2 bg-panel-2 px-3 py-2 text-sm text-fg-2" role="alert">
          {startErr.status === 429
            ? `Two runs are already in progress (the backend runs at most two at once). Try again in ~${startErr.retryAfter ?? 30} s.`
            : startErr.message}
        </p>
      )}

      <div className="mt-5 grid min-h-0 flex-1 grid-cols-[minmax(0,1fr)_320px] gap-4">
        <div className="panel flex min-h-[520px] flex-col overflow-hidden">
          {ws.mode === "replay" && !ws.runId ? (
            <EmptyState title="No finished run to replay">Switch to Live to start one.</EmptyState>
          ) : replaySource.error && ws.mode === "replay" ? (
            <ErrorState error={replaySource.error} retry={replaySource.reload} what="the run's events" />
          ) : ws.mode === "replay" && !replaySource.data ? (
            <LoadingRows rows={6} label="Reading the run's trace" />
          ) : events.length === 0 && !done ? (
            <EmptyState title={ws.mode === "replay" ? "Press Replay" : "Start a run"}>
              {ws.mode === "replay"
                ? `${replaySource.data?.length ?? 0} recorded events, played back at their real pace.`
                : "Pick the real model or the stub. The stream resumes by itself if the connection drops."}
            </EmptyState>
          ) : (
            <Feed events={events} done={done} />
          )}
        </div>
        <aside className="panel min-h-0 overflow-y-auto">
          <div className="border-b border-line px-5 py-3">
            <p className="text-sm font-medium">This run</p>
            <p className="mono mt-0.5 text-2xs text-fg-3">{watching ?? "-"}</p>
          </div>
          <Stats events={events} />
        </aside>
      </div>
    </div>
  );
}
