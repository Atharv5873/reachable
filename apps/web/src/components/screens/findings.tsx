"use client";

import { ArrowRight, MoveRight } from "lucide-react";
import Link from "next/link";
import { useLayoutEffect, useMemo, useRef, useState } from "react";

import { Cvss, Epss, Id, Kev, Seg, Stat, Verdict, shortRun } from "@/components/bits";
import { EmptyState, ErrorState, LoadingRows } from "@/components/states";
import { useApi } from "@/lib/api";
import type { Board, BoardRow } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useWorkspace } from "@/lib/workspace";

type Order = "severity" | "reachability";
const fmt = (n: number) => n.toLocaleString("en-US");
const COLS = "grid grid-cols-[86px_150px_100px_60px_52px_minmax(170px,1fr)_minmax(250px,1.5fr)_84px] items-center gap-x-4";

export function useBoard() {
  const ws = useWorkspace();
  const q = ws.runId
    ? `orgs/${ws.org}/findings?scan=${ws.scan}&run_id=${encodeURIComponent(ws.runId)}`
    : ws.orgs
      ? `orgs/${ws.org}/findings?scan=${ws.scan}`
      : null;
  return useApi<Board>(q);
}

function HeadlineCard({
  row,
  side,
  total,
  onPick,
}: {
  row: BoardRow;
  side: "low" | "high";
  total: number;
  onPick: () => void;
}) {
  const reach = row.status === "reachable";
  return (
    <button
      onClick={onPick}
      data-testid={`headline-${side}`}
      className={cn(
        "panel group relative flex-1 overflow-hidden p-5 text-left transition-colors hover:bg-panel-2",
        reach && "border-ember/50",
      )}
    >
      {reach && <span className="absolute inset-y-0 left-0 w-[3px] bg-ember" />}
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="eyebrow">{reach ? "Reachable ranks it" : "The scanner ranks it"}</p>
          <p className="mt-2 flex items-baseline gap-2">
            <span className="text-[40px] leading-none font-semibold tracking-tight">
              #{fmt(reach ? row.reach_rank! : row.scanner_rank)}
            </span>
            <span className="text-sm text-fg-3">of {fmt(total)}</span>
          </p>
        </div>
        <div className="text-right">
          <p className="eyebrow">CVSS</p>
          <p className="mt-2 text-[40px] leading-none font-semibold tracking-tight text-fg">{row.cvss?.toFixed(1)}</p>
        </div>
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-2 text-sm">
        <span className="mono text-fg">{row.cve}</span>
        <Kev on={row.kev} />
        <span className="text-fg-3">on</span>
        <span className="mono text-fg-2">{row.hostname}</span>
      </div>
      <p className={cn("mt-3 text-base", reach ? "text-fg" : "text-fg-2")}>
        {reach && <span className="mr-2 inline-block size-2 rounded-full bg-ember align-middle" />}
        {row.why}
      </p>
      <p className="mt-3 text-xs text-fg-3">
        {reach
          ? `The scanner put it at #${fmt(row.scanner_rank)}.`
          : row.reach_rank
            ? `Reachable puts it at #${row.reach_rank}.`
            : "Reachable does not rank it: no path, nothing to fix first."}
      </p>
    </button>
  );
}

function Row({
  row,
  rank,
  other,
  selected,
  onSelect,
  setRef,
}: {
  row: BoardRow;
  rank: number;
  other: string;
  selected: boolean;
  onSelect: () => void;
  setRef: (el: HTMLDivElement | null) => void;
}) {
  const reach = row.status === "reachable";
  return (
    <div
      ref={setRef}
      role="row"
      aria-selected={selected}
      data-testid="finding-row"
      data-finding={row.finding}
      data-status={row.status}
      onClick={onSelect}
      className={cn(
        COLS,
        "relative cursor-pointer border-b border-line/70 px-5 py-2.5 text-sm transition-colors",
        selected ? "bg-raised" : "hover:bg-panel-2",
      )}
    >
      {reach && <span className="absolute inset-y-1 left-0 w-[3px] rounded-r bg-ember" />}
      {selected && <span className="pointer-events-none absolute inset-0 ring-1 ring-fg-2/40 ring-inset" />}
      <div className="leading-tight">
        <span className="num text-base font-semibold">{rank}</span>
        <span className="mono block text-2xs text-fg-3">{other}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="mono text-fg">{row.cve}</span>
      </div>
      <Cvss v={row.cvss} />
      <Epss v={row.epss} />
      <Kev on={row.kev} />
      <div className="min-w-0">
        <p className="mono truncate text-fg-2">{row.hostname}</p>
        <p className="text-2xs text-fg-3">
          <Id id={row.finding} className="text-fg-3" />
          {row.zone ? ` · ${row.zone}` : ""}
        </p>
      </div>
      <p className={cn("min-w-0 truncate", reach ? "text-fg" : "text-fg-3")} title={row.why}>
        {reach && <span className="mr-2 inline-block size-1.5 rounded-full bg-ember align-middle" />}
        {row.why}
        {row.headline && (
          <span className="mono ml-2 rounded-sm border border-line-2 px-1 py-px text-2xs text-fg-2">headline</span>
        )}
      </p>
      <div className="text-right">
        <Verdict v={row.verdict} />
      </div>
    </div>
  );
}

export function FindingsScreen() {
  const ws = useWorkspace();
  const board = useBoard();
  const [order, setOrder] = useState<Order>("reachability");
  const rows = useRef(new Map<string, HTMLDivElement>());
  const tops = useRef(new Map<string, number>());

  const ids = useMemo(() => {
    const b = board.data;
    if (!b) return [];
    return order === "severity" ? b.by_severity : b.by_reachability;
  }, [board.data, order]);

  // FLIP: rows slide from their old place to their new one when the order
  // flips, so you watch the 5.0 climb and the 9.8s sink.
  useLayoutEffect(() => {
    rows.current.forEach((el, id) => {
      const prev = tops.current.get(id);
      const next = el.offsetTop;
      if (prev !== undefined && prev !== next) {
        el.animate([{ transform: `translateY(${prev - next}px)` }, { transform: "none" }], {
          duration: 700,
          easing: "cubic-bezier(.2,.7,.2,1)",
        });
      }
      tops.current.set(id, next);
    });
  }, [ids]);

  if (board.error) return <ErrorState error={board.error} retry={board.reload} what="the findings" />;
  if (!board.data) return <LoadingRows rows={10} label="Ranking findings" />;
  const b = board.data;
  const F = b.findings;
  const hiReach = Object.values(F).find((r) => r.headline === "reachable");
  const hiUnreach = Object.values(F).find((r) => r.headline === "unreachable");
  const crown = b.crown_jewels.map((c) => c.name).join(", ");

  return (
    <div className="mx-auto max-w-[1500px] px-8 pt-7 pb-16">
      <p className="eyebrow">01 · Findings, re-ranked</p>
      <h1 className="mt-2 text-[28px] leading-tight font-semibold tracking-tight">
        {fmt(b.total_open)} open findings. <span className="text-ember">{b.on_crown_path}</span> lead to the {crown}.
      </h1>
      <p className="mt-2 max-w-3xl text-base text-fg-2">
        Same findings, two orders. The scanner sorts by CVSS. Reachable sorts by what an attacker can actually reach:
        Internet, through your hosts, identities and secrets, to a crown-jewel data store.
      </p>

      <div className="mt-6 flex flex-wrap gap-x-12 gap-y-4">
        <Stat label="Open findings" value={fmt(b.total_open)} sub={`scan ${ws.scan}`} />
        <Stat label="On a crown-jewel path" value={b.on_crown_path} tone="ember" sub={`${((b.on_crown_path / b.total_open) * 100).toFixed(2)}% of the scan`} />
        <Stat label="Crown jewels" value={b.crown_jewels.length} sub={crown} />
        <Stat
          label="Ranked by"
          value={<span className="mono text-xl">{b.source === "run" ? shortRun(b.run_id) : "live"}</span>}
          sub={b.source === "run" ? "the agents' finished run (replay)" : "the graph, no run yet"}
        />
      </div>

      {hiReach && hiUnreach && (
        <div className="mt-8 flex items-stretch gap-4" data-testid="headline-pair">
          <HeadlineCard row={hiUnreach} side="high" total={b.total_open} onPick={() => ws.set({ f: hiUnreach.finding })} />
          <div className="flex flex-col items-center justify-center gap-1 px-1 text-fg-3">
            <MoveRight className="size-5" />
            <span className="eyebrow">vs</span>
          </div>
          <HeadlineCard row={hiReach} side="low" total={b.total_open} onPick={() => ws.set({ f: hiReach.finding })} />
        </div>
      )}

      <div className="mt-10 mb-3 flex items-center justify-between gap-4">
        <Seg
          testid="order-toggle"
          value={order}
          onChange={setOrder}
          options={[
            { value: "severity", label: "Sorted by severity" },
            { value: "reachability", label: "Sorted by reachability (Reachable)" },
          ]}
        />
        <div className="flex items-center gap-5 text-xs text-fg-3">
          <span className="flex items-center gap-2">
            <span className="h-3 w-[3px] rounded bg-ember" /> on a path to a crown jewel
          </span>
          <span>{Object.keys(F).length} findings shown: every reachable one, plus what a CVSS-first list puts on top</span>
        </div>
      </div>

      <div className="panel overflow-hidden" role="table" data-testid="findings-table" data-order={order}>
        <div role="row" className={cn(COLS, "border-b border-line bg-panel-2 px-5 py-2")}>
          {["#", "CVE", "CVSS", "EPSS", "KEV", "Asset", "Why this rank", "Verdict"].map((h, i) => (
            <span key={h} className={cn("eyebrow", i === 7 && "text-right")}>
              {h}
            </span>
          ))}
        </div>
        {ids.length === 0 ? (
          <EmptyState title="No findings in this scan" />
        ) : (
          <div className="relative">
            {ids.map((id, i) => {
              const r = F[id];
              const other =
                order === "severity"
                  ? r.reach_rank
                    ? `reach #${r.reach_rank}`
                    : "no path"
                  : `cvss #${fmt(r.scanner_rank)}`;
              return (
                <Row
                  key={id}
                  row={r}
                  rank={order === "severity" ? r.scanner_rank : (r.reach_rank ?? i + 1)}
                  other={other}
                  selected={ws.finding === id}
                  onSelect={() => ws.set({ f: ws.finding === id ? null : id })}
                  setRef={(el) => {
                    if (el) rows.current.set(id, el);
                    else rows.current.delete(id);
                  }}
                />
              );
            })}
          </div>
        )}
      </div>

      {ws.finding && F[ws.finding] && (
        <div className="sticky bottom-4 mt-6 flex justify-end">
          <Link
            href={ws.href("/paths")}
            data-testid="view-path"
            className="flex items-center gap-3 rounded-lg border border-line-2 bg-raised px-4 py-3 text-sm shadow-xl shadow-black/40 hover:border-fg-3"
          >
            <span className="mono text-fg-2">{F[ws.finding].hostname}</span>
            <span className="font-medium">
              {F[ws.finding].status === "reachable" ? "See its attack path" : "See why nothing reaches it"}
            </span>
            <ArrowRight className="size-4" />
          </Link>
        </div>
      )}
    </div>
  );
}
