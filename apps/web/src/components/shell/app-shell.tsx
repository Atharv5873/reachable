"use client";

import { Activity, BrainCircuit, GitCompareArrows, ListOrdered, Network, Scissors, Table2, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { Seg, day, shortId, shortRun } from "@/components/bits";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { ORG_LABEL, type Scan, useWorkspace } from "@/lib/workspace";

const NAV = [
  { href: "/findings", n: "01", label: "Findings", sub: "re-ranked", icon: ListOrdered },
  { href: "/paths", n: "02", label: "Attack paths", sub: "the hero view", icon: Network },
  { href: "/fixes", n: "03", label: "Fix plan", sub: "min cut", icon: Scissors },
  { href: "/live", n: "04", label: "Investigation", sub: "watch it reason", icon: Activity },
  { href: "/ask", n: "05", label: "Company brain", sub: "who, why, when", icon: BrainCircuit },
  { href: "/drift", n: "06", label: "Drift", sub: "v1 to v2", icon: GitCompareArrows },
  { href: "/evals", n: "07", label: "Evals", sub: "results", icon: Table2 },
];

function Logo() {
  return (
    <svg viewBox="0 0 28 28" className="size-7" aria-hidden>
      <circle cx="5" cy="14" r="3" fill="none" stroke="var(--fg-2)" strokeWidth="1.5" />
      <path d="M8 14 L14 8 L20 14 L14 20 Z" fill="none" stroke="var(--fg-3)" strokeWidth="1.5" />
      <path d="M8 14 H20" stroke="var(--ember)" strokeWidth="2" />
      <circle cx="23" cy="14" r="3" fill="var(--ember)" />
    </svg>
  );
}

function Health() {
  const [ok, setOk] = useState<boolean | null>(null);
  useEffect(() => {
    let alive = true;
    const check = () =>
      api<{ status: string }>("health")
        .then((h) => alive && setOk(h.status === "ok"))
        .catch(() => alive && setOk(false));
    check();
    const t = setInterval(check, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  return (
    <div className="flex items-center gap-2 text-xs text-fg-3" data-testid="backend-health">
      <span
        className={cn(
          "size-2 rounded-full",
          ok === null && "bg-line-2",
          ok === true && "bg-fg-2",
          ok === false && "border border-fg-2 bg-transparent",
        )}
      />
      {ok === null ? "Checking backend" : ok ? "Backend healthy" : "Backend unreachable"}
    </div>
  );
}

function Sidebar() {
  const pathname = usePathname();
  const ws = useWorkspace();
  return (
    <aside className="flex w-[228px] shrink-0 flex-col border-r border-line bg-panel">
      <div className="flex items-center gap-2.5 px-5 pt-5 pb-6">
        <Logo />
        <div>
          <p className="text-[17px] leading-none font-semibold tracking-tight">Reachable</p>
          <p className="mt-1 text-2xs text-fg-3">Decisions you can trace</p>
        </div>
      </div>
      <nav className="flex flex-col gap-0.5 px-3" aria-label="Screens">
        {NAV.map((item) => {
          const active = pathname === item.href || (pathname === "/" && item.href === "/findings");
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={ws.href(item.href)}
              className={cn(
                "group flex items-center gap-3 rounded-md px-2.5 py-2 transition-colors",
                active ? "bg-raised text-fg" : "text-fg-2 hover:bg-panel-2 hover:text-fg",
              )}
            >
              <span className={cn("mono w-5 text-2xs", active ? "text-ember" : "text-fg-3")}>{item.n}</span>
              <Icon className="size-4 shrink-0 opacity-80" aria-hidden />
              <span className="min-w-0">
                <span className="block text-sm leading-tight font-medium">{item.label}</span>
                <span className="block text-2xs leading-tight text-fg-3">{item.sub}</span>
              </span>
            </Link>
          );
        })}
      </nav>
      <div className="mt-auto space-y-3 border-t border-line px-5 py-4">
        <Health />
        <p className="text-2xs leading-relaxed text-fg-3">
          Synthetic, fictional orgs. Threat intel is real public data (CISA KEV, FIRST EPSS, NVD,
          MITRE ATT&amp;CK).
        </p>
      </div>
    </aside>
  );
}

function RunPicker() {
  const ws = useWorkspace();
  if (!ws.runs.length) {
    return <span className="text-xs text-fg-3">no finished run</span>;
  }
  return (
    <label className="flex items-center gap-2 text-xs text-fg-3">
      <span className="eyebrow">Run</span>
      <select
        data-testid="run-picker"
        className="mono h-8 rounded-md border border-line bg-panel px-2 text-xs text-fg outline-none hover:border-line-2"
        value={ws.runId ?? ""}
        onChange={(e) => ws.set({ run: e.target.value, f: null })}
      >
        {ws.runs.map((r) => (
          <option key={r.id} value={r.id}>
            {shortRun(r.id)} · {r.status} · scan {day(r.as_of)}
          </option>
        ))}
      </select>
    </label>
  );
}

function TopBar() {
  const ws = useWorkspace();
  const orgs = ws.orgs?.map((o) => o.org) ?? ["org_a", "org_b", "org_c"];
  return (
    <header className="flex h-[60px] shrink-0 items-center gap-5 border-b border-line bg-bg/80 px-6 backdrop-blur">
      <Seg
        testid="org-picker"
        value={ws.org}
        onChange={(org) => ws.set({ org })}
        options={orgs.map((o) => ({
          value: o,
          label: (
            <span className="flex items-baseline gap-1.5">
              <span className="mono text-xs">{o}</span>
              <span className="hidden text-2xs text-fg-3 xl:inline">{ORG_LABEL[o]}</span>
            </span>
          ),
        }))}
      />
      <Seg
        testid="scan-picker"
        value={ws.scan}
        onChange={(scan: Scan) => ws.set({ scan })}
        options={[
          { value: "v1", label: "scan v1", hint: "2024-01-01" },
          { value: "v2", label: "scan v2", hint: "a week later" },
        ]}
      />
      <RunPicker />
      <div className="ml-auto flex items-center gap-4">
        {ws.finding && (
          <span className="flex items-center gap-2 rounded-md border border-line bg-panel px-2.5 py-1 text-xs">
            <span className="eyebrow">Selected</span>
            <span className="mono text-fg">{shortId(ws.finding)}</span>
            <button aria-label="Clear selection" onClick={() => ws.set({ f: null })} className="text-fg-3 hover:text-fg">
              <X className="size-3.5" />
            </button>
          </span>
        )}
        <Seg
          testid="mode-picker"
          value={ws.mode}
          onChange={(mode) => ws.set({ mode })}
          options={[
            { value: "replay", label: "Replay", hint: "Read a finished run from the graph. No model calls." },
            {
              value: "live",
              label: (
                <span className="flex items-center gap-1.5">
                  <span className={cn("size-1.5 rounded-full", ws.mode === "live" ? "animate-pulse-ember bg-ember" : "bg-fg-3")} />
                  Live
                </span>
              ),
              hint: "Start real agent runs and stream them.",
            },
          ]}
        />
      </div>
    </header>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-dvh overflow-hidden">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="min-h-0 flex-1 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}

export function ShellFallback() {
  return (
    <div className="flex h-dvh">
      <div className="w-[228px] border-r border-line bg-panel" />
      <div className="flex-1" />
    </div>
  );
}
