"use client";

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { Tier as TierName } from "@/lib/types";
import { cn } from "@/lib/utils";

/** Small, consistent pieces: ids, KEV, CVSS, effort, stats. */

export function shortId(id: string | null | undefined): string {
  if (!id) return "";
  if (id.startsWith("step:")) {
    const kind = id.split(":")[1];
    return `${kind} step`;
  }
  const parts = id.split(":");
  return parts.length >= 3 ? parts.slice(2).join(":") : id;
}

export function shortRun(id: string | null | undefined): string {
  return id ? id.split(":").pop()!.slice(0, 6) : "";
}

export function day(ts?: number | null): string {
  if (!ts) return "";
  return new Date(ts * 1000).toISOString().slice(0, 10);
}

export function Id({ id, className }: { id: string; className?: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={cn("mono cursor-default text-fg-2", className)}>{shortId(id)}</span>
      </TooltipTrigger>
      <TooltipContent className="mono">{id}</TooltipContent>
    </Tooltip>
  );
}

export function Kev({ on }: { on: boolean }) {
  if (!on) return <span className="text-2xs text-fg-3">-</span>;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="mono inline-flex h-5 items-center rounded-sm border border-fg-2/60 px-1.5 text-2xs font-semibold tracking-wider text-fg">
          KEV
        </span>
      </TooltipTrigger>
      <TooltipContent>In CISA&apos;s Known Exploited Vulnerabilities catalog</TooltipContent>
    </Tooltip>
  );
}

/** CVSS as the scanner sees it: a number and a neutral bar. Deliberately not
 *  red: severity is not reachability. */
export function Cvss({ v }: { v: number | null }) {
  if (v == null) return <span className="text-fg-3">-</span>;
  return (
    <span className="inline-flex items-center gap-2">
      <span className="mono num w-8 text-right text-fg">{v.toFixed(1)}</span>
      <span className="relative h-1 w-12 overflow-hidden rounded-full bg-line">
        <span className="absolute inset-y-0 left-0 bg-fg-2" style={{ width: `${v * 10}%` }} />
      </span>
    </span>
  );
}

export function Epss({ v }: { v: number | null }) {
  if (v == null) return <span className="text-fg-3">-</span>;
  return <span className="mono num text-fg-2">{(v * 100).toFixed(v < 0.1 ? 1 : 0)}%</span>;
}

export function Effort({ n }: { n?: number }) {
  if (!n) return null;
  return (
    <span className="inline-flex items-center gap-0.5" aria-label={`effort ${n} of 5`}>
      {[1, 2, 3, 4, 5].map((i) => (
        <span key={i} className={cn("h-2 w-1.5 rounded-[1px]", i <= n ? "bg-fg-2" : "bg-line-2")} />
      ))}
    </span>
  );
}

export function Stat({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  tone?: "ember" | "safe";
}) {
  return (
    <div className="min-w-0">
      <p className="eyebrow">{label}</p>
      <p
        className={cn(
          "num mt-1 text-[28px] leading-none font-semibold tracking-tight",
          tone === "ember" && "text-ember",
          tone === "safe" && "text-safe",
        )}
      >
        {value}
      </p>
      {sub && <p className="mt-1.5 text-xs text-fg-3">{sub}</p>}
    </div>
  );
}

export function Seg<T extends string>({
  value,
  options,
  onChange,
  size = "md",
  testid,
}: {
  value: T;
  options: { value: T; label: React.ReactNode; hint?: string }[];
  onChange: (v: T) => void;
  size?: "sm" | "md";
  testid?: string;
}) {
  return (
    <div
      role="radiogroup"
      data-testid={testid}
      className="inline-flex rounded-md border border-line bg-panel p-0.5"
    >
      {options.map((o) => (
        <button
          key={o.value}
          role="radio"
          aria-checked={o.value === value}
          title={o.hint}
          onClick={() => onChange(o.value)}
          className={cn(
            "rounded-[5px] font-medium transition-colors",
            size === "sm" ? "px-2 py-0.5 text-xs" : "px-3 py-1 text-sm",
            o.value === value ? "bg-raised text-fg shadow-sm" : "text-fg-3 hover:text-fg-2",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

const TIER_HINT: Record<TierName, string> = {
  critical: "Critical crown jewel: customer or payment data",
  crown: "Crown jewel",
  high: "High-sensitivity crown jewel: internal credentials, source or deploy secrets",
  medium: "Medium-sensitivity crown jewel: an ops or log store",
};

/** The sensitivity tier of the crown jewel a path reaches (S9). */
export function Tier({ tier, className }: { tier: TierName | null | undefined; className?: string }) {
  if (!tier) return null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          data-testid="tier-badge"
          data-tier={tier}
          className={cn(
            "mono inline-flex h-5 items-center rounded-sm border px-1.5 text-2xs tracking-wider whitespace-nowrap",
            tier === "critical" || tier === "crown"
              ? "border-ember/60 text-ember"
              : tier === "high"
                ? "border-fg-2/60 text-fg-2"
                : "border-line-2 text-fg-3",
            className,
          )}
        >
          {tier}
        </span>
      </TooltipTrigger>
      <TooltipContent>{TIER_HINT[tier]}</TooltipContent>
    </Tooltip>
  );
}

export function Verdict({ v }: { v: string | null }) {
  if (!v) return null;
  const label = v.replace(/_/g, " ");
  return (
    <span
      className={cn(
        "mono rounded-sm px-1.5 py-0.5 text-2xs",
        v === "fix_now" ? "bg-fg/90 text-bg" : "border border-line-2 text-fg-2",
      )}
    >
      {label}
    </span>
  );
}
