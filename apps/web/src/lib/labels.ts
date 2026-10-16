// Display-only copy helpers: no data fetching, no business logic.
import type { BoardRow, CrownJewel, RunDump } from "@/lib/types";

/** Crown-jewel names for a title. Two org_a crown jewels are both named
 *  "bucket", so when any names collide every jewel gets its sensitivity tier:
 *  "bucket (critical) / bucket (high)". `among` is the org's full list (the
 *  collision is judged there); `show` limits which ones are named. */
export function crownLabel(among: CrownJewel[], show: CrownJewel[] = among): string {
  if (show.length === 0) return "crown jewel";
  const counts = new Map<string, number>();
  for (const c of among) counts.set(c.name, (counts.get(c.name) ?? 0) + 1);
  const clash = [...counts.values()].some((n) => n > 1);
  if (!clash) return [...new Set(show.map((c) => c.name))].join(", ");
  return show.map((c) => (c.tier ? `${c.name} (${c.tier})` : c.name)).join(" / ");
}

/** finding id -> the number of distinct Internet -> crown-jewel paths its step
 *  lies on, from the run's own ranking (PathAnalysis `ranked[].on_paths`). */
export function onPathsByFinding(run: RunDump | undefined): Map<string, number> {
  const ranked = run?.outputs?.PathAnalysis?.payload?.ranked;
  const out = new Map<string, number>();
  if (!Array.isArray(ranked)) return out;
  for (const r of ranked) {
    if (typeof r?.finding === "string" && typeof r?.on_paths === "number") out.set(r.finding, r.on_paths);
  }
  return out;
}

/** A reachable finding's why-line. When its step lies on several attack paths
 *  (which is why it ranks high), say so before the per-path detail. */
export function whyLine(row: BoardRow, onPaths?: number): string {
  if (row.status !== "reachable" || !onPaths || onPaths < 2) return row.why;
  return `On ${onPaths} attack paths · ${row.why}`;
}
