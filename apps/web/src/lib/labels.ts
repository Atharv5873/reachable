// Display-only copy helpers: no data fetching, no business logic.
import type { BoardRow, CrownJewel, Subgraph, Tier } from "@/lib/types";

const TIER_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, crown: 3 };
// "the critical bucket and the high-tier bucket"; pre-S9 "crown" says nothing.
const TIER_WORD: Partial<Record<Tier, string>> = { critical: "critical", high: "high-tier", medium: "medium-tier" };

/** "the a", "the a and the b", "the a, the b and the c". */
function theList(names: string[]): string {
  const the = names.map((n) => `the ${n}`);
  return the.length < 2 ? (the[0] ?? "") : `${the.slice(0, -1).join(", ")} and ${the[the.length - 1]}`;
}

/** Crown jewels named for a title, article included ("to " + this). Two org_a
 *  crown jewels are both named "bucket", so when any names collide each one
 *  is named by its sensitivity tier: "the critical bucket and the high-tier
 *  bucket". `among` is the org's full list (the clash is judged there);
 *  `show` limits which ones are named. */
export function crownPhrase(among: CrownJewel[], show: CrownJewel[] = among): string {
  if (show.length === 0) return "the crown jewel";
  const counts = new Map<string, number>();
  for (const c of [...among, ...show].filter((c, i, all) => all.findIndex((d) => d.id === c.id) === i)) {
    counts.set(c.name, (counts.get(c.name) ?? 0) + 1);
  }
  const clash = [...counts.values()].some((n) => n > 1);
  if (!clash) return theList([...new Set(show.map((c) => c.name))]);
  const sorted = [...show].sort((a, b) => (TIER_RANK[a.tier ?? ""] ?? 9) - (TIER_RANK[b.tier ?? ""] ?? 9));
  return theList(sorted.map((c) => (c.tier && TIER_WORD[c.tier] ? `${TIER_WORD[c.tier]} ${c.name}` : c.name)));
}

/** The crown jewels a subgraph's paths end at, with the name and sensitivity
 *  tier its nodes carry. */
export function crownTargets(g: Subgraph | undefined): CrownJewel[] {
  if (!g) return [];
  const node = new Map(g.nodes.map((n) => [n.id, n]));
  return [...new Set(g.paths.map((p) => p.target))].map((id) => ({
    id,
    name: node.get(id)?.name ?? id,
    tier: node.get(id)?.tier ?? null,
  }));
}

/** Where a finding's step sits on a subgraph's paths: 1-based path number (as
 *  the Paths screen and the backend's why-line count them) and hop. */
export type Placement = { path: number; hop: number };

export function placements(g: Subgraph | undefined, finding: string): Placement[] {
  if (!g) return [];
  const token = new Map(g.edges.map((e) => [e.id, e.fix_token]));
  const out: Placement[] = [];
  for (const p of g.paths) {
    const j = p.steps.findIndex((s) => token.get(s) === finding);
    if (j >= 0) out.push({ path: p.index + 1, hop: j + 1 });
  }
  return out.sort((a, b) => a.path - b.path);
}

/** A reachable finding's why-line. When its step lies on several attack paths
 *  (which is why it ranks high), lead with the count, then where it sits:
 *  "On 3 of 9 attack paths — hop 2 of paths #4, #8, #9". One path (or no path
 *  data) keeps the backend's own line. */
export function whyLine(row: BoardRow, on: Placement[] = [], total?: number): string {
  if (row.status !== "reachable" || on.length < 2) return row.why;
  const byHop = new Map<number, number[]>();
  for (const { path, hop } of on) byHop.set(hop, [...(byHop.get(hop) ?? []), path]);
  const where = [...byHop]
    .sort(([a], [b]) => a - b)
    .map(([hop, ps]) => {
      const list = `path${ps.length > 1 ? "s" : ""} ${ps.map((n) => `#${n}`).join(", ")}`;
      return hop === 1 ? `starts ${list}` : `hop ${hop} of ${list}`;
    })
    .join("; ");
  const of = total && total >= on.length ? ` of ${total}` : "";
  return `On ${on.length}${of} attack paths — ${where}`;
}
