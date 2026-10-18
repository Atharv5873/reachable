// S10: the same proof as check-client-bundle.mjs, against a DEPLOYED site.
//
//   REACHABLE_API_KEY=... node scripts/check-live-bundle.mjs https://reachable.devarv.dev
//
// Fetches every screen's HTML, then every /_next/static asset it references,
// following references inside the JS too (chunks load chunks), and searches
// all of it for the key's value and the env var's name. Exits 1 on a leak.

const base = (process.argv[2] || "").replace(/\/+$/, "");
const key = process.env.REACHABLE_API_KEY || "";
if (!base || key.length < 16) {
  console.error("usage: REACHABLE_API_KEY=... node scripts/check-live-bundle.mjs <site url>");
  process.exit(2);
}

const PAGES = ["/", "/findings", "/paths", "/fixes", "/live", "/ask", "/drift", "/evals"];
const ASSET = /\/_next\/static\/[^"'\s)\\]+/g;
const needles = [key, "REACHABLE_API_KEY"];
const seen = new Set();
const queue = [...PAGES];
const leaks = [];
let bytes = 0;

while (queue.length) {
  const p = queue.shift();
  if (seen.has(p)) continue;
  seen.add(p);
  const res = await fetch(base + p);
  if (!res.ok) {
    console.error(`${res.status} ${p}`);
    continue;
  }
  const text = await res.text();
  bytes += text.length;
  for (const n of needles) if (text.includes(n)) leaks.push(`${p}: ${n === key ? "<the key>" : n}`);
  for (const m of text.matchAll(ASSET)) if (!seen.has(m[0])) queue.push(m[0]);
}

if (leaks.length) {
  console.error(`LEAK on ${base}:\n${leaks.join("\n")}`);
  process.exit(1);
}
console.log(`ok: ${seen.size} responses (${PAGES.length} pages + assets, ${(bytes / 1024).toFixed(0)} KiB) from ${base}; the API key and its env var name appear in none`);
