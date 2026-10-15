// After `next build`: prove the API key never reached the browser.
//
// Scans everything Next ships to the client (.next/static) for the key's
// value and for the env var's name. The key lives only in a server-only module
// (lib/server/backend.ts) and has no NEXT_PUBLIC_ prefix, so neither may
// appear. Exits 1 on a leak.
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const staticDir = path.join(root, ".next", "static");

function readKey() {
  if (process.env.REACHABLE_API_KEY) return process.env.REACHABLE_API_KEY;
  for (const f of [".env.local", ".env.production.local", ".env"]) {
    const p = path.join(root, f);
    if (!fs.existsSync(p)) continue;
    const m = fs.readFileSync(p, "utf8").match(/^REACHABLE_API_KEY=(.+)$/m);
    if (m) return m[1].trim();
  }
  return null;
}

function* files(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* files(p);
    else yield p;
  }
}

if (!fs.existsSync(staticDir)) {
  console.error("no .next/static: run `next build` first");
  process.exit(2);
}
const key = readKey();
if (!key || key.length < 16) {
  console.error("REACHABLE_API_KEY not found (env or .env.local): nothing to check against");
  process.exit(2);
}
const needles = [key, "REACHABLE_API_KEY"];
let scanned = 0;
const leaks = [];
for (const f of files(staticDir)) {
  scanned++;
  const text = fs.readFileSync(f, "latin1");
  for (const n of needles) if (text.includes(n)) leaks.push(`${path.relative(root, f)}: ${n === key ? "<the key>" : n}`);
}
if (leaks.length) {
  console.error(`LEAK: the API key reached the client bundle:\n${leaks.join("\n")}`);
  process.exit(1);
}
console.log(`ok: ${scanned} client files scanned, the API key and its env var name appear in none`);
