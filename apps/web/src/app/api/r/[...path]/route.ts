import type { NextRequest } from "next/server";

import { forward } from "@/lib/server/backend";

// The browser's only door to the Reachable API: same origin, no key in the
// client. See lib/server/backend.ts.

// A live run's SSE relay is the one long response (a real run takes 30-70 s).
// On Vercel a function is cut at this limit (300 s is the Hobby ceiling);
// EventSource then resumes with Last-Event-ID, and the Investigation screen
// falls back to polling /events if the stream keeps failing. Replay never
// streams: it reads /runs/{id}/events once.
export const maxDuration = 300;

type Ctx = { params: Promise<{ path: string[] }> };

export async function GET(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return forward(req, path);
}

export async function POST(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return forward(req, path);
}
