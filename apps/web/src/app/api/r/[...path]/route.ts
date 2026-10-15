import type { NextRequest } from "next/server";

import { forward } from "@/lib/server/backend";

// The browser's only door to the Reachable API: same origin, no key in the
// client. See lib/server/backend.ts.

type Ctx = { params: Promise<{ path: string[] }> };

export async function GET(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return forward(req, path);
}

export async function POST(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return forward(req, path);
}
