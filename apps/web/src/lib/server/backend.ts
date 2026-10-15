import "server-only";

/**
 * The only place the Reachable API key lives in the web app.
 *
 * The browser talks to `/api/r/<path>` (a Next route handler on our own
 * origin). That handler runs on the server, checks the path against an
 * allowlist, adds `X-API-Key` from a server-only env var, and relays the
 * backend's answer, including the SSE stream, byte for byte. So:
 *   - the key is never in a client bundle (this module imports "server-only",
 *     and the env var has no NEXT_PUBLIC_ prefix, so Next never inlines it);
 *   - EventSource, which cannot set request headers, still works: it opens a
 *     plain same-origin GET and the proxy adds the header upstream;
 *   - the backend needs no CORS for the browser at all.
 */

export type Method = "GET" | "POST";

// What the UI may call. Anything else is a 404 from the proxy and never
// reaches the backend.
const SEG = "[^/]+";
const ALLOW: Record<Method, RegExp[]> = {
  GET: [
    /^health$/,
    /^orgs$/,
    new RegExp(`^orgs/${SEG}/(drift|findings|why_step)$`),
    new RegExp(`^runs/${SEG}$`),
    new RegExp(`^runs/${SEG}/(stream|events|subgraph|fixplan)$`),
    /^evals$/,
  ],
  POST: [
    /^runs$/,
    new RegExp(`^runs/${SEG}/verdict$`),
    new RegExp(`^orgs/${SEG}/(simulate|ask)$`),
  ],
};

export function isAllowed(method: string, segments: string[]): boolean {
  const rules = ALLOW[method as Method];
  if (!rules || segments.some((s) => s === "" || s === "." || s === "..")) return false;
  const path = segments.join("/");
  return rules.some((r) => r.test(path));
}

export function backendConfig(env: NodeJS.ProcessEnv = process.env) {
  return {
    url: (env.REACHABLE_API_URL || "http://localhost:8001").replace(/\/+$/, ""),
    key: env.REACHABLE_API_KEY || "",
  };
}

const PASS_HEADERS = ["content-type", "retry-after"];

export async function forward(
  req: Request,
  segments: string[],
  opts: { fetchImpl?: typeof fetch; env?: NodeJS.ProcessEnv } = {},
): Promise<Response> {
  const method = req.method.toUpperCase();
  if (!isAllowed(method, segments)) {
    return Response.json({ detail: "not found" }, { status: 404 });
  }
  const { url, key } = backendConfig(opts.env);
  if (!key) {
    return Response.json(
      { detail: "REACHABLE_API_KEY is not set on the web server" },
      { status: 500 },
    );
  }
  // Next hands us decoded segments (run ids contain ':'); encode each again.
  const path = segments.map(encodeURIComponent).join("/");
  const search = new URL(req.url).search;
  const headers = new Headers({
    "X-API-Key": key,
    Accept: req.headers.get("accept") || "application/json",
  });
  // EventSource sends Last-Event-ID itself when it reconnects; the backend
  // resumes the stream after that trace step.
  const lastId = req.headers.get("last-event-id");
  if (lastId) headers.set("Last-Event-ID", lastId);
  let body: string | undefined;
  if (method === "POST") {
    body = await req.text();
    headers.set("Content-Type", "application/json");
  }

  let upstream: Response;
  try {
    upstream = await (opts.fetchImpl ?? fetch)(`${url}/${path}${search}`, {
      method,
      headers,
      body,
      // A closed browser tab aborts the upstream request too, so the backend
      // stops polling the trace for a reader that is gone.
      signal: req.signal,
      cache: "no-store",
    });
  } catch (err) {
    if (req.signal?.aborted) return new Response(null, { status: 499 });
    return Response.json(
      { detail: "The Reachable backend is not reachable.", cause: String(err).slice(0, 200) },
      { status: 502 },
    );
  }

  const out = new Headers();
  for (const h of PASS_HEADERS) {
    const v = upstream.headers.get(h);
    if (v) out.set(h, v);
  }
  if ((upstream.headers.get("content-type") || "").startsWith("text/event-stream")) {
    // no-transform: nothing on the way (compression included) may buffer it.
    out.set("Cache-Control", "no-cache, no-transform");
    out.set("X-Accel-Buffering", "no");
    out.set("Connection", "keep-alive");
  } else {
    out.set("Cache-Control", "no-store");
  }
  return new Response(upstream.body, { status: upstream.status, headers: out });
}
