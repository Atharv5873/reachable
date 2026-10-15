import { describe, expect, it, vi } from "vitest";

import { GET, POST } from "@/app/api/r/[...path]/route";

import { forward, isAllowed } from "./backend";

const KEY = "s3cret-key-for-tests-0123456789";
const ENV = { REACHABLE_API_URL: "http://backend:8001/", REACHABLE_API_KEY: KEY } as unknown as NodeJS.ProcessEnv;

function upstream(body: BodyInit, init: ResponseInit = {}) {
  return vi.fn(async (url: string | URL | Request, req?: RequestInit) => {
    void url;
    void req;
    return new Response(body, init);
  });
}

describe("the API proxy", () => {
  it("injects the key server-side and relays the answer without it", async () => {
    const f = upstream(JSON.stringify({ ok: 1 }), { headers: { "content-type": "application/json" } });
    const req = new Request("http://web/api/r/runs/org_a:run:abc/subgraph?finding=org_a:finding:1&context=true");
    const res = await forward(req, ["runs", "org_a:run:abc", "subgraph"], { fetchImpl: f, env: ENV });
    expect(res.status).toBe(200);
    const [url, init] = f.mock.calls[0];
    // run ids carry ':'; each segment is encoded again, the query is kept
    expect(String(url)).toBe("http://backend:8001/runs/org_a%3Arun%3Aabc/subgraph?finding=org_a:finding:1&context=true");
    expect(new Headers(init!.headers).get("x-api-key")).toBe(KEY);
    const text = await res.text();
    expect(text).not.toContain(KEY);
    for (const [, v] of res.headers) expect(v).not.toContain(KEY);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("never passes a key from the browser through, and ignores client auth headers", async () => {
    const f = upstream("{}", { headers: { "content-type": "application/json" } });
    const req = new Request("http://web/api/r/orgs", { headers: { "x-api-key": "attacker", authorization: "Bearer x" } });
    await forward(req, ["orgs"], { fetchImpl: f, env: ENV });
    const h = new Headers(f.mock.calls[0][1]!.headers);
    expect(h.get("x-api-key")).toBe(KEY);
    expect(h.get("authorization")).toBeNull();
  });

  it("relays an SSE stream unbuffered and forwards Last-Event-ID", async () => {
    const enc = new TextEncoder();
    const stream = new ReadableStream({
      start(c) {
        c.enqueue(enc.encode("id: 3\nevent: tool_called\ndata: {}\n\n"));
        c.close();
      },
    });
    const f = upstream(stream, { headers: { "content-type": "text/event-stream" } });
    const req = new Request("http://web/api/r/runs/r1/stream", {
      headers: { "last-event-id": "17", accept: "text/event-stream" },
    });
    const res = await forward(req, ["runs", "r1", "stream"], { fetchImpl: f, env: ENV });
    const h = new Headers(f.mock.calls[0][1]!.headers);
    expect(h.get("last-event-id")).toBe("17");
    expect(h.get("accept")).toBe("text/event-stream");
    expect(res.headers.get("content-type")).toBe("text/event-stream");
    expect(res.headers.get("cache-control")).toContain("no-transform");
    expect(await res.text()).toContain("event: tool_called");
  });

  it("allows only the UI's endpoints", () => {
    expect(isAllowed("GET", ["orgs"])).toBe(true);
    expect(isAllowed("GET", ["runs", "x", "stream"])).toBe(true);
    expect(isAllowed("POST", ["orgs", "org_a", "ask"])).toBe(true);
    expect(isAllowed("POST", ["orgs"])).toBe(false);
    expect(isAllowed("DELETE", ["orgs"])).toBe(false);
    expect(isAllowed("GET", ["docs"])).toBe(false);
    expect(isAllowed("GET", ["openapi.json"])).toBe(false);
    expect(isAllowed("GET", ["runs", "..", "orgs"])).toBe(false);
  });

  it("refuses a path off the allowlist without calling the backend", async () => {
    const f = upstream("{}");
    const res = await forward(new Request("http://web/api/r/docs"), ["docs"], { fetchImpl: f, env: ENV });
    expect(res.status).toBe(404);
    expect(f).not.toHaveBeenCalled();
  });

  it("forwards POST bodies, 429 and Retry-After", async () => {
    const f = upstream(JSON.stringify({ detail: "busy" }), {
      status: 429,
      headers: { "content-type": "application/json", "retry-after": "30" },
    });
    const req = new Request("http://web/api/r/runs", { method: "POST", body: JSON.stringify({ org: "org_a" }) });
    const res = await forward(req, ["runs"], { fetchImpl: f, env: ENV });
    expect(f.mock.calls[0][1]!.body).toBe('{"org":"org_a"}');
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("30");
  });

  it("says so when the backend is down or the key is missing", async () => {
    const down = vi.fn(async () => {
      throw new TypeError("fetch failed");
    });
    const res = await forward(new Request("http://web/api/r/orgs"), ["orgs"], { fetchImpl: down, env: ENV });
    expect(res.status).toBe(502);
    const nokey = await forward(new Request("http://web/api/r/orgs"), ["orgs"], {
      fetchImpl: upstream("{}"),
      env: { REACHABLE_API_URL: "http://b" } as unknown as NodeJS.ProcessEnv,
    });
    expect(nokey.status).toBe(500);
  });

  it("is what the route handler serves (GET and POST)", async () => {
    const real = globalThis.fetch;
    process.env.REACHABLE_API_KEY = KEY;
    process.env.REACHABLE_API_URL = "http://backend:8001";
    const f = upstream("{}", { headers: { "content-type": "application/json" } });
    globalThis.fetch = f as unknown as typeof fetch;
    try {
      const ctx = { params: Promise.resolve({ path: ["orgs", "org_a", "drift"] }) };
      const res = await GET(new Request("http://web/api/r/orgs/org_a/drift") as never, ctx);
      expect(res.status).toBe(200);
      const ctx2 = { params: Promise.resolve({ path: ["orgs", "org_a", "ask"] }) };
      await POST(new Request("http://web/api/r/orgs/org_a/ask", { method: "POST", body: "{}" }) as never, ctx2);
      expect(f).toHaveBeenCalledTimes(2);
      expect(new Headers(f.mock.calls[1][1]!.headers).get("x-api-key")).toBe(KEY);
    } finally {
      globalThis.fetch = real;
    }
  });
});
