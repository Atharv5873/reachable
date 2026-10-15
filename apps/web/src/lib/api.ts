"use client";

import { useCallback, useEffect, useState } from "react";

/** Everything the browser asks goes to our own origin, /api/r/<path>; the
 *  Next route handler adds the API key server-side (lib/server/backend.ts). */
export const API = "/api/r";

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public retryAfter?: number,
  ) {
    super(message);
  }
}

export function path(...parts: string[]): string {
  return parts.map(encodeURIComponent).join("/");
}

export async function api<T>(p: string, init?: RequestInit & { json?: unknown }): Promise<T> {
  const { json, ...rest } = init ?? {};
  let res: Response;
  try {
    res = await fetch(`${API}/${p}`, {
      ...rest,
      method: json !== undefined ? "POST" : rest.method,
      headers: json !== undefined ? { "Content-Type": "application/json" } : rest.headers,
      body: json !== undefined ? JSON.stringify(json) : rest.body,
      cache: "no-store",
    });
  } catch {
    throw new ApiError("Cannot reach the web server.", 0);
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      const d = body?.detail;
      msg = typeof d === "string" ? d : d ? JSON.stringify(d) : msg;
    } catch {
      /* not JSON */
    }
    const ra = Number(res.headers.get("retry-after"));
    throw new ApiError(msg, res.status, Number.isFinite(ra) && ra > 0 ? ra : undefined);
  }
  return res.json() as Promise<T>;
}

// A tiny stale-while-revalidate cache: navigating between screens of the
// same run shows the last answer at once and refreshes it behind.
const cache = new Map<string, unknown>();

export type Loadable<T> = {
  data: T | undefined;
  error: ApiError | undefined;
  loading: boolean;
  reload: () => void;
};

export function useApi<T>(p: string | null): Loadable<T> {
  const [state, setState] = useState<{ key: string | null; data?: T; error?: ApiError }>(() => ({
    key: p,
    data: p ? (cache.get(p) as T | undefined) : undefined,
  }));
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!p) return;
    let cancelled = false;
    api<T>(p)
      .then((data) => {
        cache.set(p, data);
        if (!cancelled) setState({ key: p, data });
      })
      .catch((error: ApiError) => {
        if (!cancelled) setState((s) => ({ key: p, data: s.key === p ? s.data : undefined, error }));
      });
    return () => {
      cancelled = true;
    };
  }, [p, tick]);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  const current = state.key === p;
  const data = current ? state.data : p ? (cache.get(p) as T | undefined) : undefined;
  const error = current ? state.error : undefined;
  return { data, error, loading: !!p && data === undefined && !error, reload };
}

export function invalidate(prefix: string) {
  for (const k of cache.keys()) if (k.startsWith(prefix)) cache.delete(k);
}
