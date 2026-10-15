"use client";

import { AlertTriangle, CircleSlash, RotateCw } from "lucide-react";

import type { ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Loading, empty and error states, the same everywhere. A screen never shows
 *  a blank area or a stack trace: it says what is missing and what to do. */

export function Shimmer({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "animate-pulse rounded-md bg-[linear-gradient(90deg,var(--panel-2),var(--raised),var(--panel-2))]",
        className,
      )}
    />
  );
}

export function LoadingRows({ rows = 6, label }: { rows?: number; label?: string }) {
  return (
    <div className="space-y-2 p-4" aria-busy="true" aria-label={label ?? "Loading"}>
      {label && <p className="eyebrow mb-3">{label}</p>}
      {Array.from({ length: rows }).map((_, i) => (
        <Shimmer key={i} className="h-10" />
      ))}
    </div>
  );
}

export function EmptyState({
  title,
  children,
  action,
  className,
}: {
  title: string;
  children?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 px-6 py-16 text-center",
        className,
      )}
    >
      <CircleSlash className="size-6 text-fg-3" aria-hidden />
      <p className="text-base font-medium text-fg">{title}</p>
      {children && <div className="max-w-md text-sm text-fg-2">{children}</div>}
      {action}
    </div>
  );
}

export function ErrorState({
  error,
  retry,
  what,
  className,
}: {
  error: ApiError | Error;
  retry?: () => void;
  what?: string;
  className?: string;
}) {
  const status = "status" in error ? (error as ApiError).status : undefined;
  const down = status === 502 || status === 0 || status === 503;
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center justify-center gap-3 px-6 py-14 text-center",
        className,
      )}
    >
      <AlertTriangle className="size-6 text-fg-2" aria-hidden />
      <p className="text-base font-medium">
        {down ? "The Reachable backend is not answering" : `Could not load ${what ?? "this"}`}
      </p>
      <p className="max-w-lg text-sm text-fg-2">
        {down ? (
          <>
            Start it with <code className="mono text-fg">make up</code> (or{" "}
            <code className="mono text-fg">make api</code>). Nothing here needs a model: replay mode
            reads finished runs from the graph.
          </>
        ) : (
          error.message
        )}
      </p>
      {retry && (
        <button
          onClick={retry}
          className="mt-1 inline-flex items-center gap-2 rounded-md border border-line-2 px-3 py-1.5 text-sm text-fg hover:bg-raised"
        >
          <RotateCw className="size-3.5" /> Retry
        </button>
      )}
    </div>
  );
}
