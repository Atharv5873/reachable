"use client";

import type cytoscapeT from "cytoscape";
import type { Core, ElementDefinition, EdgeSingular, EventObject, NodeSingular, StylesheetJson } from "cytoscape";
import { useEffect, useMemo, useRef, useState } from "react";

import type { GEdge, GNode, Subgraph } from "@/lib/types";
import { cn } from "@/lib/utils";

/**
 * The attack graph. Cytoscape draws, dagre lays it out left to right (the
 * Internet on the left, crown jewels on the right: an attack graph is
 * DAG-ish, so a layered layout reads like a sentence), and we animate it in
 * hop by hop so the viewer watches the attacker advance.
 *
 * Colour follows the app's one rule: ember = an attacker can get there.
 * Edges of the selected fix set are white and dashed (the scissors). After a
 * simulated fix, cut edges fade, the paths go grey and the crown jewel turns
 * "safe".
 */

const C = {
  bg: "#0a0c0f",
  node: "#151920",
  nodeLine: "#2c333d",
  fg: "#e8ebef",
  fg2: "#a7afbb",
  fg3: "#6f7885",
  line: "#2a313a",
  ember: "#ff5533",
  ember2: "#ff8a6e",
  emberFill: "#2a1611",
  safe: "#6fd3a8",
  safeFill: "#10261d",
  cut: "#f4f6f8",
};

// Hard ceiling on what we ask the browser to draw, whatever the API sends.
export const CLIENT_MAX_NODES = 150;

let registered: Promise<typeof cytoscapeT> | null = null;
function loadCytoscape() {
  registered ??= Promise.all([import("cytoscape"), import("cytoscape-dagre")]).then(
    ([cy, dagre]) => {
      cy.default.use(dagre.default);
      return cy.default;
    },
  );
  return registered;
}

const KIND_SHAPE: Record<string, string> = {
  internet: "hexagon",
  asset: "round-rectangle",
  identity: "ellipse",
  secret: "diamond",
  datastore: "barrel",
};

function stylesheet(font: string): StylesheetJson {
  return [
    {
      selector: "node",
      style: {
        shape: (n: NodeSingular) => KIND_SHAPE[n.data("kind")] ?? "round-rectangle",
        width: 30,
        height: 30,
        "background-color": C.node,
        "border-width": 1.5,
        "border-color": C.nodeLine,
        label: "data(label)",
        "font-family": font,
        "font-size": 12,
        color: C.fg2,
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 7,
        "text-wrap": "wrap",
        "text-max-width": "130px",
        "text-background-color": C.bg,
        "text-background-opacity": 0.85,
        "text-background-padding": "2px",
        "overlay-opacity": 0,
        "transition-property": "background-color, border-color, border-width, opacity",
        "transition-duration": 0.35,
      } as never,
    },
    { selector: "node[kind = 'asset']", style: { width: 40, height: 28 } },
    { selector: "node[kind = 'secret']", style: { width: 26, height: 26 } },
    { selector: "node[kind = 'identity']", style: { width: 30, height: 26 } },
    {
      selector: "node[kind = 'internet']",
      style: { width: 44, height: 40, "border-color": C.fg, "border-width": 2, color: C.fg, "font-weight": 600 },
    },
    {
      selector: "node[kind = 'datastore']",
      style: { width: 44, height: 40 },
    },
    {
      selector: "node.onpath",
      style: { "border-color": C.ember, "border-width": 2, color: C.fg },
    },
    { selector: "node.hot", style: { "background-color": C.emberFill, "border-width": 3 } },
    {
      selector: "node.crown",
      style: {
        width: 56,
        height: 50,
        "background-color": C.ember,
        "border-color": C.ember2,
        "border-width": 3,
        color: C.fg,
        "font-size": 14,
        "font-weight": 600,
      },
    },
    {
      selector: "node.crown.safe",
      style: { "background-color": C.safeFill, "border-color": C.safe, color: C.safe },
    },
    {
      selector: "node.hub",
      style: { "border-width": 4, "border-color": C.cut, "underlay-color": C.cut, "underlay-opacity": 0.12, "underlay-padding": 9 } as never,
    },
    { selector: "node.context", style: { opacity: 0.5, "border-style": "dashed" } },
    { selector: "node.dim", style: { opacity: 0.22 } },
    {
      selector: "node.isnew",
      style: { "border-color": C.ember, "border-width": 3, "border-style": "double" } as never,
    },
    {
      selector: "node.focus",
      style: { "underlay-color": C.fg, "underlay-opacity": 0.14, "underlay-padding": 10 } as never,
    },
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": C.line,
        "target-arrow-color": C.line,
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.9,
        "curve-style": "bezier",
        label: "data(label)",
        "font-family": font,
        "font-size": 11,
        color: C.fg3,
        "text-background-color": C.bg,
        "text-background-opacity": 1,
        "text-background-padding": "2px",
        "text-rotation": "none",
        "overlay-opacity": 0,
        "transition-property": "line-color, target-arrow-color, width, opacity",
        "transition-duration": 0.35,
      } as never,
    },
    {
      selector: "edge.onpath",
      style: {
        width: (e: EdgeSingular) => 1.8 + Math.min(4, (e.data("shared") || 1) - 1) * 1.1,
        "line-color": C.ember,
        "target-arrow-color": C.ember,
        color: C.fg2,
      } as never,
    },
    { selector: "edge.hot", style: { width: 4, color: C.fg } },
    { selector: "edge.nolabel", style: { label: "" } },
    { selector: "edge.flow", style: { "line-style": "dashed", "line-dash-pattern": [9, 5] } as never },
    {
      selector: "edge.cut",
      style: {
        width: 4,
        "line-color": C.cut,
        "target-arrow-color": C.cut,
        "line-style": "dashed",
        "line-dash-pattern": [6, 4],
        color: C.fg,
        "font-weight": 600,
      } as never,
    },
    {
      selector: "edge.severed",
      style: { opacity: 0.25, "line-color": C.fg3, "target-arrow-color": C.fg3, width: 1.5 },
    },
    {
      selector: "edge.cleared",
      style: { "line-color": "#3a434f", "target-arrow-color": "#3a434f", width: 1.5, "line-style": "solid" },
    },
    { selector: "edge.context", style: { opacity: 0.45, width: 1 } },
    { selector: "edge.dim", style: { opacity: 0.12 } },
    { selector: "edge.isnew", style: { "line-color": C.ember, "target-arrow-color": C.ember, width: 4 } },
    {
      selector: "edge.selected",
      style: { width: 6, "line-color": C.ember2, "target-arrow-color": C.ember2, color: C.fg, "z-index": 99 },
    },
    { selector: "node.hidden-init, edge.hidden-init", style: { opacity: 0 } },
  ];
}

export type GraphView = {
  focusPaths?: number[] | null; // highlight these, dim the rest
  cut?: "fewest" | "cheapest" | null; // draw this fix set as cut edges
  severed?: boolean; // after a simulated fix: cut edges gone, crown jewels safe
  showNew?: boolean; // drift: emphasise new steps / nodes
  hubs?: string[]; // "one fix, many paths": the shared hops to call out
  focusNode?: string | null;
  selectedEdge?: string | null;
};

function hopDepths(nodes: GNode[], edges: GEdge[]): Map<string, number> {
  const out = new Map<string, number>([["internet", 0]]);
  const adj = new Map<string, string[]>();
  for (const e of edges) adj.set(e.source, [...(adj.get(e.source) ?? []), e.target]);
  const queue = ["internet"];
  while (queue.length) {
    const u = queue.shift()!;
    for (const v of adj.get(u) ?? []) {
      if (!out.has(v)) {
        out.set(v, out.get(u)! + 1);
        queue.push(v);
      }
    }
  }
  for (const n of nodes) if (!out.has(n.id)) out.set(n.id, 1);
  return out;
}

function nodeLabel(n: GNode): string {
  if (n.kind === "internet") return "Internet";
  if (n.crown) return `${n.name}\ncrown jewel`;
  const sub = n.sub && n.sub !== n.name ? `\n${n.sub.replace(/_/g, " ")}` : "";
  const shared = n.shared > 1 ? `  ×${n.shared}` : "";
  return `${n.name}${shared}${sub}`;
}

export function AttackGraph({
  graph,
  view = {},
  animate = true,
  onEdge,
  onNode,
  className,
  testid = "attack-graph",
}: {
  graph: Subgraph;
  view?: GraphView;
  animate?: boolean;
  onEdge?: (e: GEdge) => void;
  onNode?: (n: GNode) => void;
  className?: string;
  testid?: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  // "ready" belongs to one graph: a new graph is not ready until it is drawn.
  const [readyFor, setReadyFor] = useState<unknown>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const handlers = useRef({ onEdge, onNode });
  useEffect(() => {
    handlers.current = { onEdge, onNode };
  }, [onEdge, onNode]);

  const { nodes, edges, clipped } = useMemo(() => {
    const keep = graph.nodes.slice(0, CLIENT_MAX_NODES);
    const ids = new Set(keep.map((n) => n.id));
    return {
      nodes: keep,
      edges: graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target)),
      clipped: graph.nodes.length > keep.length,
    };
  }, [graph]);
  const ready = readyFor === nodes;

  // Build (or rebuild) when the graph itself changes.
  useEffect(() => {
    let cancelled = false;
    const timers: ReturnType<typeof setTimeout>[] = [];
    loadCytoscape()
      .then((cytoscape) => {
        if (cancelled || !box.current) return;
        const font = getComputedStyle(document.body).fontFamily || "sans-serif";
        const els: ElementDefinition[] = [
          ...nodes.map((n) => ({
            group: "nodes" as const,
            data: { ...n, label: nodeLabel(n) },
          })),
          ...edges.map((e) => ({
            group: "edges" as const,
            data: { ...e, label: e.technique ?? "" },
          })),
        ];
        cyRef.current?.destroy();
        const cy = cytoscape({
          container: box.current,
          elements: els,
          style: stylesheet(font),
          minZoom: 0.25,
          maxZoom: 2.2,
          wheelSensitivity: 0.25,
          boxSelectionEnabled: false,
          autoungrabify: false,
        });
        cyRef.current = cy;
        cy.layout({
          name: "dagre",
          rankDir: "LR",
          nodeSep: 44,
          rankSep: 130,
          edgeSep: 14,
          ranker: "network-simplex",
          fit: true,
          padding: 36,
        } as never).run();
        if (cy.zoom() > 1.35) {
          cy.zoom(1.35);
          cy.center();
        }
        cy.on("tap", "edge", (ev: EventObject) => handlers.current.onEdge?.(ev.target.data() as GEdge));
        cy.on("tap", "node", (ev: EventObject) => handlers.current.onNode?.(ev.target.data() as GNode));
        cy.on("mouseover", "edge, node", () => box.current && (box.current.style.cursor = "pointer"));
        cy.on("mouseout", "edge, node", () => box.current && (box.current.style.cursor = "default"));

        const depth = hopDepths(nodes, edges);
        const max = Math.max(0, ...depth.values());
        const big = nodes.length > 80;
        if (animate && !big && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
          // Draw the attack advancing: hop 0 (the Internet), then each hop's
          // edges and the nodes they reach.
          cy.elements().addClass("hidden-init");
          const STEP = 230;
          for (let d = 0; d <= max; d++) {
            timers.push(
              setTimeout(() => {
                if (cancelled) return;
                cy.batch(() => {
                  cy.edges()
                    .filter((e: EdgeSingular) => depth.get(e.data("target")) === d || (depth.get(e.data("source")) === d - 1 && depth.get(e.data("target"))! <= d))
                    .removeClass("hidden-init");
                  cy.nodes()
                    .filter((n: NodeSingular) => depth.get(n.id()) === d)
                    .removeClass("hidden-init");
                });
              }, 120 + d * STEP),
            );
          }
          timers.push(
            setTimeout(() => {
              if (cancelled) return;
              cy.elements().removeClass("hidden-init");
              setReadyFor(nodes);
            }, 160 + (max + 1) * STEP),
          );
        } else {
          setReadyFor(nodes);
        }
      })
      .catch((err) => !cancelled && setFailed(String(err)));
    return () => {
      cancelled = true;
      timers.forEach(clearTimeout);
    };
  }, [nodes, edges, animate]);

  useEffect(
    () => () => {
      cyRef.current?.destroy();
      cyRef.current = null;
    },
    [],
  );

  // Apply the view (focus, cut, severed, new) without re-laying out.
  const { focusPaths, cut, severed, showNew, hubs, focusNode, selectedEdge } = view;
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const focus = focusPaths && focusPaths.length ? new Set(focusPaths) : null;
    const hubSet = new Set(hubs ?? []);
    cy.batch(() => {
      cy.elements().removeClass("onpath hot nolabel flow cut severed cleared context dim isnew hub focus selected safe crown");
      // Many identical Internet -> host labels (T1190) are noise when every path
      // is shown; a focused path keeps all of its labels.
      const crowded = !focus && cy.edges().length > 20;
      cy.nodes().forEach((n) => {
        const d = n.data() as GNode;
        const inFocus = !focus || d.paths.some((p) => focus.has(p));
        if (d.context) n.addClass("context");
        else if (inFocus && d.paths.length && !severed) n.addClass(focus ? "onpath hot" : "onpath");
        if (focus && !inFocus && !d.context && d.kind !== "internet" && !d.crown) n.addClass("dim");
        if (d.crown) n.addClass("crown");
        if (d.crown && severed) n.addClass("safe");
        if (showNew && d.new) n.addClass("isnew");
        if (hubSet.has(d.id)) n.addClass("hub");
        if (focusNode && d.id === focusNode) n.addClass("focus");
      });
      cy.edges().forEach((e) => {
        const d = e.data() as GEdge;
        const inFocus = !focus || d.paths.some((p) => focus.has(p));
        if (d.context) e.addClass("context");
        else if (inFocus && d.paths.length) {
          e.addClass(focus ? "onpath hot" : "onpath");
          if (!cut && !severed && !showNew) e.addClass("flow");
        }
        if (focus && !inFocus && !d.context) e.addClass("dim nolabel");
        if (crowded && d.source === "internet") e.addClass("nolabel");
        const isCut = cut === "fewest" ? d.in_fewest : cut === "cheapest" ? d.in_cheapest : false;
        if (isCut) e.addClass(severed ? "severed" : "cut");
        else if (severed && d.paths.length) e.addClass("cleared");
        if (showNew && d.new) e.addClass("isnew");
        if (selectedEdge && d.id === selectedEdge) e.addClass("selected");
      });
    });
  }, [ready, focusPaths, cut, severed, showNew, hubs, focusNode, selectedEdge]);

  // Marching dashes along the attack path: the direction of travel, at a glance.
  useEffect(() => {
    if (!ready || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    let raf = 0;
    let off = 0;
    const tick = () => {
      const cy = cyRef.current;
      if (cy) {
        off = (off - 0.6) % 1000;
        cy.edges(".flow").style("line-dash-offset", off);
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [ready]);

  const fit = () => cyRef.current?.animate({ fit: { eles: cyRef.current.elements(), padding: 36 } } as never, { duration: 300 });

  return (
    <div className={cn("relative h-full min-h-[320px] w-full", className)}>
      {/* Cytoscape forces position: relative on its container, so the
          container is a full-size child of an absolutely placed box. */}
      <div className="absolute inset-0">
      <div
        ref={box}
        data-testid={testid}
        data-ready={ready ? "1" : "0"}
        data-nodes={nodes.length}
        data-edges={edges.length}
        data-cut={cut ?? ""}
        data-severed={severed ? "1" : "0"}
        className="h-full w-full"
      />
      </div>
      {failed && (
        <div className="absolute inset-0 grid place-items-center text-sm text-fg-2">
          The graph could not be drawn: {failed}
        </div>
      )}
      <div className="pointer-events-none absolute right-3 bottom-3 flex items-center gap-2">
        {(clipped || graph.truncated) && (
          <span className="pointer-events-auto rounded-md border border-line bg-panel/90 px-2 py-1 text-2xs text-fg-2">
            Showing {graph.paths.length} of {graph.total_paths} paths (capped at {graph.caps.max_nodes} nodes)
          </span>
        )}
        <button
          onClick={fit}
          className="pointer-events-auto rounded-md border border-line bg-panel/90 px-2 py-1 text-2xs text-fg-2 hover:text-fg"
        >
          Fit
        </button>
      </div>
    </div>
  );
}

export function GraphLegend({ cut, severed, showNew }: { cut?: boolean; severed?: boolean; showNew?: boolean }) {
  const item = (swatch: React.ReactNode, label: string) => (
    <span className="flex items-center gap-1.5">
      {swatch}
      {label}
    </span>
  );
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-2xs text-fg-3">
      {item(<span className="h-[3px] w-5 rounded bg-ember" />, "attack step")}
      {cut && item(<span className="h-[3px] w-5 border-t-[3px] border-dashed border-cut" />, "cut by the fix set")}
      {severed && item(<span className="size-2.5 rounded-full border-2 border-safe" />, "safe after the fix")}
      {showNew && item(<span className="h-[3px] w-5 rounded bg-ember ring-1 ring-ember-2" />, "new since v1")}
      {item(<span className="size-2.5 rotate-45 border border-fg-3" />, "secret")}
      {item(<span className="h-2.5 w-3.5 rounded-sm border border-fg-3" />, "asset")}
      {item(<span className="h-2.5 w-3.5 rounded-full border border-fg-3" />, "identity")}
      {item(<span className="size-2.5 rounded-sm bg-ember" />, "crown jewel")}
    </div>
  );
}
