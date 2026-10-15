// Shapes of what the Reachable API returns (apps/api/src/reachable_api).

export type RunHead = {
  id: string;
  kind: string;
  scan: string;
  status: string;
  started?: number;
  as_of?: number;
  models?: string[] | null;
};

export type ScanInfo = {
  scan: "v1" | "v2";
  graph: string;
  info: { id: string; version: string; ts: number } | null;
  recent_runs: RunHead[];
  alerts: { id: string; summary?: string }[];
};

export type OrgInfo = { org: string; scans: ScanInfo[] };

export type RowStatus =
  | "reachable"
  | "accepted"
  | "mitigated"
  | "dead_end"
  | "internal"
  | "unreachable";

export type BoardRow = {
  finding: string;
  asset: string;
  hostname: string;
  cve: string;
  cvss: number | null;
  epss: number | null;
  kev: boolean;
  zone: string | null;
  scanner_rank: number;
  reach_rank: number | null;
  score: number | null;
  status: RowStatus;
  why: string;
  targets: string[];
  attack_steps: number;
  verdict: string | null;
  headline: "reachable" | "unreachable" | null;
};

export type Board = {
  graph: string;
  run_id: string | null;
  source: "run" | "live";
  total_open: number;
  on_crown_path: number;
  crown_jewels: { id: string; name: string }[];
  by_severity: string[];
  by_reachability: string[];
  findings: Record<string, BoardRow>;
};

export type NodeKind = "internet" | "asset" | "identity" | "secret" | "datastore";

export type GNode = {
  id: string;
  name: string;
  kind: NodeKind;
  sub: string | null;
  crown: boolean;
  paths: number[];
  shared: number;
  entry: boolean;
  new: boolean;
  context?: boolean;
};

export type GEdge = {
  id: string;
  source: string;
  target: string;
  technique: string | null;
  rule: string | null;
  likelihood: number | null;
  fix_token: string | null;
  paths: number[];
  shared: number;
  token_paths: number;
  in_fewest: boolean;
  in_cheapest: boolean;
  new: boolean;
  hop?: number;
  context?: boolean;
};

export type GPath = {
  index: number;
  target: string;
  likelihood: number;
  nodes: string[];
  steps: string[];
};

export type Subgraph = {
  graph: string;
  run_id: string;
  source: "run" | "live";
  nodes: GNode[];
  edges: GEdge[];
  paths: GPath[];
  total_paths: number;
  truncated: boolean;
  cuts: { fewest: string[]; cheapest: string[] };
  chosen: "fewest" | "cheapest" | null;
  caps: { max_nodes: number; max_edges: number; context_nodes: number };
};

export type Adr = { adr: string; title: string; approved_by: string; role?: string; date: string };

export type Fix = {
  token: string;
  kind: string;
  action: string;
  effort?: number;
  asset?: string | null;
  hostname?: string | null;
  cve?: string | null;
  cvss?: number | null;
  kev?: boolean;
  team?: { id: string; name: string } | null;
  on_call?: { name: string; role?: string; window?: string; covers_as_of?: boolean } | null;
  adrs: Adr[];
  ticket: { title: string; body: string; by: string };
  routed_by?: string | null;
  accepted_risk?: unknown;
  paths_cut: number;
};

export type FixPlan = {
  graph: string;
  run_id: string;
  mode: "fewest" | "cheapest";
  chosen: "fewest" | "cheapest" | null;
  source: "run" | "tools";
  fix_tokens: string[];
  total_effort: number;
  verified: boolean | null;
  rationale: string | null;
  fixes: Fix[];
  paths: number;
  reachable_before: string[];
};

export type SimResult = {
  summary: string;
  data: {
    fix_tokens: string[];
    unknown_tokens: string[];
    removed_steps: number;
    crown_jewels: string[];
    reachable_before: string[];
    reachable_after: string[];
    now_unreachable: string[];
    all_crown_jewels_disconnected: boolean;
    remaining_paths: { target: string; likelihood: number; nodes: { id: string; name: string }[] }[];
  };
  queries: Query[];
};

export type Query = { graph?: string; cypher: string; params?: Record<string, unknown>; ms: number };

export type EvidenceNode = { id: string; label: string; name: string; role?: string | null };

export type AskAnswer = {
  question: string;
  resolved_by: "llm" | "rules";
  intent: string | null;
  params?: Record<string, unknown>;
  entity?: { id: string; name: string; kind: string } | null;
  answer: string | null;
  summary?: string;
  data?: Record<string, unknown> & {
    decisions?: {
      adr: string;
      title: string;
      decision: string;
      date: string;
      status?: string;
      port?: number | null;
      approved_by: { id: string; name: string; role: string };
      approver_team?: { id: string; name: string };
    }[];
    exposed_ports?: number[];
    teams?: { id: string; name: string; on_call?: { name: string; role: string; window: string } }[];
    on_call?: { name: string; team_name: string; window: string; role?: string }[];
    tickets?: { ticket: string; title: string; status: string; opened: string; closed?: string; cve: string }[];
  };
  evidence?: { nodes: EvidenceNode[]; edges: { src: string; rel: string; dst: string }[] };
  queries?: Query[];
  llm?: { model: string; ms: number; tokens_in: number } | null;
  note?: string | null;
  error?: string;
  suggest?: string[];
  ms?: number;
};

export type WhyStep = {
  summary: string;
  data: {
    key: string;
    src: { id: string; labels: string[]; props: Record<string, unknown> } | null;
    dst: { id: string; labels: string[]; props: Record<string, unknown> } | null;
    rule: string;
    rule_text: string;
    technique: { id: string; name?: string; url?: string; tactics?: string[] };
    likelihood: number;
    cost: number;
    fix: { token: string; kind: string; action: string };
    because: { id: string; labels: string[]; props: Record<string, unknown> }[];
    structural_edges: { src: string; rel: string; dst: string; props: Record<string, unknown> }[];
  };
  queries: Query[];
};

// One event of a run's stream (GET /runs/{id}/stream or /events).
export type RunEvent = {
  type: string;
  seq?: number;
  agent?: string;
  ts?: number;
  tool?: string;
  by?: string;
  ok?: boolean;
  cached?: boolean;
  refused?: boolean;
  ms?: number | null;
  db_ms?: number | null;
  summary?: string | null;
  queries?: { graph?: string; cypher: string; ms: number }[];
  model?: string;
  served_by?: string;
  tokens_in?: number;
  tokens_out?: number;
  tool_calls?: string[];
  action?: string;
  detail?: unknown;
  output?: string;
  new_paths?: string[][];
  closed_paths?: string[][];
  flagged_on_arrival?: string[];
  alert?: string;
  investigate?: string[];
  carried?: string[];
  suppressed?: string[];
  rank?: number;
  target?: string;
  likelihood?: number;
  hops?: string[];
  steps?: string[];
  finding?: string;
  score?: number;
  why?: string;
  ranked_by?: string;
  chosen?: string;
  fix_tokens?: string[];
  total_effort?: number;
  verified?: boolean;
  fixes?: { token: string; action: string; team: string | null; routed_by: string | null }[];
  headline?: string;
  run_id?: string;
  status?: string;
  risk?: string;
  report?: string;
  stats?: Record<string, unknown>;
};

export type RunDump = {
  run: RunHead & { stats?: Record<string, unknown>; finished?: number; models?: string[] };
  outputs: Record<string, { id: string; agent: string; ts: number; summary: string; payload: any }>; // eslint-disable-line @typescript-eslint/no-explicit-any
  steps: Record<string, unknown>[];
  chain_ok: boolean;
  graph: string;
};
