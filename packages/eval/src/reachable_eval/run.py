"""The matrix: every prioritiser on every scan; raw outputs on disk; then scores.

    python -m reachable_eval run        [--seeds 1 2 3] [--orgs ...] [--scans v1 v2]
    python -m reachable_eval ablation   [--org org_a --scan v1 --seeds 1 2 3]
    python -m reachable_eval score      (recompute every table from the raw files)

Raw outputs: evals/results/raw/<prioritiser>/<graph>_s<seed>.json, one per run:
the top 100 of the order, the fix set, the model's own picks and one-line whys,
ids it named that are not open findings, cost, and the tool-call log. The
scores are recomputed from these files plus labels.json alone (`score`), so a
skeptic can rerun the metrics without a model, a key or a database.

A run whose raw file exists is not run again (`--force` to redo it): within a
matrix run that is the cache, and an interrupted matrix resumes where it
stopped. Deterministic prioritisers run once per scan (seed 0).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path

import litellm

from reachable_core.settings import REPO_ROOT, get_settings

from .agent import MAX_LLM_CALLS, eval_llm
from .base import HEAD_KEEP, Ranking, SeveritySort, SmartScore
from .reachable import reachable
from .scoring import load_truth, score_raw
from .sql_agent import sql_agent
from .store import ScanData, ScanRef, ensure_eval_views, load_scan
from .vector_rag import EMBED_MODEL, Embedder, build_docs, ensure_index, vector_rag

log = logging.getLogger("reachable.eval")
RESULTS = REPO_ROOT / "evals" / "results"
RAW = RESULTS / "raw"
DETERMINISTIC = ("severity_sort", "smart_score")
LLM_PRIORITISERS = ("vector_rag", "sql_agent", "reachable")
ALL = DETERMINISTIC + LLM_PRIORITISERS
ABLATION = ("reachable", "reachable_graph_off")
CONCURRENCY = 4

# Per-run spend assumed before any run of that prioritiser exists (then the
# measured mean of the raw files replaces it).
PRIOR_TOKENS = {"in": 45_000, "out": 3_000}


def make(name: str):
    return {
        "severity_sort": SeveritySort,
        "smart_score": SmartScore,
        "vector_rag": vector_rag,
        "sql_agent": sql_agent,
        "reachable": reachable,
        "reachable_graph_off": lambda: reachable(graph_off=True),
    }[name]()


def raw_path(prioritiser: str, ref: ScanRef, seed: int, *, group: str | None = None) -> Path:
    return RAW / (group or prioritiser) / f"{ref.graph}_{prioritiser}_s{seed}.json"


def to_raw(r: Ranking, data: ScanData, seed: int) -> dict:
    return {
        "prioritiser": r.prioritiser,
        "org": data.ref.org,
        "scan": data.ref.scan,
        "graph": data.ref.graph,
        "seed": seed,
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "universe": {"open_findings": len(data.universe), "sha": data.universe_hash()},
        "head": r.order[:HEAD_KEEP],
        "named": r.head[:HEAD_KEEP],
        "tail_rule": r.tail_rule,
        "fix_set": r.fix_set,
        "why": r.why,
        "invalid_ids": r.invalid_ids,
        "reasoning": r.reasoning,
        "meta": r.meta,
        "tool_log": r.tool_log,
    }


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str) + "\n", encoding="utf-8")


def scans(orgs: list[str], scan_names: list[str]) -> list[ScanRef]:
    return [ScanRef.of(o, s) for s in scan_names for o in orgs]


# ------------------------------------------------------------------- prepare
async def prepare(refs: list[ScanRef], need_rag: bool) -> tuple[dict[str, ScanData], dict]:
    """Eval views, scan data, and (if vector_rag runs) every RAG index, built
    one scan at a time so parallel runs never race on an index."""
    data: dict[str, ScanData] = {}
    build = {"embed_calls": 0, "embed_tokens": 0, "embed_usd": 0.0, "docs": 0}
    emb = Embedder() if need_rag else None
    for ref in refs:
        await asyncio.to_thread(ensure_eval_views, ref.graph)
        data[ref.key] = await asyncio.to_thread(load_scan, ref)
        if emb:
            info = await ensure_index(data[ref.key], emb)
            build["docs"] += info["docs"]
            print(f"  rag index {ref.graph}: {info['docs']} docs, rebuilt={info['rebuilt']}")
    if emb:
        build.update(
            embed_calls=emb.calls, embed_tokens=emb.tokens, embed_usd=emb.usd(), cached=emb.cached
        )
    return data, build


# ------------------------------------------------------------------ estimate
def measured_tokens(prioritiser: str) -> dict | None:
    files = list(RAW.rglob(f"*_{prioritiser}_s*.json")) if RAW.exists() else []
    metas = [json.loads(f.read_text("utf-8"))["meta"] for f in files]
    metas = [m for m in metas if m.get("llm_calls")]
    if not metas:
        return None
    return {
        "in": sum(m["tokens_in"] for m in metas) / len(metas),
        "out": sum(m["tokens_out"] for m in metas) / len(metas),
        "n": len(metas),
    }


def estimate(jobs: list[tuple[str, ScanRef, int]], *, group: str | None = None) -> dict:
    """Spend for the jobs not already on disk, before anything runs."""
    model = get_settings().llm_primary_model
    rows, total = [], 0.0
    names = ALL + ABLATION[1:]
    for p in sorted({j[0] for j in jobs}, key=names.index):
        if p in DETERMINISTIC:
            continue
        todo = [j for j in jobs if j[0] == p and not raw_path(*j[:3], group=group).exists()]
        m = (
            measured_tokens(p)
            or measured_tokens(p.replace("_graph_off", ""))
            or {**PRIOR_TOKENS, "n": 0}
        )
        i, o = litellm.cost_per_token(
            model=model, prompt_tokens=int(m["in"]), completion_tokens=int(m["out"])
        )
        cost = (i + o) * len(todo)
        total += cost
        rows.append(
            {
                "prioritiser": p,
                "runs": len(todo),
                "tokens_in_per_run": int(m["in"]),
                "tokens_out_per_run": int(m["out"]),
                "basis": f"measured over {m['n']} run(s)" if m["n"] else "prior assumption",
                "usd": round(cost, 4),
            }
        )
    worst = litellm.cost_per_token(
        model=model, prompt_tokens=PRIOR_TOKENS["in"] * 2, completion_tokens=4096 * MAX_LLM_CALLS
    )
    return {"model": model, "rows": rows, "usd": round(total, 4), "worst_case_run_usd": sum(worst)}


def rag_embed_estimate(refs: list[ScanRef], data: dict[str, ScanData]) -> dict:
    """Uncached documents to embed for the indexes (chars / 4 ~ tokens)."""
    emb = Embedder()
    todo_chars = 0
    for ref in refs:
        docs = build_docs(data[ref.key])
        shas = [hashlib.sha256(f"passage:{t}".encode()).hexdigest() for _, _, t in docs]
        have = emb.cache.get(shas)
        todo_chars += sum(len(t) for (_, _, t), h in zip(docs, shas, strict=True) if h not in have)
    tokens = todo_chars // 4
    return {"model": f"{EMBED_MODEL} (local)", "tokens": tokens, "usd": 0.0}


def print_estimate(est: dict, emb: dict | None) -> float:
    print(f"\nCost estimate (model {est['model']}, LiteLLM prices):")
    for r in est["rows"]:
        print(
            f"  {r['prioritiser']:<22} {r['runs']:>3} run(s) x ~{r['tokens_in_per_run']:,} in / "
            f"~{r['tokens_out_per_run']:,} out ({r['basis']}) = ${r['usd']:.4f}"
        )
    total = est["usd"]
    if emb:
        print(f"  embeddings ({emb['model']}): ~{emb['tokens']:,} tokens = ${emb['usd']:.4f}")
        total += emb["usd"]
    print(f"  TOTAL ~${total:.4f}  (one run's hard ceiling ~${est['worst_case_run_usd']:.3f})\n")
    return total


# ----------------------------------------------------------------------- run
async def run_jobs(
    jobs: list[tuple[str, ScanRef, int]], data: dict[str, ScanData], *, force: bool, group=None
) -> list[dict]:
    sem = asyncio.Semaphore(CONCURRENCY)
    out: list[dict] = []

    async def one(p: str, ref: ScanRef, seed: int) -> None:
        path = raw_path(p, ref, seed, group=group)
        if path.exists() and not force:
            out.append(json.loads(path.read_text("utf-8")))
            return
        async with sem:
            t = time.perf_counter()
            r = await make(p).rank(data[ref.key], seed=seed)
            r.meta.setdefault("wall_s", round(time.perf_counter() - t, 2))
            raw = to_raw(r, data[ref.key], seed)
            write_json(path, raw)
            out.append(raw)
            m = r.meta
            print(
                f"  {p:<20} {ref.graph:<9} s{seed}: named {len(r.head):>3}, "
                f"llm {m.get('llm_calls', 0)}, tools {m.get('tool_calls', 0)}, "
                f"tokens {m.get('tokens_in', 0):,}+{m.get('tokens_out', 0):,}, "
                f"{m.get('wall_s')} s, stop={m.get('stop', '-')}"
            )

    # One failed job must not cancel the others (their spend is already made).
    results = await asyncio.gather(*(one(*j) for j in jobs), return_exceptions=True)
    failed = [(j, r) for j, r in zip(jobs, results, strict=True) if isinstance(r, BaseException)]
    for (p, ref, seed), exc in failed:
        print(f"  FAILED {p} {ref.graph} s{seed}: {type(exc).__name__}: {str(exc)[:300]}")
    if failed:
        raise SystemExit(f"{len(failed)} job(s) failed; rerun to retry only those (raw files kept)")
    return out


def matrix_jobs(refs: list[ScanRef], prioritisers: list[str], seeds: list[int]) -> list:
    jobs = []
    for p in prioritisers:
        for ref in refs:
            for seed in [0] if p in DETERMINISTIC else seeds:
                jobs.append((p, ref, seed))
    return jobs


def check_model() -> str:
    s = get_settings()
    model = s.llm_primary_model
    if "flash-lite" not in model:
        raise SystemExit(
            f"LLM_PRIMARY_MODEL is {model!r}: the S7 eval runs on a flash-lite model "
            "(set LLM_PRIMARY_MODEL or pass --any-model)"
        )
    eval_llm(1)  # a primary deployment exists (else LLMUnavailable)
    return model


def confirm_matrix_runs(raws: list[dict], data: dict[str, ScanData]) -> None:
    """Every raw output was ranked over exactly its scan's open findings."""
    for r in raws:
        d = data.get(r["graph"])
        if d and r["universe"]["sha"] != d.universe_hash():
            raise SystemExit(
                f"{r['prioritiser']} {r['graph']} s{r['seed']}: ranked over a different finding "
                "set than the current scan (re-seeded since?). Re-run with --force."
            )


def load_raws(group: str | None = None) -> list[dict]:
    """The matrix's raw outputs (group None: every prioritiser's folder except
    the ablation's), or one group's."""
    if not RAW.exists():
        return []
    if group:
        files = sorted((RAW / group).glob("*.json"))
    else:
        files = sorted(f for f in RAW.glob("*/*.json") if f.parent.name != "ablation")
    return [json.loads(f.read_text("utf-8")) for f in files]


def score_all(raws: list[dict]) -> list[dict]:
    truths: dict[tuple[str, str], object] = {}
    out = []
    for r in raws:
        key = (r["org"], r["scan"])
        if key not in truths:
            truths[key] = load_truth(*key)
        out.append(
            {
                **{k: r[k] for k in ("prioritiser", "org", "scan", "graph", "seed")},
                "meta": r["meta"],
                "invalid_ids": r.get("invalid_ids", []),
                "score": score_raw(r, truths[key]),
            }
        )
    return out
