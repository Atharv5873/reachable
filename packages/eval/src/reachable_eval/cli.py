"""`python -m reachable_eval {estimate,run,ablation,score}` (make eval / make ablation)."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging

from reachable_core.settings import get_settings

from . import run as R
from .report import ablation_md, build_ablation, build_comparison, comparison_md

ABL_GROUP = "ablation"


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--seeds", type=int, nargs="+", default=[1], help="provider seeds (LLM only)")
    p.add_argument("--force", action="store_true", help="re-run jobs whose raw output exists")
    p.add_argument("--max-usd", type=float, default=5.0, help="refuse to start above this")
    p.add_argument("--any-model", action="store_true", help="allow a non flash-lite model")
    p.add_argument("--dry-run", action="store_true", help="print the estimate and stop")


def _model(args) -> str:
    return get_settings().llm_primary_model if args.any_model else R.check_model()


def _gate(args, est_total: float) -> bool:
    if args.dry_run:
        print("(dry run: nothing executed)")
        return False
    if est_total > args.max_usd:
        raise SystemExit(
            f"estimate ${est_total:.2f} exceeds --max-usd {args.max_usd}: not starting"
        )
    return True


async def _run(args) -> None:
    model = _model(args)
    refs = R.scans(args.orgs, args.scans)
    jobs = R.matrix_jobs(refs, args.prioritisers, args.seeds)
    print(f"Matrix: {len(args.prioritisers)} prioritisers x {len(refs)} scans; seeds {args.seeds}")
    data, _ = await R.prepare(refs, need_rag=False)
    need_rag = "vector_rag" in args.prioritisers
    emb = R.rag_embed_estimate(refs, data) if need_rag else None
    if args.force:
        for j in jobs:
            R.raw_path(*j).unlink(missing_ok=True)
    if not _gate(args, R.print_estimate(R.estimate(jobs), emb)):
        return
    _, build = await R.prepare(refs, need_rag=need_rag)
    raws = await R.run_jobs(jobs, data, force=False)
    R.confirm_matrix_runs(raws, data)
    if need_rag:
        R.write_json(R.RAW / "rag_build.json", build)
    _score(seeds=args.seeds, model=model)


def _score(seeds=None, model=None) -> None:
    raws = R.load_raws()
    if not raws:
        raise SystemExit("no raw outputs under evals/results/raw/: run `make eval` first")
    scored = R.score_all(raws)
    build_path = R.RAW / "rag_build.json"
    model = model or next((r["meta"].get("model") for r in raws if r["meta"].get("model")), "?")
    abl = R.load_raws(ABL_GROUP)
    abl_doc = _score_ablation(abl, model=model) if abl else None
    doc = build_comparison(
        scored,
        model=model,
        seeds=seeds or sorted({r["seed"] for r in raws if r["seed"]}),
        dataset_seed=get_settings().seed,
        rag_build=json.loads(build_path.read_text("utf-8")) if build_path.exists() else {},
        runs=len(raws),
        ablation=abl_doc
        and {k: abl_doc[k] for k in ("org", "scan", "seeds", "graph_on", "graph_off", "drop")},
    )
    R.write_json(R.RESULTS / "comparison.json", doc)
    (R.RESULTS / "comparison.md").write_text(comparison_md(doc), encoding="utf-8")
    print(f"wrote {R.RESULTS / 'comparison.json'} and comparison.md ({len(raws)} runs)")


def _score_ablation(raws: list[dict], *, model: str) -> dict:
    doc = build_ablation(R.score_all(raws), model=model, seeds=sorted({r["seed"] for r in raws}))
    R.write_json(R.RESULTS / "ablation.json", doc)
    (R.RESULTS / "ablation.md").write_text(ablation_md(doc), encoding="utf-8")
    d = doc["drop"]
    print(
        f"ablation {doc['org']} {doc['scan']}: path recall@10 drop {d['path_recall@10']:+.2f}, "
        f"NDCG@10 drop {d['ndcg@10']:+.2f} -> evals/results/ablation.md"
    )
    return doc


async def _ablation(args) -> None:
    model = _model(args)
    ref = R.ScanRef.of(args.org, args.scan)
    jobs = [(p, ref, s) for p in R.ABLATION for s in args.seeds]
    data, _ = await R.prepare([ref], need_rag=False)
    if args.force:
        for j in jobs:
            R.raw_path(*j, group=ABL_GROUP).unlink(missing_ok=True)
    if not _gate(args, R.print_estimate(R.estimate(jobs, group=ABL_GROUP), None)):
        return
    raws = await R.run_jobs(jobs, data, force=False, group=ABL_GROUP)
    R.confirm_matrix_runs(raws, data)
    _score_ablation(raws, model=model)


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    # Gemini 3 + temperature: a DeprecationWarning on every call (we keep temperature 0).
    logging.getLogger("LiteLLM").setLevel(logging.ERROR)
    s = get_settings()
    p = argparse.ArgumentParser(prog="reachable_eval")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="the comparison matrix -> comparison.json/.md")
    _common(r)
    r.add_argument("--orgs", nargs="+", default=list(s.orgs))
    r.add_argument("--scans", nargs="+", default=["v1", "v2"])
    r.add_argument("--prioritisers", nargs="+", default=list(R.ALL), choices=list(R.ALL))
    a = sub.add_parser("ablation", help="reachable with graph tools on vs off -> ablation.*")
    _common(a)
    a.add_argument("--org", default="org_a")
    a.add_argument("--scan", default="v1")
    sub.add_parser("score", help="recompute every table from evals/results/raw/")
    args = p.parse_args(argv)
    if args.cmd == "run":
        asyncio.run(_run(args))
    elif args.cmd == "ablation":
        asyncio.run(_ablation(args))
    else:
        _score()
