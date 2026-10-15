"""The four agents: Triage -> Pathfinder -> Fixer -> Reporter.

Each agent is two halves:

  1. the LLM half: an AgentSpec (its MCP tools and its job) run by loop.run_agent.
     The model picks the tools and writes a JSON answer.
  2. the grounding half (`finalise_*`): turn that answer into a handoff output
     that is TRUE. Every id the model names is checked against the tool results
     the run actually got; anything it made up is dropped (and listed under
     `dropped`). Authoritative facts (is a risk acceptance live? did
     simulate_fix disconnect the crown jewel?) are read from the tool results,
     never from the model's prose. If the model gave no answer (budget hit, every
     provider down), the same code builds the output from the tool results alone.

Handoffs: each agent writes its output through MemoryRepo (Triage, PathAnalysis,
FixPlan, Report nodes on the run) and the next agent READS IT BACK from the
graph by run id. Nothing is passed in memory between agents except ids.
"""

from __future__ import annotations

from typing import Any

from reachable_graph.tools import label_of

from .loop import AgentSpec, LoopOutcome, day, run_agent
from .runtime import RunCtx

SENSITIVITY_WEIGHT = {"crown": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
MAX_INVESTIGATE = 25
MAX_RANKED = 25


def _is_finding(token: str) -> bool:
    return label_of(token) == "Finding"


def _note(outcome: LoopOutcome) -> dict:
    return {
        "llm_answered": outcome.final is not None,
        "stop": outcome.reason,
        "turns": outcome.turns,
    }


# ====================================================================== Triage
TRIAGE = AgentSpec(
    name="triage",
    tools=("triage_memory", "playbooks"),
    required=("triage_memory",),
    max_turns=3,
    role="""\
Decide which of this scan's open findings deserve attack-path investigation. CONTEXT.scan \
is the scan digest: counts by severity band, ATT&CK technique and exposure; the CANDIDATES \
(Internet-facing findings on a crown-jewel path, with detail); a count and sample of the \
other Internet-facing findings; the critical findings that enable no attack step at all; \
and the ids of findings someone already decided about (previously_decided).
1. In ONE turn, in parallel: triage_memory on the candidates, the critical no-step findings \
AND every previously_decided id; playbooks for the techniques the candidates enable.
2. A LIVE risk acceptance suppresses a finding: do not investigate it, name the acceptance. \
An EXPIRED one does NOT suppress anything. Past verdicts and patterns explain recurring \
problems.
Investigate the candidates unless a live acceptance suppresses them. Deprioritise critical \
findings that enable no attack step, and say why (high score, no way in).""",
    schema="""{"investigate": ["<finding id>", "... most urgent first"],
 "deprioritised": [{"finding": "<finding id>", "reason": "<short>"}],
 "suppressed": [{"finding": "<finding id>", "acceptance": "<risk acceptance id>"}],
 "playbooks": {"<technique id>": "<playbook id>"},
 "reasoning": "<3-6 sentences>"}""",
)


async def triage_agent(ctx: RunCtx, state: dict) -> tuple[str, str]:
    # Every triage starts from the same question, so the run asks it (one traced
    # MCP call, by="run") instead of spending an LLM turn on "call scan_findings".
    sf, _ = await ctx.preload("triage", "scan_findings", {"view": "triage", "limit": 30})
    context = {
        "org": state["org"],
        "as_of_date": day(ctx.as_of),
        "scan": scan_digest((sf or {}).get("data") or {}),
    }
    outcome = await run_agent(TRIAGE, ctx, context)
    payload = finalise_triage(ctx, outcome)
    summary = (
        f"{payload['counts'].get('open', '?')} open findings; investigate "
        f"{len(payload['investigate'])}, suppressed {len(payload['suppressed'])} (live risk "
        f"acceptance), {len(payload['expired_acceptances'])} expired acceptance(s) ignored, "
        f"deprioritised {len(payload['deprioritised'])}."
    )
    cites = (
        [f["finding"] for f in payload["investigate"]]
        + [s["finding"] for s in payload["suppressed"]]
        + [d["finding"] for d in payload["deprioritised"]]
    )
    oid = ctx.repo.write_output(
        ctx.graph,
        ctx.run_id,
        "Triage",
        agent="triage",
        payload=payload,
        summary=summary,
        as_of=ctx.as_of,
        cites=cites,
    )
    return oid, summary


def scan_digest(sf: dict) -> dict:
    """What Triage's model reads: scan_findings(view="triage") minus what it never
    uses (asset ids, flags that are true for every row)."""
    cand = ("finding", "hostname", "cve", "cvss", "kev", "techniques", "best_likelihood")
    other = sf.get("other_internet_facing") or {}
    return {
        "scan": sf.get("scan"),
        "counts": sf.get("counts"),
        "aggregates": sf.get("aggregates"),
        "crown_jewels": sf.get("crown_jewels"),
        "candidates": [{k: f.get(k) for k in cand} for f in sf.get("findings", [])],
        "other_internet_facing": {
            "count": other.get("count", 0),
            "sample": [
                {k: f.get(k) for k in ("finding", "hostname", "cvss", "best_likelihood")}
                for f in other.get("top", [])
            ],
        },
        "critical_without_attack_step": [
            {k: f.get(k) for k in ("finding", "hostname", "cve", "cvss", "kev")}
            for f in sf.get("critical_without_attack_step", [])
        ],
        "previously_decided": sf.get("previously_decided", []),
    }


def _scan_rows(sf: dict) -> dict[str, dict]:
    """Every finding row scan_findings returned, by id. The triage view lists only
    Internet-facing rows (and drops the flag), so it is set back here."""
    rows = list(sf.get("findings", [])) + list(
        (sf.get("other_internet_facing") or {}).get("top", [])
    )
    triage = sf.get("view") == "triage"
    return {
        f["finding"]: {**f, "from_internet": True} if triage else f
        for f in rows
        if isinstance(f, dict)
    }


def finalise_triage(ctx: RunCtx, outcome: LoopOutcome) -> dict:
    ans = outcome.final or {}
    sf = ctx.results_of("scan_findings")
    sf = sf[0].result["data"] if sf else {}  # the run's own (preloaded) call
    on_steps = _scan_rows(sf)
    no_step = {f["finding"]: f for f in sf.get("critical_without_attack_step", [])}

    # Memory, merged over every triage_memory call: the tool computed "live"
    # at the run's as_of, so suppression here is a fact, not the model's opinion.
    mem: dict[str, dict] = {}
    acceptances: dict[str, dict] = {}
    patterns: dict[str, dict] = {}
    for r in ctx.results_of("triage_memory"):
        d = r.result["data"]
        for f in d["findings"]:
            m = mem.setdefault(f["finding"], {**f})
            m["suppressed"] = m["suppressed"] or f["suppressed"]
        for ra in d["live_risk_acceptances"] + d["expired_risk_acceptances"]:
            acceptances[ra["id"]] = ra
        for p in d["patterns"]:
            patterns[p["id"]] = p
    suppressed = []
    for fid, m in mem.items():
        if m["suppressed"]:
            ra = acceptances.get((m["live_acceptances"] or [None])[0], {})
            suppressed.append(
                {
                    "finding": fid,
                    "acceptance": ra.get("id"),
                    "approved_by": ra.get("approver_name") or ra.get("approved_by"),
                    "expires": ra.get("expires"),
                    "expires_date": day(ra.get("expires")),
                    "reason": ra.get("reason"),
                }
            )
    sup_ids = {s["finding"] for s in suppressed}
    expired = [
        {
            "finding": fid,
            "acceptance": aid,
            "expired_date": day(acceptances.get(aid, {}).get("expires")),
        }
        for fid, m in mem.items()
        if not m["suppressed"]
        for aid in m["expired_acceptances"]
    ]

    dropped = []
    wanted = [x for x in ans.get("investigate", []) if isinstance(x, str)]
    investigate_ids = []
    for fid in wanted:
        if fid in sup_ids:
            continue
        if fid not in on_steps:
            dropped.append(fid)  # not a finding any tool showed: never investigate it
            continue
        investigate_ids.append(fid)
    if not outcome.final:  # no answer: the candidates (way in AND on a crown path)
        investigate_ids = [
            f for f, x in on_steps.items() if x.get("on_crown_path") and f not in sup_ids
        ]
    investigate_ids = list(dict.fromkeys(investigate_ids))[:MAX_INVESTIGATE]

    reasons = {
        d.get("finding"): d.get("reason")
        for d in ans.get("deprioritised", [])
        if isinstance(d, dict)
    }
    deprioritised = []
    for fid, f in no_step.items():
        if fid in sup_ids:
            continue
        default = (
            f"CVSS {f.get('cvss')}{' KEV' if f.get('kev') else ''} on {f.get('hostname')}, "
            "but it enables no attack step: no way in."
        )
        deprioritised.append({"finding": fid, "reason": reasons.get(fid) or default})
    dropped += [f for f in reasons if f not in no_step and f not in on_steps]

    playbooks = []
    for r in ctx.results_of("playbooks"):
        for p in r.result["data"]["playbooks"]:
            if p["current"]:
                playbooks.append(
                    {
                        "technique": p["technique"],
                        "id": p["current"]["id"],
                        "version": p["current"]["version"],
                    }
                )
    by_finding_patterns = {
        pid: sorted(f for f, m in mem.items() if pid in m["patterns"]) for pid in patterns
    }
    return {
        "scan": sf.get("scan"),
        "as_of": ctx.as_of,
        "counts": sf.get("counts", {}),
        "crown_jewels": sf.get("crown_jewels", []),
        "investigate": [
            {
                "finding": f,
                **{
                    k: on_steps[f].get(k)
                    for k in (
                        "asset",
                        "hostname",
                        "cve",
                        "cvss",
                        "epss",
                        "kev",
                        "techniques",
                        "on_crown_path",
                        "from_internet",
                        "best_likelihood",
                    )
                },
                "past_verdicts": mem.get(f, {}).get("verdicts", []),
            }
            for f in investigate_ids
        ],
        "suppressed": suppressed,
        "expired_acceptances": expired,
        "deprioritised": deprioritised,
        "patterns": [
            {"id": p["id"], "description": p["description"], "findings": by_finding_patterns[pid]}
            for pid, p in patterns.items()
        ],
        "playbooks": list({p["technique"]: p for p in playbooks}.values()),
        "reasoning": str(ans.get("reasoning", ""))[:2000],
        "dropped": sorted(set(dropped)),
        **_note(outcome),
    }


# ================================================================== Pathfinder
PATHFINDER = AgentSpec(
    name="pathfinder",
    tools=("why_step", "blast_radius", "attack_paths"),
    required=(),
    max_turns=2,
    role="""\
Rank the triaged findings by the real Internet -> crown-jewel attack paths. CONTEXT.paths \
already holds attack_paths (k=10) for every crown jewel; a step key reads \
rule|fix_token|from|to.
- ALL IN ONE TURN: why_step on AT MOST 3 hops, the ones that matter most (the entry \
exploit, any credential or role hop) so each claim is grounded; blast_radius on the entry \
asset of the most likely path only if it adds something. attack_paths again only for a \
source or target CONTEXT does not cover.
- Rank findings (fix_tokens that are Finding ids) by: on a path to a crown jewel, path \
likelihood, the target's sensitivity. A finding on no path does not rank, whatever its CVSS.""",
    schema="""{"ranked": [{"finding": "<finding id on a path>",
             "why": "<one sentence naming the path>"}],
 "key_steps": ["<ATTACK_STEP edge key you explained with why_step>"],
 "reasoning": "<3-6 sentences>"}""",
)


async def pathfinder_agent(ctx: RunCtx, state: dict) -> tuple[str, str]:
    triage = ctx.repo.read_output(ctx.graph, ctx.run_id, "Triage")
    tp = triage["payload"] if triage else {}
    crown = [c["id"] for c in tp.get("crown_jewels", [])]
    paths = []
    for target in crown or [None]:  # every run asks this first: the run asks it
        args = {"k": 10, **({"target_id": target} if target else {})}
        _, shown = await ctx.preload("pathfinder", "attack_paths", args)
        paths.append(shown)
    context = {
        "crown_jewels": tp.get("crown_jewels", []),
        "investigate": [
            {k: f.get(k) for k in ("finding", "hostname", "cve", "cvss", "kev", "techniques")}
            for f in tp.get("investigate", [])
        ],
        "suppressed_by_live_acceptance": [s["finding"] for s in tp.get("suppressed", [])],
        "as_of_date": day(ctx.as_of),
        "paths": paths,
    }
    outcome = await run_agent(PATHFINDER, ctx, context)
    payload = finalise_paths(ctx, outcome, tp)
    best = payload["paths"][0] if payload["paths"] else None
    summary = (
        f"{len(payload['paths'])} attack path(s) to {len(payload['targets_reached'])} crown "
        f"jewel(s); {len(payload['ranked'])} finding(s) ranked"
        + (
            f"; most likely p={best['likelihood']:.3f} in {len(best['steps'])} steps."
            if best
            else "."
        )
    )
    oid = ctx.repo.write_output(
        ctx.graph,
        ctx.run_id,
        "PathAnalysis",
        agent="pathfinder",
        payload=payload,
        summary=summary,
        as_of=ctx.as_of,
        cites=[r["finding"] for r in payload["ranked"]],
        built_on=triage["id"] if triage else None,
    )
    return oid, summary


def finalise_paths(ctx: RunCtx, outcome: LoopOutcome, tp: dict) -> dict:
    ans = outcome.final or {}
    weight = {
        c["id"]: SENSITIVITY_WEIGHT.get(c.get("sensitivity") or "crown", 1.0)
        for c in tp.get("crown_jewels", [])
    }
    # Every path any attack_paths call returned, de-duplicated by its steps.
    seen, paths = set(), []
    for r in ctx.results_of("attack_paths"):
        for p in r.result["data"]["paths"]:
            sig = tuple(s["key"] for s in p["steps"])
            if sig in seen:
                continue
            seen.add(sig)
            paths.append(
                {
                    "target": p["target"],
                    "likelihood": p["likelihood"],
                    "nodes": [{"id": n["id"], "name": n.get("name")} for n in p["nodes"]],
                    "steps": [
                        {
                            k: s.get(k)
                            for k in ("key", "rule", "technique", "likelihood", "fix_token")
                        }
                        for s in p["steps"]
                    ],
                }
            )
    paths.sort(key=lambda p: -p["likelihood"])
    # Which findings sit on which path; a finding's score is its best path's
    # likelihood times the target's sensitivity weight.
    on_path: dict[str, dict] = {}
    for i, p in enumerate(paths):
        score = p["likelihood"] * weight.get(p["target"], 1.0)
        for s in p["steps"]:
            tok = s["fix_token"]
            if not _is_finding(tok):
                continue
            e = on_path.setdefault(tok, {"score": 0.0, "paths": [], "targets": set()})
            e["paths"].append(i)
            e["targets"].add(p["target"])
            if score > e["score"]:
                e["score"], e["best_path"], e["step_key"] = score, i, s["key"]
    sup = {s["finding"] for s in tp.get("suppressed", [])}
    why_llm = {r.get("finding"): r.get("why") for r in ans.get("ranked", []) if isinstance(r, dict)}
    order = [f for f in why_llm if f in on_path]
    dropped = [f for f in why_llm if f not in on_path]
    order += sorted((f for f in on_path if f not in order), key=lambda f: -on_path[f]["score"])
    ranked = []
    for rank, f in enumerate(order[:MAX_RANKED], start=1):
        e = on_path[f]
        best = paths[e["best_path"]]
        ranked.append(
            {
                "rank": rank,
                "finding": f,
                "score": round(e["score"], 4),
                "best_likelihood": round(best["likelihood"], 4),
                "targets": sorted(e["targets"]),
                "path_index": e["best_path"],
                "on_paths": len(e["paths"]),
                "step_key": e["step_key"],
                "suppressed_by_live_acceptance": f in sup,
                "why": why_llm.get(f)
                or f"Step {e['step_key']} on path #{e['best_path'] + 1} to {best['target']} "
                f"(p={best['likelihood']:.3f}).",
                "ranked_by": "llm" if f in why_llm else "score",
            }
        )
    explained = [
        {
            "key": r.result["data"]["key"],
            "rule": r.result["data"]["rule"],
            "technique": r.result["data"]["technique"].get("id"),
            "fix": r.result["data"]["fix"],
            "because": [b["id"] for b in r.result["data"]["because"]],
        }
        for r in ctx.results_of("why_step")
    ]
    blast = [
        {
            "start": r.result["data"]["start"],
            "crown_jewels": r.result["data"]["crown_jewels"],
            "counts": r.result["data"]["counts"],
        }
        for r in ctx.results_of("blast_radius")
    ]
    return {
        "paths": paths,
        "targets_reached": sorted({p["target"] for p in paths}),
        "crown_jewels": tp.get("crown_jewels", []),
        "ranked": ranked,
        "explained_steps": explained,
        "blast_radius": blast,
        "reasoning": str(ans.get("reasoning", ""))[:2000],
        "dropped": sorted(set(dropped)),
        **_note(outcome),
    }


# ======================================================================= Fixer
FIXER = AgentSpec(
    name="fixer",
    tools=("simulate_fix", "owners", "decision_trail"),
    required=("simulate_fix",),
    role="""\
Turn the attack paths into a fix plan people can act on. CONTEXT.min_cuts holds min_cut in \
both modes ("fewest" and "cheapest"); CONTEXT.routes holds, per fix asset, the owning team, \
the on-call person and the ADR that exposed it (looked up for you, or remembered from an \
earlier run).
1. Compare fewer fixes vs less total effort and choose ONE of the two sets. If both have \
the same number of fixes, take the cheaper one (same work count, less effort).
2. simulate_fix ONCE on exactly the chosen set (it copies the graph: one call, never one \
per fix). owners / decision_trail only for an asset CONTEXT.routes lacks.
Write a ticket per fix: a title and a 2-4 sentence body naming the asset, the attack step it \
removes, the owner, and the ADR if there is one.""",
    schema="""{"chosen": "fewest" | "cheapest", "fix_tokens": ["<fix token>"],
 "rationale": "<2-4 sentences>",
 "tickets": [{"token": "<fix token>", "title": "<title>", "body": "<2-4 sentences>"}]}""",
    check=lambda ctx, final: verify_mismatch(ctx, final),
    max_turns=4,  # verify, answer; +1 turn each only if the answer needs re-verifying
)


def verify_mismatch(ctx: RunCtx, final: dict) -> str | None:
    """The Fixer must answer with the set it proved. Seen for real: it simulated
    the "fewest" set, answered "cheapest", and wrote that the simulation passed."""
    want = sorted({t for t in final.get("fix_tokens", []) if isinstance(t, str)})
    sims = [sorted(r.result["data"]["fix_tokens"]) for r in ctx.results_of("simulate_fix")]
    if not want or want in sims:
        return None
    return (
        f"Your answer names fix set {want}, but simulate_fix ran on {sims}: that set is NOT "
        "verified. Call simulate_fix on exactly the set you chose, then answer with the JSON."
    )


async def fixer_agent(ctx: RunCtx, state: dict) -> tuple[str, str]:
    triage = ctx.repo.read_output(ctx.graph, ctx.run_id, "Triage")
    pa = ctx.repo.read_output(ctx.graph, ctx.run_id, "PathAnalysis")
    tp, pp = (triage or {}).get("payload", {}), (pa or {}).get("payload", {})
    cuts, fixes = {}, {}
    for mode in ("fewest", "cheapest"):  # every Fixer starts by asking both: the run does
        res, cuts[mode] = await ctx.preload("fixer", "min_cut", {"mode": mode})
        for f in ((res or {}).get("data") or {}).get("fixes", []):
            fixes.setdefault(f["token"], f)
    entry = {f["asset"] for f in tp.get("investigate", []) if f.get("asset")}
    routes = await lookup_routes(ctx, list(fixes.values()), entry, state.get("known_routes"))
    context = {
        "min_cuts": cuts,
        "routes": {a: _route_view(r) for a, r in routes.items()},
        "crown_jewels": pp.get("crown_jewels", []),
        "ranked_findings": [
            {k: r.get(k) for k in ("rank", "finding", "score", "targets", "step_key")}
            for r in pp.get("ranked", [])[:10]
        ],
        "most_likely_path": (pp.get("paths") or [None])[0],
        "suppressed_by_live_acceptance": tp.get("suppressed", []),
        "as_of_date": day(ctx.as_of),
    }
    outcome = await run_agent(FIXER, ctx, context)
    payload = finalise_fixes(ctx, outcome, tp, routes)
    v = payload["verified"]
    summary = (
        f"{payload['chosen'] or 'no'} fix set: {len(payload['fix_tokens'])} fix(es), effort "
        f"{payload['total_effort']}; simulate_fix: "
        + ("all crown jewels disconnected." if v else "NOT verified." if v is None else "FAILED.")
    )
    oid = ctx.repo.write_output(
        ctx.graph,
        ctx.run_id,
        "FixPlan",
        agent="fixer",
        payload=payload,
        summary=summary,
        as_of=ctx.as_of,
        cites=[t for t in payload["fix_tokens"] if _is_finding(t)],
        built_on=pa["id"] if pa else None,
    )
    return oid, summary


def _route_asset(fix: dict) -> str | None:
    """The asset whose owner should get this fix."""
    if fix.get("asset"):
        return fix["asset"]
    for k in ("from", "to"):
        if fix.get(k) and label_of(fix[k]) in ("Asset", "DataStore"):
            return fix[k]
    return None


async def lookup_routes(
    ctx: RunCtx, fixes: list[dict], entry_assets: set[str], known: dict | None = None
) -> dict[str, dict]:
    """Who gets each fix: per fix asset, the owning team + on-call person (owners)
    and, for an Internet-facing entry asset, the ADR that exposed it
    (decision_trail). Deterministic plumbing, so the run does it (by="run"):
    the model's job is choosing and proving the set, not paging through owners.

    `known` = routes remembered from an earlier run whose on-call slot still covers
    this run's clock (episodic memory): those assets are not looked up again."""
    routes: dict[str, dict] = {}
    for f in fixes:
        asset = _route_asset(f)
        if not asset or asset in routes:
            continue
        if known and asset in known:
            routes[asset] = {**known[asset], "source": known[asset].get("source", "memory")}
            continue
        own, _ = await ctx.preload("fixer", "owners", {"asset_id": asset})
        team = (((own or {}).get("data") or {}).get("teams") or [None])[0]
        adrs = []
        if asset in entry_assets:
            trail, _ = await ctx.preload("fixer", "decision_trail", {"asset_id": asset})
            adrs = [
                {
                    "adr": d["adr"],
                    "title": d["title"],
                    "date": d["date"],
                    "approved_by": d["approved_by"]["name"],
                    "role": d["approved_by"]["role"],
                }
                for d in ((trail or {}).get("data") or {}).get("decisions", [])
            ]
        routes[asset] = {
            "asset": asset,
            "team": {"id": team["id"], "name": team["name"]} if team else None,
            "on_call": team.get("on_call") if team else None,
            "adrs": adrs,
            "source": "lookup",
        }
    return routes


def _route_view(r: dict) -> dict:
    oc = r.get("on_call") or {}
    return {
        "team": (r.get("team") or {}).get("name"),
        "on_call": f"{oc.get('name')} ({oc.get('role')})" if oc else None,
        "adrs": [
            f"{a['adr']} {a['title']} ({a['date']}, approved by {a['approved_by']})"
            for a in r.get("adrs", [])
        ],
        **({"remembered_from": r["source"]} if r.get("source", "lookup") != "lookup" else {}),
    }


def finalise_fixes(
    ctx: RunCtx, outcome: LoopOutcome, tp: dict, routes: dict[str, dict] | None = None
) -> dict:
    ans = outcome.final or {}
    options: dict[str, dict] = {}
    fix_info: dict[str, dict] = {}
    for r in ctx.results_of("min_cut"):
        d = r.result["data"]
        if not d.get("fix_tokens"):
            continue
        options[d["mode"]] = {
            "fix_tokens": d["fix_tokens"],
            "total_effort": d["total_effort"],
            "max_flow": d["max_flow"],
            "prefer": d["prefer"],
        }
        for f in d["fixes"]:
            fix_info[f["token"]] = f
    chosen = ans.get("chosen") if ans.get("chosen") in options else None
    dropped: list[str] = []
    wanted = [t for t in ans.get("fix_tokens", []) if isinstance(t, str)]
    if wanted and all(t in fix_info for t in wanted):
        tokens = sorted(set(wanted))  # the model's set, every token from a min_cut
    else:
        dropped += [t for t in wanted if t not in fix_info]
        chosen = chosen or ("fewest" if "fewest" in options else next(iter(options), None))
        tokens = options[chosen]["fix_tokens"] if chosen else []
    if chosen is None:
        chosen = next((m for m, o in options.items() if o["fix_tokens"] == tokens), "custom")

    # Verification is simulate_fix's answer for exactly this set, nothing else.
    sim = next(
        (
            r.result["data"]
            for r in ctx.results_of("simulate_fix")
            if sorted(r.result["data"]["fix_tokens"]) == tokens
        ),
        None,
    )
    other_sim = [r.result["data"]["fix_tokens"] for r in ctx.results_of("simulate_fix")]
    verified = sim["all_crown_jewels_disconnected"] if sim else None

    # Routing: the run's lookups/memory, plus any owners / decision_trail the model
    # asked for itself (an asset the routes lacked).
    routes = dict(routes or {})
    for r in ctx.results_of("owners", "fixer"):
        if r.args["asset_id"] not in routes:
            team = (r.result["data"].get("teams") or [None])[0]
            routes[r.args["asset_id"]] = {
                "team": {"id": team["id"], "name": team["name"]} if team else None,
                "on_call": team.get("on_call") if team else None,
                "adrs": [],
                "source": "lookup",
            }
    sup = {s["finding"]: s for s in tp.get("suppressed", [])}
    tickets = {
        t.get("token"): t for t in ans.get("tickets", []) if isinstance(t, dict) and t.get("token")
    }
    fixes = []
    for tok in tokens:
        f = fix_info.get(tok, {"token": tok})
        asset = _route_asset(f)
        route = routes.get(asset) or {}
        t = tickets.get(tok) or {}
        fixes.append(
            {
                "token": tok,
                "kind": f.get("kind"),
                "action": f.get("action"),
                "effort": f.get("effort"),
                "asset": asset,
                "hostname": f.get("hostname"),
                "cve": f.get("cve"),
                "team": route.get("team"),
                "on_call": route.get("on_call"),
                "adrs": route.get("adrs", []),
                "routed_by": route.get("source"),
                "accepted_risk": sup.get(tok),
                "ticket": {
                    "title": str(t.get("title") or f"Remove attack step: {f.get('action', tok)}")[
                        :200
                    ],
                    "body": str(
                        t.get("body")
                        or f"{f.get('action', tok)}. This fix is in the minimum set that cuts "
                        "every attack path to the crown jewels (min_cut)."
                    )[:1500],
                    "by": "llm" if t else "template",
                },
            }
        )
    dropped += [k for k in tickets if k not in tokens]
    return {
        "options": options,
        "chosen": chosen,
        "fix_tokens": tokens,
        "total_effort": sum((fix_info.get(t, {}).get("effort") or 0) for t in tokens),
        "verified": verified,
        "simulation": {
            k: sim[k]
            for k in (
                "fix_tokens",
                "removed_steps",
                "reachable_before",
                "reachable_after",
                "all_crown_jewels_disconnected",
            )
        }
        if sim
        else None,
        "simulated_other_sets": [s for s in other_sim if sorted(s) != tokens],
        "fixes": fixes,
        "rationale": str(ans.get("rationale", ""))[:2000],
        "dropped": sorted(set(dropped)),
        **_note(outcome),
    }


# ==================================================================== Reporter
REPORTER = AgentSpec(
    name="reporter",
    tools=(),  # the evidence is already in its CONTEXT: one call, no tool turns
    required=(),
    max_turns=1,
    role="""\
Write the one-page executive summary of this run for a non-technical reader. EVERY claim \
must carry evidence: the node ids or ATTACK_STEP keys from CONTEXT that prove it (claims \
whose evidence is missing or not in CONTEXT are dropped). Cover: how many findings the scan \
had vs how many actually matter; the most likely path to the crown jewel; the fix plan (how \
many fixes, effort, verified or not, who owns them); anything a live risk acceptance \
suppressed or an expired one no longer covers. Plain words, no jargon.""",
    schema="""{"headline": "<one sentence>",
 "risk": "critical" | "high" | "medium" | "low",
 "claims": [{"text": "<one sentence>", "evidence": ["<node id or step key>"]}]}""",
)


async def reporter_agent(ctx: RunCtx, state: dict) -> tuple[str, str]:
    from .report import build_report  # report.py renders; this module decides

    outs = {
        label: ctx.repo.read_output(ctx.graph, ctx.run_id, label)
        for label in ("Triage", "PathAnalysis", "FixPlan")
    }
    tp, pp, fp = ((outs[k] or {}).get("payload", {}) for k in ("Triage", "PathAnalysis", "FixPlan"))
    context = digest(tp, pp, fp, ctx.as_of)
    outcome = await run_agent(REPORTER, ctx, context)
    payload = build_report(ctx, outcome, tp, pp, fp, {**state, "digest": context})
    triage_id = (outs["Triage"] or {}).get("id")
    payload["verdicts"] = record_verdicts(ctx, triage_id, tp, pp, fp)
    summary = payload["headline"]
    oid = ctx.repo.write_output(
        ctx.graph,
        ctx.run_id,
        "Report",
        agent="reporter",
        payload=payload,
        summary=summary,
        as_of=ctx.as_of,
        cites=[r["finding"] for r in pp.get("ranked", [])],
        built_on=(outs["FixPlan"] or {}).get("id"),
    )
    return oid, summary


def digest(tp: dict, pp: dict, fp: dict, as_of: int) -> dict:
    """What the Reporter's model reads: the three handoffs, cut to essentials."""
    best = (pp.get("paths") or [None])[0]
    return {
        "as_of_date": day(as_of),
        "scan": {"counts": tp.get("counts"), "scan": tp.get("scan")},
        "triage": {
            "investigated": [f["finding"] for f in tp.get("investigate", [])],
            "suppressed": tp.get("suppressed", []),
            "expired_acceptances": tp.get("expired_acceptances", []),
            "deprioritised": tp.get("deprioritised", [])[:5],
            "patterns": tp.get("patterns", []),
        },
        "most_likely_path": best,
        "ranked_findings": [
            {k: r.get(k) for k in ("rank", "finding", "best_likelihood", "targets", "step_key")}
            for r in pp.get("ranked", [])[:8]
        ],
        "fix_plan": {
            "chosen": fp.get("chosen"),
            "options": fp.get("options"),
            "verified_by_simulate_fix": fp.get("verified"),
            "fixes": [
                {
                    "token": f["token"],
                    "action": f["action"],
                    "effort": f["effort"],
                    "asset": f["asset"],
                    "team": f["team"],
                    "adrs": [a["adr"] for a in f["adrs"]],
                }
                for f in fp.get("fixes", [])
            ],
        },
    }


def record_verdicts(ctx: RunCtx, triage_id: str | None, tp: dict, pp: dict, fp: dict) -> list[dict]:
    """Episodic memory for the next run: one Verdict per finding this run decided."""
    fix_set = set(fp.get("fix_tokens", []))
    decisions: dict[str, tuple[str, str]] = {}
    for r in pp.get("ranked", []):
        f = r["finding"]
        if f in fix_set:
            decisions[f] = ("fix_now", f"In the verified minimum fix set; cuts {r['step_key']}.")
        elif not r.get("suppressed_by_live_acceptance"):
            decisions[f] = (
                "schedule",
                f"On an attack path (p={r['best_likelihood']}) but not in the minimum fix set.",
            )
    for f in fix_set:
        if _is_finding(f) and f not in decisions:
            decisions[f] = ("fix_now", "In the verified minimum fix set (min_cut).")
    for d in tp.get("deprioritised", []):
        decisions.setdefault(d["finding"], ("not_reachable", d["reason"][:300]))
    out = []
    for f, (decision, reason) in sorted(decisions.items()):
        v = ctx.repo.record_verdict(
            ctx.graph, f, decision, reason, triage_id=triage_id, ts=ctx.as_of
        )
        out.append({"id": v.id, "finding": f, "decision": decision})
    return out


def known_evidence(ctx: RunCtx, *payloads: dict[str, Any]) -> set[str]:
    """Every id / step key a claim may cite: what the tools returned as evidence,
    plus the ids in the handoff payloads (which were grounded the same way)."""
    known = set(ctx.evidence)

    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif isinstance(x, str) and (label_of(x) or "|" in x or x.startswith("step:")):
            known.add(x)

    for p in payloads:
        walk(p)
    return known
