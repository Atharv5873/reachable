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
    tools=("playbooks", "triage_memory"),
    required=("playbooks",),
    max_turns=3,
    role="""\
Decide which of this scan's open findings deserve attack-path investigation. CONTEXT.scan \
is the scan digest: counts by severity band, ATT&CK technique and exposure; the CANDIDATES \
still to decide (Internet-facing findings on a crown-jewel path, with detail); a count and \
sample of the other Internet-facing findings; the critical findings that enable no attack \
step at all; and previously_decided (findings a person decided about). CONTEXT.memory is \
what memory already said about the candidates before you started: CARRIED ones keep their \
earlier verdict (nothing changed for them) and are NOT investigated again; SUPPRESSED ones \
have a live risk acceptance.
1. playbooks for the techniques the candidates and carried findings enable. The memory of \
every finding in CONTEXT.scan is already in CONTEXT.memory: call triage_memory only for a \
finding it does not cover. CONTEXT.memory.still_unreachable counts critical no-step findings \
whose earlier "not reachable" verdict stands (they stay deprioritised).
2. A LIVE risk acceptance suppresses a finding: name it. An EXPIRED one does NOT suppress \
anything.
3. CONTEXT.drift (a new scan only) is the Sentinel's check: findings on a NEW crown path and \
arrivals FLAGGED by a learned pattern: investigate those first.
Investigate the remaining candidates unless a live acceptance suppresses them. Deprioritise \
critical findings that enable no attack step, and say why (high score, no way in).""",
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
    sf = (sf or {}).get("data") or {}
    drift_out = ctx.repo.read_output(ctx.graph, ctx.run_id, "Drift")  # the Sentinel's handoff
    drift = (drift_out or {}).get("payload") or {}
    digest = scan_digest(sf)

    # Recall before reasoning (episodic memory): the run asks memory about every
    # candidate, sets aside those whose earlier verdict still stands, and the
    # model reasons only about what is new.
    cands = [c["finding"] for c in digest["candidates"]]
    crits = [c["finding"] for c in digest["critical_without_attack_step"]]
    ids = list(dict.fromkeys(cands + crits + list(digest["previously_decided"])))[:200]
    if ids:
        await ctx.preload("triage", "triage_memory", {"finding_ids": ids})
    rec = recall(ctx, _scan_rows(sf), drift, no_step=crits)
    if rec["carried"]:
        ctx.record_memory(
            "triage",
            "carried_verdicts",
            {
                "skipped": len(rec["carried"]),
                "findings": {c["finding"]: c["verdict"] for c in rec["carried"]},
            },
        )
    set_aside = {c["finding"] for c in rec["carried"]} | rec["sup_ids"]
    digest["candidates"] = [c for c in digest["candidates"] if c["finding"] not in set_aside]
    still_out = {c["finding"] for c in rec["still_unreachable"]} | rec["sup_ids"]
    digest["critical_without_attack_step"] = [
        c for c in digest["critical_without_attack_step"] if c["finding"] not in still_out
    ]
    context = {
        "org": state["org"],
        "as_of_date": day(ctx.as_of),
        "scan": digest,
        "memory": {
            "carried": {
                c[
                    "finding"
                ]: f"{c['decision']} on {c['decided']} ({', '.join(c['techniques'] or [])})"
                for c in rec["carried"]
            },
            "suppressed": {s["finding"]: s["acceptance"] for s in rec["suppressed"]},
            "expired_acceptances": {e["finding"]: e["acceptance"] for e in rec["expired"]},
            "still_unreachable": len(rec["still_unreachable"]),
            "patterns": {
                p["id"]: p["description"][:140] for p in list(rec["patterns"].values())[:5]
            },
        },
        **({"drift": drift_digest(drift)} if drift_out else {}),
    }
    outcome = await run_agent(TRIAGE, ctx, context)
    payload = finalise_triage(ctx, outcome, drift)
    summary = (
        f"{payload['counts'].get('open', '?')} open findings; investigate "
        f"{len(payload['investigate'])}, carried {len(payload['carried'])} (prior verdict "
        f"stands), suppressed {len(payload['suppressed'])} (live risk acceptance), "
        f"{len(payload['expired_acceptances'])} expired acceptance(s) ignored, deprioritised "
        f"{len(payload['deprioritised'])}."
    )
    cites = (
        [f["finding"] for f in payload["investigate"]]
        + [c["finding"] for c in payload["carried"]]
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
        built_on=(drift_out or {}).get("id"),
    )
    return oid, summary


def recall(
    ctx: RunCtx,
    on_steps: dict[str, dict],
    drift: dict,
    extra: list[str] = (),
    no_step: list[str] = (),
) -> dict:
    """What memory says, merged over every triage_memory result Triage has so far.
    The tool computed "live" at the run's as_of, so suppression is a fact, not the
    model's opinion; and so is "carried" (episodic memory, as a rule):

    a candidate whose newest verdict (at the run's clock) still stands is carried,
    not investigated again. It stands unless something changed for it: it is on a
    NEW or cost-changed crown path, a learned pattern flagged it on arrival, or a
    risk acceptance on it lapsed after that verdict was made."""
    mem: dict[str, dict] = {}
    acceptances: dict[str, dict] = {}
    patterns: dict[str, dict] = {}
    latest: dict[str, dict] = {}
    for r in ctx.results_of("triage_memory", "triage"):
        d = r.result["data"]
        for f in d["findings"]:
            m = mem.setdefault(f["finding"], {**f})
            m["suppressed"] = m["suppressed"] or f["suppressed"]
        for ra in d["live_risk_acceptances"] + d["expired_risk_acceptances"]:
            acceptances[ra["id"]] = ra
        for p in d["patterns"]:
            patterns[p["id"]] = p
        for v in d["verdicts"]:
            if (v.get("ts") or 0) > ctx.as_of:
                continue  # decided after this run's clock: not memory yet
            cur = latest.get(v["finding"])
            if cur is None or (v["ts"], v["id"]) > (cur["ts"], cur["id"]):
                latest[v["finding"]] = v
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
    flagged = drift.get("flagged_on_arrival") or {}
    fresh = (
        set(drift.get("new_path_findings", []))
        | set(drift.get("changed_path_findings", []))
        | set(flagged)
    )
    pool = [f for f, x in on_steps.items() if x.get("on_crown_path")] + list(extra)
    carried = []
    for fid in dict.fromkeys(pool):
        v = latest.get(fid)
        # An acceptance that expired AFTER the verdict changed the finding's
        # standing (the verdict was made while it was accepted); one that had
        # already expired is part of what the verdict decided.
        lapsed = [
            a
            for a in mem.get(fid, {}).get("expired_acceptances", [])
            if (acceptances.get(a, {}).get("expires") or 0) > (v or {}).get("ts", 0)
        ]
        if v is None or fid in sup_ids or fid in fresh or lapsed:
            continue
        carried.append(
            {
                "finding": fid,
                "verdict": v["id"],
                "decision": v["decision"],
                "reason": str(v.get("reason") or "")[:300],
                "decided": day(v.get("ts")),
                **{
                    k: on_steps.get(fid, {}).get(k)
                    for k in ("asset", "hostname", "cve", "kev", "techniques", "on_crown_path")
                },
            }
        )
    # A critical finding that still enables no attack step, with a standing
    # "not reachable" verdict: nothing to re-argue, its reason stands.
    still_unreachable = [
        {"finding": f, "verdict": latest[f]["id"], "reason": latest[f].get("reason")}
        for f in no_step
        if f in latest and latest[f]["decision"] == "not_reachable" and f not in sup_ids
    ]
    return {
        "mem": mem,
        "patterns": patterns,
        "suppressed": suppressed,
        "sup_ids": sup_ids,
        "expired": expired,
        "carried": carried,
        "still_unreachable": still_unreachable,
        "flagged": flagged,
        "fresh": fresh,
    }


def drift_digest(d: dict) -> dict:
    """What Triage's model reads of the Sentinel's check."""
    return {
        "new_crown_path": d.get("new_crown_path"),
        "new_paths": [" -> ".join(p["hops"]) for p in d.get("new_paths", [])],
        "new_path_findings": d.get("new_path_findings", []),
        "changed_path_findings": d.get("changed_path_findings", []),
        "closed_path_findings": d.get("closed_path_findings", []),
        "flagged_on_arrival": {
            f: [p["description"][:160] for p in ps]
            for f, ps in (d.get("flagged_on_arrival") or {}).items()
        },
    }


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


def finalise_triage(ctx: RunCtx, outcome: LoopOutcome, drift: dict | None = None) -> dict:
    ans = outcome.final or {}
    drift = drift or {}
    sf = ctx.results_of("scan_findings")
    sf = sf[0].result["data"] if sf else {}  # the run's own (preloaded) call
    on_steps = _scan_rows(sf)
    no_step = {f["finding"]: f for f in sf.get("critical_without_attack_step", [])}

    dropped = []
    wanted = [x for x in ans.get("investigate", []) if isinstance(x, str)]
    rec = recall(
        ctx, on_steps, drift, extra=[f for f in wanted if f in on_steps], no_step=list(no_step)
    )
    mem, sup_ids, flagged, fresh = rec["mem"], rec["sup_ids"], rec["flagged"], rec["fresh"]
    carried = rec["carried"]
    carried_ids = {c["finding"] for c in carried}
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
    # Whatever is fresh and is a candidate gets investigated, first; whatever
    # memory carried does not get investigated again.
    first = [f for f in on_steps if f in fresh and f not in sup_ids]
    investigate_ids = [f for f in dict.fromkeys(first + investigate_ids) if f not in carried_ids][
        :MAX_INVESTIGATE
    ]

    reasons = {
        d.get("finding"): d.get("reason")
        for d in ans.get("deprioritised", [])
        if isinstance(d, dict)
    }
    deprioritised = []
    standing = {x["finding"]: x["reason"] for x in rec["still_unreachable"]}
    for fid, f in no_step.items():
        if fid in sup_ids:
            continue
        if fid in standing and fid not in reasons:  # memory: the earlier reason stands
            deprioritised.append({"finding": fid, "reason": str(standing[fid])[:300]})
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
                        "policy": p["current"].get("policy") or [],
                    }
                )
    patterns = rec["patterns"]
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
                **({"flagged_by": [x["pattern"] for x in flagged[f]]} if f in flagged else {}),
                **({"why_now": "on a new crown-jewel path"} if f in fresh - set(flagged) else {}),
            }
            for f in investigate_ids
        ],
        "carried": carried,
        "skipped_by_memory": len(carried),
        "flagged_on_arrival": flagged,
        "suppressed": rec["suppressed"],
        "expired_acceptances": rec["expired"],
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
source or target CONTEXT does not cover. Spend why_step on the findings in \
CONTEXT.investigate; CONTEXT.carried were explained by an earlier run (memory).
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
        "carried": {c["finding"]: c["decision"] for c in tp.get("carried", [])},
        "suppressed_by_live_acceptance": [s["finding"] for s in tp.get("suppressed", [])],
        "as_of_date": day(ctx.as_of),
        "paths": paths,
    }
    if not tp.get("investigate") and tp.get("carried"):
        # Memory made this agent's model call unnecessary: nothing new to explain,
        # every candidate's earlier verdict stands. Rank from the paths alone.
        outcome = LoopOutcome(None, "nothing_new", 0)
        ctx.record_memory(
            "pathfinder", "skipped_llm", {"reason": "every candidate carried a standing verdict"}
        )
    else:
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
    prior = {c["finding"]: c for c in tp.get("carried", [])}
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
                or (
                    f"Carried: {prior[f]['decision']} since {prior[f]['decided']} "
                    f"({prior[f]['verdict']}): {prior[f]['reason']}"
                    if f in prior
                    else None
                )
                or f"Step {e['step_key']} on path #{e['best_path'] + 1} to {best['target']} "
                f"(p={best['likelihood']:.3f}).",
                "ranked_by": "llm" if f in why_llm else "memory" if f in prior else "score",
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
    prior_run, known = ctx.repo.prior_routes(ctx.graph, run_id=ctx.run_id, as_of=ctx.as_of)
    routes = await lookup_routes(ctx, list(fixes.values()), entry, known)
    reused = sorted(a for a, r in routes.items() if r.get("source", "").startswith("memory:"))
    if reused:
        ctx.record_memory(
            "fixer",
            "remembered_routes",
            {"from_run": prior_run, "assets": reused, "looked_up": len(routes) - len(reused)},
        )
    context = {
        "min_cuts": cuts,
        "routes": {a: _route_view(r) for a, r in routes.items()},
        "crown_jewels": pp.get("crown_jewels", []),
        "ranked_findings": [
            {k: r.get(k) for k in ("rank", "finding", "score", "targets", "step_key")}
            for r in pp.get("ranked", [])[:10]
        ],
        "most_likely_path": (pp.get("paths") or [None])[0],
        "suppressed_by_live_acceptance": {
            s["finding"]: s["acceptance"] for s in tp.get("suppressed", [])
        },
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
    payload["patterns_learned"] = record_patterns(ctx, triage_id, tp)
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
            "carried_from_memory": len(tp.get("carried", [])),
            "flagged_on_arrival": sorted(tp.get("flagged_on_arrival") or {}),
            "patterns": [
                {"id": p["id"], "description": p["description"][:140]}
                for p in tp.get("patterns", [])[:5]
            ],
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

    # Procedural memory: a playbook rule in force at this run's clock (learned
    # from an analyst's rejected verdict) overrides the default decision for
    # every finding it matches: same technique, same facts, same decision it
    # was written against.
    facts = finding_facts(tp, pp)
    rules = [
        (pb["technique"], pb["version"], pb["id"], r)
        for pb in tp.get("playbooks", [])
        for r in pb.get("policy") or []
    ]
    by_playbook: dict[str, str] = {}
    for f, (decision, _) in list(decisions.items()):
        fx = facts.get(f)
        for tech, ver, pid, r in rules if fx else []:
            when = r.get("when") or {}
            if (
                tech in fx["techniques"]
                and r.get("instead_of") == decision
                and all(fx.get(k) == v for k, v in when.items())
            ):
                decisions[f] = (r["decision"], f"Playbook {tech} v{ver}: {r.get('because')}"[:300])
                by_playbook[f] = pid
                break
    if by_playbook:
        ctx.record_memory("reporter", "playbook_rules_applied", {"findings": by_playbook})
    out = []
    for f, (decision, reason) in sorted(decisions.items()):
        v = ctx.repo.record_verdict(
            ctx.graph, f, decision, reason, triage_id=triage_id, ts=ctx.as_of, by="agent"
        )
        out.append(
            {
                "id": v.id,
                "finding": f,
                "decision": decision,
                **({"playbook": by_playbook[f]} if f in by_playbook else {}),
            }
        )
    return out


def finding_facts(tp: dict, pp: dict) -> dict[str, dict]:
    """Per finding on a crown path, what a playbook rule can match on: its ATT&CK
    techniques, whether it is a way in from the Internet, and whether it is KEV."""
    facts: dict[str, dict] = {}
    for p in pp.get("paths", []):
        for st in p["steps"]:
            tok = st["fix_token"]
            if not _is_finding(tok):
                continue
            x = facts.setdefault(
                tok,
                {"techniques": set(), "from_internet": False, "on_crown_path": True, "kev": False},
            )
            x["techniques"].add(st.get("technique"))
            x["from_internet"] = x["from_internet"] or st["key"].split("|")[2] == "internet"
    for row in tp.get("investigate", []) + tp.get("carried", []):
        if row["finding"] in facts:
            facts[row["finding"]]["kev"] = bool(row.get("kev"))
    return facts


def record_patterns(ctx: RunCtx, triage_id: str | None, tp: dict) -> list[dict]:
    """Semantic memory for the next scan: every software image (CPE) that was the
    way in on a crown-jewel path becomes a Pattern ABOUT those Software nodes.
    On a later scan, the Sentinel flags any ARRIVING finding on the same image
    before a single path is computed (triage_memory matches Software by CPE)."""
    entries = [
        r for r in tp.get("investigate", []) + tp.get("carried", []) if r.get("on_crown_path")
    ]
    if not entries or not triage_id:
        return []
    ctxs = ctx.repo.finding_context(ctx.graph, [r["finding"] for r in entries])
    by_cpe: dict[str, list[tuple[dict, dict]]] = {}
    for r in entries:
        c = ctxs.get(r["finding"])
        if c and c.get("cpe"):
            by_cpe.setdefault(c["cpe"], []).append((r, c))
    scan = (tp.get("scan") or {}).get("version") or "?"
    out = []
    for cpe, items in sorted(by_cpe.items()):
        vendor, product, version = (cpe.split(":") + ["?"] * 6)[3:6]
        hosts = sorted({r.get("hostname") or c["asset"] for r, c in items})
        n = len(items)
        rec = ctx.repo.upsert_pattern(
            ctx.graph,
            "crown_path_image",
            f"Image {vendor} {product} {version} was the way in on {n} crown-jewel path "
            f"entr{'y' if n == 1 else 'ies'} in scan {scan} ({', '.join(hosts[:4])}). A new "
            "Internet-facing host built from it is a crown-path suspect until a path search "
            "clears it.",
            sorted({c["software"] for _, c in items}),
            seen_in=triage_id,
            ts=ctx.as_of,
        )
        out.append({"id": rec.id, "cpe": cpe, "findings": [r["finding"] for r, _ in items]})
    if out:
        ctx.record_memory(
            "reporter", "patterns_learned", {"patterns": {p["id"]: p["cpe"] for p in out}}
        )
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
