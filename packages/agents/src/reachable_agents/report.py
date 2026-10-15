"""The Reporter's two artifacts, and the human-readable dump of a whole run.

build_report      the Report payload: the exec summary (claims, each with the
                  evidence that proves it; unsupported claims are dropped, not
                  softened) and the engineer view (ranked findings, each with its
                  attack path and the fix that cuts it).
render_run        runs/<run_id>.md, rendered from the run AS READ BACK FROM THE
                  GRAPH (MemoryRepo.agent_run), so the file proves the run is
                  reconstructable without the process that produced it.
"""

from __future__ import annotations

import json
import re

from .agents import known_evidence
from .loop import LoopOutcome, day
from .runtime import RunCtx

RISKS = ("critical", "high", "medium", "low")


# ------------------------------------------------------------- the Report
def build_report(
    ctx: RunCtx, outcome: LoopOutcome, tp: dict, pp: dict, fp: dict, state: dict
) -> dict:
    ans = outcome.final or {}
    known = known_evidence(ctx, tp, pp, fp)
    numbers = known_numbers(tp, pp, fp, state.get("digest"))
    claims, dropped = [], []
    for c in ans.get("claims", []):
        if not isinstance(c, dict) or not str(c.get("text", "")).strip():
            continue
        ev = [e for e in c.get("evidence", []) if isinstance(e, str)]
        bad = [e for e in ev if e not in known]
        made_up = unsupported_numbers(str(c["text"]), numbers)
        if not ev or bad or made_up:
            why = (
                "no evidence"
                if not ev
                else f"unknown: {bad}"
                if bad
                else f"numbers not in the data: {made_up}"
            )
            dropped.append({"text": c["text"], "evidence": ev, "why": why})
        else:
            claims.append({"text": str(c["text"])[:400], "evidence": ev, "by": "llm"})
    if not claims:  # no usable answer: state the facts the handoffs prove
        claims = fact_claims(tp, pp, fp)
    headline = str(ans.get("headline") or "").strip()
    if not headline or unsupported_numbers(headline, numbers):
        if headline:
            dropped.append(
                {"text": headline, "evidence": [], "why": "headline: numbers not in data"}
            )
        headline = default_headline(tp, pp, fp)
    risk = ans.get("risk") if ans.get("risk") in RISKS else default_risk(pp, fp)
    payload = {
        "headline": headline[:300],
        "risk": risk,
        "claims": claims,
        "dropped_claims": dropped,
        **{k: v for k, v in _note(outcome).items()},
    }
    payload["exec_md"] = exec_markdown(payload)
    payload["engineer_md"] = engineer_markdown(tp, pp, fp, ctx.as_of)
    return payload


_NUM = re.compile(r"\d[\d,]*(?:\.\d+)?")


def known_numbers(*sources) -> set[float]:
    """Every number the Reporter's model could legitimately quote: those in its
    context and in the three handoffs (rounded to 2 decimals)."""
    text = json.dumps(sources, default=str)
    return {round(float(m.replace(",", "")), 2) for m in _NUM.findall(text)}


def unsupported_numbers(text: str, numbers: set[float]) -> list[str]:
    """Numbers in a sentence that appear nowhere in the data. Small counts (<= 20)
    are allowed: they are usually the length of a list ("5 steps", "7 fixes")."""
    out = []
    for m in _NUM.findall(text):
        x = float(m.replace(",", "").rstrip("."))
        if x <= 20 and x == int(x):
            continue
        if round(x, 2) not in numbers and round(x / 100, 2) not in numbers:  # 20% vs 0.2
            out.append(m)
    return out


def _note(outcome: LoopOutcome) -> dict:
    return {
        "llm_answered": outcome.final is not None,
        "stop": outcome.reason,
        "turns": outcome.turns,
    }


def fact_claims(tp: dict, pp: dict, fp: dict) -> list[dict]:
    out = []
    c = tp.get("counts") or {}
    scan = tp.get("scan") or {}
    inv = [f["finding"] for f in tp.get("investigate", [])]
    if c:
        out.append(
            {
                "text": f"The scan has {c.get('open')} open findings, but only "
                f"{c.get('enabling_attack_steps')} enable any attack step and "
                f"{c.get('on_crown_path')} sit on a path to a crown jewel; {len(inv)} were "
                "investigated.",
                "evidence": [x for x in [scan.get("id"), *inv[:3]] if x],
            }
        )
    best = (pp.get("paths") or [None])[0]
    if best:
        names = " -> ".join(n.get("name") or n["id"] for n in best["nodes"])
        out.append(
            {
                "text": f"The most likely attack reaches crown jewel {best['target']} in "
                f"{len(best['steps'])} steps (likelihood {best['likelihood']:.3f}): {names}.",
                "evidence": [best["target"], *(s["key"] for s in best["steps"])],
            }
        )
    if fp.get("fix_tokens"):
        v = fp.get("verified")
        out.append(
            {
                "text": f"{len(fp['fix_tokens'])} fixes (total effort {fp.get('total_effort')}) "
                "cut every attack path to the crown jewels; simulate_fix "
                + (
                    "confirmed it."
                    if v
                    else "did not confirm it."
                    if v is False
                    else "was not run."
                ),
                "evidence": list(fp["fix_tokens"]),
            }
        )
    for s in tp.get("suppressed", []):
        out.append(
            {
                "text": f"{s['finding']} is suppressed by live risk acceptance {s['acceptance']} "
                f"(approved by {s.get('approved_by')}, expires {s.get('expires_date')}).",
                "evidence": [s["finding"], s["acceptance"]],
            }
        )
    for e in tp.get("expired_acceptances", []):
        out.append(
            {
                "text": f"Risk acceptance {e['acceptance']} on {e['finding']} expired on "
                f"{e['expired_date']}, so that finding is back in scope.",
                "evidence": [e["finding"], e["acceptance"]],
            }
        )
    dep = tp.get("deprioritised", [])
    if dep:
        out.append(
            {
                "text": f"{len(dep)} critical findings were deprioritised: they enable no attack "
                "step, so no attacker can use them today.",
                "evidence": [d["finding"] for d in dep[:5]],
            }
        )
    for o in out:
        o["by"] = "facts"
    return out


def default_headline(tp: dict, pp: dict, fp: dict) -> str:
    best = (pp.get("paths") or [None])[0]
    if not best:
        return "No attack path from the Internet to a crown jewel was found in this scan."
    return (
        f"An attacker can reach the crown jewel in {len(best['steps'])} steps; "
        f"{len(fp.get('fix_tokens', []))} fixes cut every path."
    )


def default_risk(pp: dict, fp: dict) -> str:
    best = (pp.get("paths") or [None])[0]
    if not best:
        return "low"
    return (
        "critical"
        if best["likelihood"] >= 0.1
        else "high"
        if best["likelihood"] >= 0.01
        else "medium"
    )


def exec_markdown(p: dict) -> str:
    lines = [f"**{p['headline']}** (risk: {p['risk']})", ""]
    for c in p["claims"]:
        lines.append(
            f"- {c['text']}  \n  _evidence:_ " + ", ".join(f"`{e}`" for e in c["evidence"])
        )
    if p["dropped_claims"]:
        lines += ["", f"_{len(p['dropped_claims'])} claim(s) dropped for missing evidence._"]
    return "\n".join(lines)


def engineer_markdown(tp: dict, pp: dict, fp: dict, as_of: int) -> str:
    paths = pp.get("paths", [])
    fixes = {f["token"]: f for f in fp.get("fixes", [])}
    fix_set = set(fp.get("fix_tokens", []))
    inv = {f["finding"]: f for f in tp.get("investigate", [])}
    lines = []
    for r in pp.get("ranked", [])[:12]:
        p = paths[r["path_index"]]
        f = inv.get(r["finding"], {})
        head = f"**{r['rank']}. `{r['finding']}`**"
        if f:
            head += f" on {f.get('hostname')} ({f.get('cve')}, CVSS {f.get('cvss')}" + (
                ", KEV)" if f.get("kev") else ")"
            )
        if r.get("suppressed_by_live_acceptance"):
            head += " (accepted risk: live acceptance)"
        lines.append(head)
        names = " -> ".join(n.get("name") or n["id"] for n in p["nodes"])
        lines.append(
            f"- path #{r['path_index'] + 1} to `{p['target']}`, p={p['likelihood']:.3f}: {names}"
        )
        lines.append("- steps: " + " -> ".join(f"`{s['key']}`" for s in p["steps"]))
        cuts = [s["fix_token"] for s in p["steps"] if s["fix_token"] in fix_set]
        for tok in dict.fromkeys(cuts):
            fx = fixes.get(tok, {})
            team = (fx.get("team") or {}).get("name", "no owner recorded")
            oc = (fx.get("on_call") or {}).get("name")
            adr = ", ".join(a["adr"] for a in fx.get("adrs", []))
            lines.append(
                f"- cut by `{tok}`: {fx.get('action')} (effort {fx.get('effort')}; {team}"
                + (f", on call {oc}" if oc else "")
                + (f"; {adr}" if adr else "")
                + ")"
            )
        if not cuts:
            lines.append("- not cut by the chosen fix set (see Fix plan)")
        lines.append(f"- why: {r['why']}")
        lines.append("")
    return "\n".join(lines) or f"No ranked findings (as of {day(as_of)})."


# ------------------------------------------------------- runs/<run_id>.md
def render_run(dump: dict) -> str:
    run, outs = dump["run"], dump["outputs"]
    tp = outs.get("Triage", {}).get("payload", {})
    pp = outs.get("PathAnalysis", {}).get("payload", {})
    fp = outs.get("FixPlan", {}).get("payload", {})
    rp = outs.get("Report", {}).get("payload", {})
    st = run.get("stats") or {}
    lines = [
        f"# Reachable run `{run['id']}`",
        "",
        f"- graph `{dump.get('graph', '?')}`, scan **{run.get('scan')}**, as_of "
        f"**{day(run.get('as_of'))}** (the scan's clock; started "
        f"{day(run.get('started'))} wall clock)",
        f"- status **{run.get('status')}**, wall time {st.get('wall_ms', 0) / 1000:.1f} s",
        f"- LLM calls {st.get('llm_calls')}, tool calls {st.get('tool_calls')} "
        f"(+{st.get('cache_hits')} cache hits, {st.get('refused')} refused), "
        f"tokens {st.get('tokens_in')} in / {st.get('tokens_out')} out",
        f"- models: {', '.join(run.get('models') or []) or 'none'}"
        + (f"; fallbacks {st.get('fallbacks')}" if st.get("fallbacks") else ""),
        f"- AgentStep chain intact: {dump.get('chain_ok')}",
        "",
        "## Triage",
        "",
        outs.get("Triage", {}).get("summary", "(no triage output)"),
        "",
    ]
    for s in tp.get("suppressed", []):
        lines.append(
            f"- suppressed `{s['finding']}`: live acceptance `{s['acceptance']}` "
            f"until {s.get('expires_date')} ({s.get('approved_by')})"
        )
    for e in tp.get("expired_acceptances", []):
        lines.append(
            f"- back in scope `{e['finding']}`: acceptance `{e['acceptance']}` "
            f"expired {e['expired_date']}"
        )
    for d in tp.get("deprioritised", [])[:5]:
        lines.append(f"- deprioritised `{d['finding']}`: {d['reason']}")
    for p in tp.get("playbooks", []):
        lines.append(f"- playbook for {p['technique']}: `{p['id']}` (v{p['version']})")
    if tp.get("reasoning"):
        lines += ["", f"> {tp['reasoning']}"]
    lines += ["", "## Top paths", ""]
    for i, p in enumerate(pp.get("paths", [])[:3], start=1):
        names = " -> ".join(n.get("name") or n["id"] for n in p["nodes"])
        lines.append(f"{i}. p={p['likelihood']:.3f} to `{p['target']}`: {names}")
    lines += ["", "## Fix plan", ""]
    lines.append(outs.get("FixPlan", {}).get("summary", "(no fix plan)"))
    lines.append("")
    for mode, o in (fp.get("options") or {}).items():
        mark = " (chosen)" if mode == fp.get("chosen") else ""
        lines.append(f"- {mode}{mark}: {len(o['fix_tokens'])} fixes, effort {o['total_effort']}")
    lines += ["", "| fix | action | effort | owner | on call | ADR |", "|---|---|---|---|---|---|"]
    for f in fp.get("fixes", []):
        oc = f.get("on_call") or {}
        lines.append(
            f"| `{f['token']}` | {f.get('action')} | {f.get('effort')} | "
            f"{(f.get('team') or {}).get('name', '-')} | {oc.get('name', '-')} | "
            + (", ".join(a["adr"] for a in f.get("adrs", [])) or "-")
            + " |"
        )
    lines += ["", "### Tickets", ""]
    for f in fp.get("fixes", []):
        t = f["ticket"]
        lines += [f"**{t['title']}** ({t['by']})", "", t["body"], ""]
    lines += ["## Report", "", "### Executive summary", "", rp.get("exec_md", "(none)"), ""]
    lines += ["### Engineer view", "", rp.get("engineer_md", "(none)"), ""]
    lines += [
        "## Trace",
        "",
        "| seq | agent | step | ms | queries | note |",
        "|---|---|---|---|---|---|",
    ]
    for s in dump["steps"]:
        if s.get("kind") == "llm":
            what = f"llm {s.get('served_by', '')} {s.get('model', '')}".strip()
            note = ", ".join(c["name"] for c in s.get("tool_calls") or []) or (
                "answer" if s.get("output") else s.get("error", "")
            )
            q = "-"
        else:
            what = s.get("tool", "?")
            note = (
                "cache hit"
                if s.get("cached")
                else s.get("error") or (s.get("summary") or "")[:90].replace("|", "/")
            )
            q = f"{s.get('n_queries', 0)} ({s.get('db_ms', 0)} ms)" if s.get("n_queries") else "-"
        lines.append(
            f"| {s['seq']} | {s.get('agent', '')} | {what} | {s.get('ms', '')} | {q} | {note} |"
        )
    return "\n".join(lines) + "\n"
