"""A deterministic stand-in for the LLM, so the agent graph runs in CI with no
network and no keys.

It speaks the same ChatModel interface as RouterLLM and plays each agent's part
with a fixed policy: read the CONTEXT and the tool results already in the
conversation, then either ask for the next tools (as tool calls, exactly like
a real model) or give the final JSON. Everything downstream (the loop, the MCP
calls, the cache, the budget, the AgentStep trace, the grounding) runs for
real. It also slips one unsupported claim into the Reporter's answer, so the
evidence check is exercised on every fake run.
"""

from __future__ import annotations

import json
import uuid

from .llm import LLMReply, ToolCall
from .runtime import INJECTION_NOTE


class FakeLLM:
    model = "fake/deterministic"

    def __init__(self) -> None:
        self.calls = 0

    async def chat(
        self, messages: list[dict], tools: list[dict], *, agent: str, tool_choice: str = "auto"
    ) -> LLMReply:
        self.calls += 1
        ctx = _context(messages)
        results = _results(messages)
        act = getattr(self, f"_{agent}")(ctx, results)
        if tool_choice == "none" or isinstance(act, dict):
            final = act if isinstance(act, dict) else getattr(self, f"_{agent}_final")(ctx, results)
            return self._reply(json.dumps(final), [], messages)
        return self._reply(None, act, messages)

    def _reply(self, content: str | None, calls: list[ToolCall], messages: list[dict]) -> LLMReply:
        chars = sum(len(str(m.get("content") or "")) for m in messages)
        return LLMReply(
            content=content,
            tool_calls=calls,
            served_by="fake",
            model=self.model,
            tokens_in=chars // 4,
            tokens_out=len(content or "") // 4 + 20 * len(calls),
            ms=0.0,
            fallback=False,
        )

    # ------------------------------------------------------------ triage
    def _triage(self, ctx, res):
        sf = res.get("scan_findings")
        if not sf:
            return [_call("scan_findings", limit=30)]
        if "triage_memory" not in res:
            d = sf["data"]
            ids = [f["finding"] for f in _dicts(d["findings"])]
            ids += [f["finding"] for f in _dicts(d["critical_without_attack_step"])]
            ids += [f["finding"] for f in _dicts(d["previously_decided"])]
            techs = sorted({t for f in _dicts(d["findings"]) for t in f["techniques"]})
            return [_call("triage_memory", finding_ids=ids), _call("playbooks", techniques=techs)]
        return self._triage_final(ctx, res)

    def _triage_final(self, ctx, res):
        sf = (res.get("scan_findings") or {}).get("data", {})
        tm = (res.get("triage_memory") or {}).get("data", {})
        sup = {f["finding"]: f for f in _dicts(tm.get("findings", [])) if f["suppressed"]}
        return {
            "investigate": [
                f["finding"]
                for f in _dicts(sf.get("findings", []))
                if (f["on_crown_path"] or f["from_internet"]) and f["finding"] not in sup
            ],
            "deprioritised": [
                {"finding": f["finding"], "reason": "critical, but enables no attack step"}
                for f in _dicts(sf.get("critical_without_attack_step", []))
            ],
            "suppressed": [
                {"finding": f, "acceptance": (s["live_acceptances"] or [None])[0]}
                for f, s in sup.items()
            ],
            "reasoning": "Stub policy: investigate every finding on a crown-jewel path or "
            "reachable from the Internet, minus live risk acceptances.",
        }

    # -------------------------------------------------------- pathfinder
    def _pathfinder(self, ctx, res):
        if "attack_paths" not in res:
            return [
                _call("attack_paths", target_id=c["id"], k=10) for c in ctx.get("crown_jewels", [])
            ] or [_call("attack_paths", k=10)]
        if "why_step" not in res:
            paths = _dicts(res["attack_paths"]["data"]["paths"])
            if paths and paths[0]["steps"]:
                return [_call("why_step", edge_key=paths[0]["steps"][0]["key"])]
        return self._pathfinder_final(ctx, res)

    def _pathfinder_final(self, ctx, res):
        ranked, keys = [], []
        paths = _dicts((res.get("attack_paths") or {}).get("data", {}).get("paths", []))
        for i, p in enumerate(paths):
            for s in _dicts(p["steps"]):
                tok = s["fix_token"]
                if ":finding:" in tok and tok not in [r["finding"] for r in ranked]:
                    ranked.append({"finding": tok, "why": f"On path #{i + 1} to {p['target']}."})
        if "why_step" in res:
            keys.append(res["why_step"]["data"]["key"])
        return {"ranked": ranked, "key_steps": keys, "reasoning": "Stub: ranked in path order."}

    # ------------------------------------------------------------- fixer
    def _fixer(self, ctx, res):
        if "min_cut" not in res:
            return [_call("min_cut", mode="fewest"), _call("min_cut", mode="cheapest")]
        fewest = _fewest(res)
        if "owners" not in res and fewest:
            assets = []
            for f in _dicts(fewest["fixes"]):
                a = f.get("asset") or (f.get("from") if ":asset:" in str(f.get("from")) else None)
                if a and a not in assets:
                    assets.append(a)
            calls = [_call("owners", asset_id=a) for a in assets[:6]]
            entry = next((f["asset"] for f in _dicts(fewest["fixes"]) if f.get("asset")), None)
            if entry:
                calls.append(_call("decision_trail", asset_id=entry))
            if calls:
                return calls
        if "simulate_fix" not in res and fewest:
            return [_call("simulate_fix", fix_tokens=fewest["fix_tokens"])]
        return self._fixer_final(ctx, res)

    def _fixer_final(self, ctx, res):
        fewest = _fewest(res) or {"fix_tokens": [], "fixes": []}
        return {
            "chosen": "fewest",
            "fix_tokens": fewest["fix_tokens"],
            "rationale": "Stub: the fewest-fixes cut, verified once with simulate_fix.",
            "tickets": [
                {"token": f["token"], "title": f"Fix: {f['action']}", "body": f["action"] + "."}
                for f in _dicts(fewest["fixes"])
            ],
        }

    # ---------------------------------------------------------- reporter
    def _reporter(self, ctx, res):
        return self._reporter_final(ctx, res)

    def _reporter_final(self, ctx, res):
        best = ctx.get("most_likely_path") or {}
        fp = ctx.get("fix_plan") or {}
        claims = []
        if best:
            claims.append(
                {
                    "text": f"The most likely path reaches {best['target']} "
                    f"in {len(best['steps'])} steps.",
                    "evidence": [best["target"], *(s["key"] for s in best["steps"])],
                }
            )
        tokens = [f["token"] for f in fp.get("fixes", [])]
        if tokens:
            claims.append({"text": f"{len(tokens)} fixes cut every path.", "evidence": tokens})
        claims.append(  # deliberately unsupported: the Reporter must drop it
            {"text": "A finding nobody scanned is critical.", "evidence": ["org_x:finding:99999"]}
        )
        return {
            "headline": "Stub report: attack paths found and cut.",
            "risk": "high",
            "claims": claims,
        }


# ----------------------------------------------------------------- helpers
def _call(name: str, **args) -> ToolCall:
    return ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name=name, arguments=args)


def _dicts(xs) -> list[dict]:
    """Trimmed lists end with a '... N more' string; keep the real items."""
    return [x for x in xs if isinstance(x, dict)]


def _context(messages: list[dict]) -> dict:
    text = messages[1]["content"]
    return json.loads(text[text.index("{") :])


def _results(messages: list[dict]) -> dict[str, dict]:
    """tool name -> its latest successful result in this conversation; min_cut
    is kept per mode (min_cut:fewest, min_cut:cheapest), the fake needs both."""
    names = {}
    for m in messages:
        for tc in m.get("tool_calls") or []:
            names[tc["id"]] = tc["function"]["name"]
    out: dict[str, dict] = {}
    for m in messages:
        if m.get("role") != "tool":
            continue
        body = json.loads(m["content"].removeprefix(INJECTION_NOTE))
        if "error" not in body:
            name = names.get(m["tool_call_id"], m.get("name"))
            out[name] = body
            if name == "min_cut":
                out[f"min_cut:{body['data'].get('mode')}"] = body
    return out


def _fewest(res: dict) -> dict | None:
    return (res.get("min_cut:fewest") or {}).get("data")
