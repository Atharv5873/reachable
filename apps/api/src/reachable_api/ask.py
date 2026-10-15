"""POST /orgs/{org}/ask: an English question -> ONE fixed company-brain intent.

There is no free text to Cypher anywhere. The question is mapped to one of
company_query's five intents (who_owns, who_is_on_call, why_exposed,
who_approved, fix_history) plus the id it is about, and the typed tool answers
it. Two resolvers do the mapping:

* "llm": one small model call. The model sees the intents as an enum and a
  short list of the org's entities it may name (the assets decisions were
  made about, the hosts on crown-jewel paths, the teams), and must call a
  single function. Its choice is validated like any tool input; an id it
  invents is rejected, not trusted.
* "rules": keywords for the intent and word overlap against the same entity
  list. No model, so it is deterministic: replay mode and the video use it,
  and it is the fallback when no model answers.

The answer carries the tool's evidence (node ids and edges), with names
resolved, so the UI can link each piece back into the graph view.
"""

from __future__ import annotations

import re
import time
from typing import Any

from reachable_graph.models import COMPANY_INTENTS
from reachable_graph.tools import GraphTools, ToolError, label_of

INTENTS = list(COMPANY_INTENTS)
# Words that say what kind of question it is, not what it is about.
STOP = frozenset(
    re.findall(
        r"[a-z]+",
        """a an and approved approve are be by did for from has have how i in is it its me of on
        open opened or our port the this to was what when which who whom why with exposed
        exposure internet call oncall owns owner owned history fix fixed tickets ticket
        now right currently tell show""",
    )
)

ASK_TOOL = {
    "type": "function",
    "function": {
        "name": "company_query",
        "description": (
            "Answer a question about who owns, who is on call for, why something is "
            "exposed, who approved it, or the fix history of ONE asset or team."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "question_kind": {
                    "type": "string",
                    "enum": INTENTS,
                    "description": "who_owns | who_is_on_call | why_exposed (the decision "
                    "that opened it) | who_approved | fix_history (tickets)",
                },
                "entity_id": {
                    "type": "string",
                    "description": "The id of the asset or team, copied from the list.",
                },
                "port": {"type": "integer", "description": "A port, if the question names one."},
            },
            "required": ["question_kind", "entity_id"],
        },
    },
}


def entities(tools: GraphTools, graph: str) -> list[dict]:
    """What a question may be about: assets with a recorded decision, hosts
    that start an attack step from the Internet, and the teams. Each with the
    words that describe it (hostname, kind, ADR titles, team names)."""
    q = lambda c, p=None: tools._q(graph, c, p or {}, [])  # noqa: E731
    out: dict[str, dict] = {}
    for aid, host, kind, title, decision in q(
        """
        MATCH (d:ADR)-[:CHANGED]->(a:Asset)
        RETURN a.id, a.hostname, a.kind, d.title, d.decision
        """
    ):
        e = out.setdefault(aid, {"id": aid, "name": host, "kind": kind, "words": []})
        e["words"] += [title or "", decision or ""]
    for aid, host, kind in q(
        """
        MATCH (:Internet)-[:ATTACK_STEP]->(a:Asset)
        WHERE a:CrownPath
        RETURN DISTINCT a.id, a.hostname, a.kind
        """
    ):
        out.setdefault(aid, {"id": aid, "name": host, "kind": kind, "words": []})
    for aid, team in q(
        """
        MATCH (t:Team)-[:OWNS]->(a:Asset) WHERE a.id IN $ids
        RETURN a.id, t.name
        """,
        {"ids": list(out)},
    ):
        out[aid]["words"].append(f"team {team}")
    for tid, name in q("MATCH (t:Team) RETURN t.id, t.name ORDER BY t.id"):
        out[tid] = {"id": tid, "name": name, "kind": "team", "words": []}
    return list(out.values())


def _words(text: str) -> set[str]:
    toks = re.findall(r"[a-z0-9]+", text.lower().replace("_", " ").replace("-", " "))
    return {t for t in toks if t not in STOP and len(t) > 1}


def rule_intent(question: str) -> str:
    q = question.lower()
    if re.search(r"\bon[\s-]?call\b|\bpager\b|\bpage\b|\bpaged\b", q):
        return "who_is_on_call"
    if re.search(r"\bwhy\b", q) and re.search(r"expos|open|internet|reach|allow|stor|let", q):
        return "why_exposed"
    if re.search(r"approv|sign(ed)? off|authori[sz]", q):
        return "who_approved"
    if re.search(r"histor|ticket|patched before|fixed before|previous fix", q):
        return "fix_history"
    if re.search(r"\bown|responsible|whose\b", q):
        return "who_owns"
    return "why_exposed"


ID_RE = re.compile(r"[a-z0-9_]+:[a-z]+:\d+")
HOSTNAME_RE = re.compile(r"\b[a-z]+(?:-[a-z0-9]+)+-\d+\b")


def named_hosts(tools: GraphTools, graph: str, question: str) -> list[dict]:
    """Hostnames typed in the question, looked up in the whole graph (any asset,
    not only the listed ones). Unknown names come back with id None."""
    out = []
    for h in dict.fromkeys(HOSTNAME_RE.findall(question.lower())):
        rows = tools._q(
            graph, "MATCH (a:Asset {hostname: $h}) RETURN a.id, a.kind LIMIT 1", {"h": h}, []
        )
        out.append(
            {"id": rows[0][0] if rows else None, "name": h, "kind": rows[0][1] if rows else None}
        )
    return out


def rule_entity(question: str, ents: list[dict]) -> dict | None:
    q = question.lower()
    for e in ents:  # an exact hostname or id wins outright
        if e["name"] and e["name"].lower() in q or e["id"].lower() in q:
            return e
    qw = _words(question)
    scored = []
    for e in ents:
        kind_words = _words(e.get("kind") or "")
        name_words = _words(e.get("name") or "")
        text_words = _words(" ".join(e["words"]))
        score = 3 * len(qw & kind_words) + 2 * len(qw & name_words) + len(qw & text_words)
        if score:
            scored.append((score, e["kind"] != "team", e["id"], e))
    if not scored:
        return None
    scored.sort(key=lambda x: (-x[0], not x[1], x[2]))
    return scored[0][3]


def params_for(intent: str, entity_id: str, port: int | None) -> dict:
    is_team = label_of(entity_id) == "Team"
    if intent == "who_is_on_call":
        return {"team_id": entity_id} if is_team else {"asset_id": entity_id}
    if is_team:
        raise ToolError(f"{intent} is about an asset, not a team")
    if intent in ("why_exposed", "who_approved"):
        return {"asset_id": entity_id, **({"port": port} if port else {})}
    return {"asset_id": entity_id}


async def llm_resolve(llm, question: str, ents: list[dict]) -> tuple[str, str, int | None, dict]:
    listing = "\n".join(
        f"- entity_id={e['id']} | {e['name']} ({e['kind']})"
        + (f" | {'; '.join(w for w in e['words'] if w)[:160]}" if e["words"] else "")
        for e in ents
    )
    messages = [
        {
            "role": "system",
            "content": "Map the analyst's question to exactly one company_query call. "
            "entity_id is ONLY the id after 'entity_id=' on one of these lines "
            "(like org_a:asset:00001), never the rest of the line:\n" + listing,
        },
        {"role": "user", "content": question},
    ]
    reply = await llm.chat(messages, [ASK_TOOL], agent="ask", tool_choice="required")
    if not reply.tool_calls:
        raise ToolError("the model did not choose an intent")
    args = reply.tool_calls[0].arguments
    meta = {"model": reply.model, "ms": reply.ms, "tokens_in": reply.tokens_in}
    # Small models sometimes copy the whole line; the id is its first token.
    m = ID_RE.search(str(args.get("entity_id") or ""))
    return args.get("question_kind"), m.group(0) if m else None, args.get("port"), meta


async def answer(
    tools: GraphTools,
    graph: str,
    question: str,
    *,
    mode: str = "auto",
    llm=None,
    as_of: int | None = None,
    run_sync=None,
) -> dict[str, Any]:
    """Resolve the question to one intent, run company_query, return the answer
    with its evidence. `run_sync` runs blocking graph reads off the event loop."""
    import asyncio

    run_sync = run_sync or asyncio.to_thread
    t0 = time.perf_counter()
    ents = await run_sync(entities, tools, graph)
    hosts = await run_sync(named_hosts, tools, graph, question)
    missing = [h["name"] for h in hosts if h["id"] is None]
    if missing:
        return {
            "question": question,
            "resolved_by": "rules",
            "intent": None,
            "answer": None,
            "error": f"No asset named {', '.join(missing)} in this org.",
            "suggest": [e["name"] for e in ents if e["kind"] != "team"][:6],
            "note": None,
        }
    listed = {e["id"] for e in ents}
    ents += [{**h, "words": []} for h in hosts if h["id"] not in listed]
    known = {e["id"]: e for e in ents}
    m = re.search(r"\bport\s+(\d{1,5})\b|:(\d{1,5})\b", question.lower())
    rule_port = int(m.group(1) or m.group(2)) if m else None

    resolved_by, meta, note = "rules", {}, None
    intent = entity_id = port = None
    if mode in ("auto", "llm") and llm is not None:
        try:
            intent, entity_id, port, meta = await llm_resolve(llm, question, ents)
            if intent not in COMPANY_INTENTS or entity_id not in known:
                note = f"model chose {intent!r} / {entity_id!r}, not in the allowed lists"
                intent = entity_id = None
            else:
                resolved_by = "llm"
        except Exception as exc:  # noqa: BLE001 - any model failure falls back to rules
            note = f"model unavailable: {type(exc).__name__}"
    elif mode == "llm":
        note = "no model configured"
    if resolved_by == "rules":
        intent = rule_intent(question)
        e = rule_entity(question, ents)
        entity_id, port = (e["id"] if e else None), rule_port
    if not entity_id:
        return {
            "question": question,
            "resolved_by": resolved_by,
            "intent": intent,
            "answer": None,
            "error": "Could not tell which asset or team the question is about.",
            "suggest": [e["name"] for e in ents if e["kind"] != "team"][:6],
            "note": note,
        }
    if label_of(entity_id) == "Team" and intent != "who_is_on_call":
        intent = "who_is_on_call"  # the only intent a team can answer
    params = params_for(intent, entity_id, port)
    r = await run_sync(tools.company_query, graph, intent, params, as_of)
    if params.get("port") and not r.data.get("decisions"):
        # No decision opened that port: say so, and answer for the asset.
        asked = params.pop("port")
        r = await run_sync(tools.company_query, graph, intent, params, as_of)
        ports = r.data.get("exposed_ports") or []
        note = (
            f"No recorded decision opens port {asked} on {known[entity_id]['name']}"
            + (f"; it is exposed on {', '.join(map(str, ports))}" if ports else "")
            + ". These are the decisions on record for it."
        )
    ev = r.evidence
    names = await run_sync(_names, tools, graph, ev.node_ids)
    return {
        "question": question,
        "resolved_by": resolved_by,
        "intent": intent,
        "params": params,
        "entity": known.get(entity_id),
        "answer": r.data.get("answer"),
        "summary": r.summary,
        "data": r.data,
        "evidence": {
            "nodes": [
                {"id": i, **names.get(i, {"label": label_of(i), "name": i})} for i in ev.node_ids
            ],
            "edges": [e.model_dump() for e in ev.edges],
        },
        "queries": [q.model_dump() for q in r.queries],
        "llm": meta or None,
        "note": note,
        "ms": round((time.perf_counter() - t0) * 1000, 1),
    }


def _names(tools: GraphTools, graph: str, ids: list[str]) -> dict[str, dict]:
    out = {"internet": {"label": "Internet", "name": "Internet"}}
    for nid, n in tools._nodes(graph, [i for i in ids if i != "internet"], []).items():
        p = n["props"]
        label = n["labels"][0] if n["labels"] else label_of(nid)
        out[nid] = {
            "label": label,
            "name": p.get("hostname") or p.get("title") or p.get("name") or p.get("kind") or nid,
            "role": p.get("role"),
        }
    return out
