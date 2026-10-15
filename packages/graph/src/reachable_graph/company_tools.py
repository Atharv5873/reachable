"""Company-layer tools (Track 03): ownership, on-call, decision trails, fix history.

Same contract as every other tool in tools.py: Pydantic-validated input, only
GRAPH.RO_QUERY through GraphTools._q, a ToolResult whose evidence ids all exist
in the graph. Mixed into GraphTools so they share its connection, org
allowlist, timeout and query log.

Why this is a graph question and not a document search: the ADR, the ticket
and the rota are nodes wired to the very Asset / Finding the security tools
talk about. "Why is 443 open on gw-01 and who approved it?" is one traversal
    (:Internet)-[:EXPOSES]->(a)<-[:CHANGED]-(adr:ADR)-[:APPROVED_BY]->(p:Person)
and the answer carries the ADR id, so a human can open the source.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .models import (
    CompanyQueryInput,
    DecisionTrailInput,
    EdgeRef,
    Evidence,
    FixHistoryParams,
    OwnersInput,
    QueryLog,
    ToolResult,
    WhoApprovedParams,
    WhoIsOnCallParams,
    WhoOwnsParams,
    WhyExposedParams,
)


def _day(ts: int | None) -> str | None:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d") if ts else None


class CompanyToolsMixin:
    """Requires the host class to provide _org, _q, _node (see GraphTools)."""

    # ================================================================ owners
    def owners(self, org: str, asset_id: str) -> ToolResult:
        """Owning team(s) of an asset or data store, their members, and who is on call now."""
        inp = OwnersInput(org=org, asset_id=asset_id)
        g, qlog = self._org(inp.org), []
        node = self._owned_node(g, inp.asset_id, qlog)
        teams = self._owning_teams(g, node, qlog)
        members = self._members(g, [t["id"] for t in teams], qlog)
        oncall = self._on_call(g, [t["id"] for t in teams], qlog)
        ev = Evidence(node_ids=[inp.asset_id])
        for t in teams:
            ev.node_ids.append(t["id"])
            ev.edges.append(EdgeRef(src=t["id"], rel="OWNS", dst=inp.asset_id))
            for m in members.get(t["id"], []):
                ev.node_ids.append(m["id"])
                ev.edges.append(EdgeRef(src=m["id"], rel="MEMBER_OF", dst=t["id"]))
            for oc in oncall.get(t["id"], []):
                ev.node_ids += [oc["oncall"], oc["person"]]
                ev.edges.append(EdgeRef(src=oc["oncall"], rel="FOR", dst=t["id"]))
                ev.edges.append(EdgeRef(src=oc["person"], rel="ON_CALL", dst=oc["oncall"]))
        ev.node_ids = list(dict.fromkeys(ev.node_ids))
        name = node["name"]
        if teams:
            parts = []
            for t in teams:
                oc = oncall.get(t["id"])
                who = f"{oc[0]['name']} ({oc[0]['role']})" if oc else "nobody"
                parts.append(
                    f"{t['name']} ({len(members.get(t['id'], []))} people; on call now: {who})"
                )
            summary = f"{name} is owned by " + "; ".join(parts) + "."
        else:
            summary = f"{name} has no owning team recorded: route to the security team."
        return ToolResult(
            summary=summary,
            data={
                "asset": node,
                "teams": [
                    {
                        **t,
                        "members": members.get(t["id"], []),
                        "on_call": (oncall.get(t["id"]) or [None])[0],
                    }
                    for t in teams
                ],
            },
            evidence=ev,
            queries=qlog,
        )

    def _owned_node(self, g: str, node_id: str, qlog: list[QueryLog]) -> dict:
        from .tools import ToolError

        n = self._node(g, node_id, qlog)
        if not {"Asset", "DataStore"} & set(n["labels"]):
            raise ToolError(f"{node_id!r} is not an Asset or DataStore")
        p = n["props"]
        return {
            "id": node_id,
            "label": "Asset" if "Asset" in n["labels"] else "DataStore",
            "name": p.get("hostname") or f"{p.get('kind')} {node_id}",
            "kind": p.get("kind"),
            "zone": p.get("zone"),
        }

    def _owning_teams(self, g: str, node: dict, qlog) -> list[dict]:
        rows = self._q(
            g,
            f"""
            MATCH (t:Team)-[:OWNS]->(a:{node["label"]} {{id: $id}})
            RETURN t.id, t.name, t.change_effort ORDER BY t.id
            """,
            {"id": node["id"]},
            qlog,
        )
        return [{"id": i, "name": n, "change_effort": e} for i, n, e in rows]

    def _members(self, g: str, team_ids: list[str], qlog) -> dict[str, list[dict]]:
        if not team_ids:
            return {}
        rows = self._q(
            g,
            """
            MATCH (t:Team) WHERE t.id IN $teams
            MATCH (p:Person)-[:MEMBER_OF]->(t)
            RETURN t.id, p.id, p.name, p.role ORDER BY t.id, p.id
            """,
            {"teams": team_ids},
            qlog,
        )
        out: dict[str, list[dict]] = {}
        for tid, pid, name, role in rows:
            out.setdefault(tid, []).append({"id": pid, "name": name, "role": role})
        return out

    def _on_call(self, g: str, team_ids: list[str], qlog) -> dict[str, list[dict]]:
        """The person in each team's CURRENT rotation slot."""
        if not team_ids:
            return {}
        rows = self._q(
            g,
            """
            MATCH (t:Team) WHERE t.id IN $teams
            MATCH (oc:OnCall {current: true})-[:FOR]->(t)
            MATCH (p:Person)-[:ON_CALL]->(oc)
            RETURN t.id, oc.id, oc.window, p.id, p.name, p.role ORDER BY t.id
            """,
            {"teams": team_ids},
            qlog,
        )
        out: dict[str, list[dict]] = {}
        for tid, oc, window, pid, name, role in rows:
            out.setdefault(tid, []).append(
                {"oncall": oc, "window": window, "person": pid, "name": name, "role": role}
            )
        return out

    # ========================================================= decision_trail
    def decision_trail(
        self,
        org: str,
        asset_id: str | None = None,
        hostname: str | None = None,
        port: int | None = None,
    ) -> ToolResult:
        """The ADRs that changed an asset (optionally about one port), with approver
        and date, next to the asset's live exposure and Internet attack steps."""
        inp = DecisionTrailInput(org=org, asset_id=asset_id, hostname=hostname, port=port)
        g, qlog = self._org(inp.org), []
        aid = self._resolve_asset(g, inp.asset_id, inp.hostname, qlog)
        host = self._node(g, aid, qlog)["props"].get("hostname", aid)

        # The optional port narrows the trail. Two fixed query texts (never a
        # value spliced in): with a port the filter is a parameter.
        port_filter = "WHERE adr.port = $port" if inp.port is not None else ""
        rows = self._q(
            g,
            f"""
            MATCH (a:Asset {{id: $id}})
            MATCH (adr:ADR)-[:CHANGED]->(a) {port_filter}
            MATCH (adr)-[:APPROVED_BY]->(p:Person)
            OPTIONAL MATCH (p)-[:MEMBER_OF]->(t:Team)
            RETURN adr.id, adr.title, adr.decision, adr.date, adr.status, adr.port, adr.cidr,
                   p.id, p.name, p.role, t.id, t.name
            ORDER BY adr.date, adr.id
            """,
            {"id": aid, "port": inp.port},
            qlog,
        )
        decisions = [
            {
                "adr": r[0],
                "title": r[1],
                "decision": r[2],
                "date": _day(r[3]),
                "status": r[4],
                "port": r[5],
                "cidr": r[6],
                "approved_by": {"id": r[7], "name": r[8], "role": r[9]},
                "approver_team": {"id": r[10], "name": r[11]} if r[10] else None,
            }
            for r in rows
        ]
        exposed = sorted(
            r[0]
            for r in self._q(
                g,
                "MATCH (:Internet)-[x:EXPOSES]->(a:Asset {id: $id}) RETURN DISTINCT x.port",
                {"id": aid},
                qlog,
            )
        )
        steps = self._q(
            g,
            """
            MATCH (:Internet)-[e:ATTACK_STEP]->(a:Asset {id: $id})
            RETURN e.key, e.fix_token, e.likelihood ORDER BY e.likelihood DESC
            """,
            {"id": aid},
            qlog,
        )
        ev = Evidence(node_ids=[aid])
        for d in decisions:
            ev.node_ids += [d["adr"], d["approved_by"]["id"]]
            ev.edges.append(EdgeRef(src=d["adr"], rel="CHANGED", dst=aid))
            ev.edges.append(EdgeRef(src=d["adr"], rel="APPROVED_BY", dst=d["approved_by"]["id"]))
            if d["approver_team"]:
                ev.node_ids.append(d["approver_team"]["id"])
                ev.edges.append(
                    EdgeRef(
                        src=d["approved_by"]["id"], rel="MEMBER_OF", dst=d["approver_team"]["id"]
                    )
                )
        if exposed:
            ev.node_ids.insert(0, "internet")
            ev.edges.append(EdgeRef(src="internet", rel="EXPOSES", dst=aid))
        for key, _, _ in steps:
            ev.edges.append(EdgeRef(src="internet", rel="ATTACK_STEP", dst=aid, key=key))
        ev.node_ids = list(dict.fromkeys(ev.node_ids))

        where = f"{host}" + (f":{inp.port}" if inp.port else "")
        if decisions:
            d = decisions[-1]
            a = d["approved_by"]
            team = f", {d['approver_team']['name']}" if d["approver_team"] else ""
            summary = (
                f"{len(decisions)} decision(s) on {where}. Latest: {d['title']} "
                f"({d['date']}), approved by {a['name']} ({a['role']}{team}). {d['decision']}"
            )
        else:
            summary = f"No recorded decision for {where}: an undocumented change."
        if exposed:
            summary += f" Exposed to the Internet on {exposed}"
            summary += (
                f"; exploitable from the Internet via {len(steps)} attack step(s)."
                if steps
                else "; no exploitable step from the Internet."
            )
        return ToolResult(
            summary=summary,
            data={
                "asset": aid,
                "hostname": host,
                "port": inp.port,
                "decisions": decisions,
                "exposed_ports": exposed,
                "internet_attack_steps": [
                    {"key": k, "fix_token": t, "likelihood": lk} for k, t, lk in steps
                ],
            },
            evidence=ev,
            queries=qlog,
        )

    def _resolve_asset(self, g: str, asset_id: str | None, hostname: str | None, qlog) -> str:
        from .tools import ToolError, label_of

        if asset_id:
            if label_of(asset_id) != "Asset":
                raise ToolError(f"{asset_id!r} is not an Asset id")
            self._node(g, asset_id, qlog)
            return asset_id
        rows = self._q(
            g, "MATCH (a:Asset {hostname: $h}) RETURN a.id LIMIT 2", {"h": hostname}, qlog
        )
        if len(rows) != 1:
            raise ToolError(f"hostname {hostname!r} matches {len(rows)} assets in {g}")
        return rows[0][0]

    # ========================================================== company_query
    def company_query(self, org: str, question_kind: str, params: dict | None = None) -> ToolResult:
        """One of a FIXED set of company-brain intents (no free text to Cypher)."""
        inp = CompanyQueryInput(org=org, question_kind=question_kind, params=params or {})
        p = inp.typed_params()
        if isinstance(p, WhoOwnsParams):
            r = self.owners(inp.org, p.asset_id)
            teams = r.data["teams"]
            answer = ", ".join(t["name"] for t in teams) if teams else "no owner recorded"
        elif isinstance(p, WhoIsOnCallParams):
            r = self._on_call_result(inp.org, p)
            answer = r.data["answer"]
        elif isinstance(p, WhyExposedParams | WhoApprovedParams):
            r = self.decision_trail(inp.org, p.asset_id, p.hostname, p.port)
            ds = r.data["decisions"]
            if not ds:
                answer = "no recorded decision"
            elif isinstance(p, WhyExposedParams):
                answer = f"{ds[-1]['adr']}: {ds[-1]['decision']}"
            else:
                answer = "; ".join(
                    f"{d['approved_by']['name']} ({d['approved_by']['role']}) on {d['date']} "
                    f"[{d['adr']}]"
                    for d in ds
                )
        elif isinstance(p, FixHistoryParams):
            r = self._fix_history(inp.org, p.asset_id)
            answer = r.data["answer"]
        else:  # pragma: no cover - COMPANY_INTENTS and this dispatch move together
            raise AssertionError(inp.question_kind)
        r.data = {
            "question_kind": inp.question_kind,
            "params": p.model_dump(),
            "answer": answer,
            **r.data,
        }
        r.summary = f"[{inp.question_kind}] {r.summary}"
        return r

    def _on_call_result(self, org: str, p: WhoIsOnCallParams) -> ToolResult:
        g, qlog = self._org(org), []
        ev = Evidence()
        if p.asset_id:
            node = self._owned_node(g, p.asset_id, qlog)
            teams = self._owning_teams(g, node, qlog)
            ev.node_ids.append(p.asset_id)
            ev.edges += [EdgeRef(src=t["id"], rel="OWNS", dst=p.asset_id) for t in teams]
        else:
            n = self._node(g, p.team_id, qlog)
            teams = [{"id": p.team_id, "name": n["props"].get("name")}]
        oncall = self._on_call(g, [t["id"] for t in teams], qlog)
        rota = []
        for t in teams:
            ev.node_ids.append(t["id"])
            for oc in oncall.get(t["id"], []):
                rota.append({"team": t["id"], "team_name": t["name"], **oc})
                ev.node_ids += [oc["oncall"], oc["person"]]
                ev.edges.append(EdgeRef(src=oc["oncall"], rel="FOR", dst=t["id"]))
                ev.edges.append(EdgeRef(src=oc["person"], rel="ON_CALL", dst=oc["oncall"]))
        ev.node_ids = list(dict.fromkeys(ev.node_ids))
        answer = (
            "; ".join(f"{o['name']} ({o['team_name']}, {o['window']})" for o in rota)
            or "nobody on call"
        )
        return ToolResult(
            summary=f"On call now: {answer}.",
            data={"answer": answer, "on_call": rota},
            evidence=ev,
            queries=qlog,
        )

    def _fix_history(self, org: str, asset_id: str) -> ToolResult:
        g, qlog = self._org(org), []
        node = self._owned_node(g, asset_id, qlog)
        rows = self._q(
            g,
            """
            MATCH (a:Asset {id: $id})
            MATCH (f:Finding)-[:ON]->(a)
            MATCH (t:Ticket)-[:FIXES]->(f)
            MATCH (f)-[:OF]->(v:Vuln)
            RETURN t.id, t.title, t.status, t.opened, t.closed, f.id, f.status, v.cve
            ORDER BY t.opened, t.id
            """,
            {"id": asset_id},
            qlog,
        )
        tickets = [
            {
                "ticket": r[0],
                "title": r[1],
                "status": r[2],
                "opened": _day(r[3]),
                "closed": _day(r[4]),
                "finding": r[5],
                "finding_status": r[6],
                "cve": r[7],
            }
            for r in rows
        ]
        ev = Evidence(node_ids=[asset_id])
        for t in tickets:
            ev.node_ids += [t["ticket"], t["finding"]]
            ev.edges.append(EdgeRef(src=t["ticket"], rel="FIXES", dst=t["finding"]))
            ev.edges.append(EdgeRef(src=t["finding"], rel="ON", dst=asset_id))
        ev.node_ids = list(dict.fromkeys(ev.node_ids))
        answer = (
            "; ".join(f"{t['ticket']} {t['status']}: {t['title']}" for t in tickets) or "no tickets"
        )
        return ToolResult(
            summary=f"{len(tickets)} ticket(s) on findings of {node['name']}: {answer}.",
            data={"answer": answer, "tickets": tickets},
            evidence=ev,
            queries=qlog,
        )
