"""Seed a little prior agent memory into each org (clearly synthetic).

A memory layer that starts empty can't show anything on the first demo run, and
S5 needs a baseline to measure "memory lift" against. So each org starts with:

  * episodic: one earlier triage Run (three ordered AgentSteps), two Triage
    sessions, two Verdicts on the decoys, and two RiskAcceptances:
      - LIVE   on the WAF-mitigated decoy (expires mid-2027);
      - EXPIRED on the entry finding of the medium planted path. It expired,
        so it must NOT suppress that finding, which sits on a crown-jewel path.
  * semantic: one Pattern, "golden image keeps reintroducing CVE-X", ABOUT the
    Software and Vuln nodes carrying the org's most repeated CVE, SEEN_IN both
    triages.
  * procedural: starter Playbooks for the two most common techniques: T1190 at
    version 2 (v2 SUPERSEDES v1, v1 kept) and T1210 at version 1.

Same schema the runtime uses (reachable_graph.memory); a test reads this seed
back through the repository, so the two cannot drift apart.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime

from .company import DAY, SECURITY_LEAD
from .generate import NOW, Builder
from .ground_truth import GroundTruth
from .model import (
    AgentStep,
    Pattern,
    Playbook,
    RiskAcceptance,
    Run,
    Technique,
    Triage,
    Verdict,
)

# Far enough ahead to stay live whatever "now" a reader uses (the synthetic
# 2024 clock or the real one), and an unambiguous past date for the expired one.
LIVE_UNTIL = int(datetime(2027, 6, 30, tzinfo=UTC).timestamp())

PLAYBOOKS = {
    "T1190": (
        "Exploit Public-Facing Application",
        [
            "1. Confirm the finding is reachable from the Internet (attack_paths).\n"
            "2. Patch or upgrade the exposed service.\n"
            "3. If a patch is not possible this week, put a WAF virtual patch in front.",
            "1. Confirm the finding is reachable from the Internet (attack_paths).\n"
            "2. Check the decision trail: is the exposure still needed? If not, close it.\n"
            "3. Patch or upgrade; verify with simulate_fix that the path is gone.\n"
            "4. If a patch must wait, WAF virtual patch + a dated RiskAcceptance.",
        ],
    ),
    "T1210": (
        "Exploitation of Remote Services",
        [
            "1. Find who can reach the service (CAN_REACH) and on which port.\n"
            "2. Patch the service, or tighten the firewall rule to the callers that need it.\n"
            "3. Re-run min_cut: one patched funnel can cut several paths.",
        ],
    ),
}


def _hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def seed_memory(b: Builder, gt: GroundTruth) -> None:
    ds = b.ds
    person = next(p for p in ds.persons if p.role == SECURITY_LEAD)
    findings_on: dict[str, list[str]] = {}
    for e in ds.edges:
        if e.type == "ON" and e.src.split(":")[1] == "finding":
            findings_on.setdefault(e.dst, []).append(e.src)

    # --- episodic: a past run and its triages -------------------------------
    run = Run(id=b._id("run"), started=NOW - 14 * DAY, kind="triage")
    ds.runs.append(run)
    prev = None
    for seq, (tool, args) in enumerate(
        [
            ("exposure_surface", {"org": b.org, "limit": 50}),
            ("attack_paths", {"org": b.org, "k": 5}),
            ("min_cut", {"org": b.org, "prefer": "entry"}),
        ]
    ):
        st = AgentStep(
            id=b._id("step"), tool=tool, input_hash=_hash(args), ts=run.started + 30 * seq, seq=seq
        )
        ds.steps.append(st)
        ds.add_edge(run.id, st.id, "HAS_STEP")
        if prev:
            ds.add_edge(prev.id, st.id, "NEXT")
        prev = st
    old = Triage(id=b._id("triage"), ts=NOW - 45 * DAY)  # a human's, before the agent
    recent = Triage(id=b._id("triage"), ts=run.started + 120)
    ds.triages += [old, recent]
    ds.add_edge(run.id, recent.id, "HAS_TRIAGE")

    decoy = {d.kind: d for d in gt.decoys}
    for d, decision, reason in (
        (
            decoy["severity"],
            "not_reachable",
            "Critical KEV vuln, but the host sits in the isolated quarantine zone: no route in.",
        ),
        (
            decoy["mitigated"],
            "accept_risk",
            "Exposed critical vuln is blocked by a WAF rule on this host; vendor fix scheduled.",
        ),
    ):
        v = Verdict(id=b._id("verdict"), decision=decision, reason=reason, ts=recent.ts)
        ds.verdicts.append(v)
        ds.add_edge(v.id, d.finding_ids[0], "ON")
        ds.add_edge(recent.id, v.id, "HAS_VERDICT")

    medium = next(p for p in gt.paths if p.name == "medium_start_web_db")
    medium_finding = findings_on[medium.hops[0].dst.split(":", 1)[1]][0]
    for fid, reason, created, expires in (
        (
            decoy["mitigated"].finding_ids[0],
            "WAF virtual patch in place; vendor fix lands with the next platform upgrade.",
            NOW - 30 * DAY,
            LIVE_UNTIL,
        ),
        (
            medium_finding,
            "Medium severity with extra monitoring; accepted until the Q4 upgrade.",
            NOW - 200 * DAY,
            NOW - 20 * DAY,
        ),
    ):
        ra = RiskAcceptance(
            id=b._id("riskacc"),
            reason=reason,
            approved_by=person.id,
            created=created,
            expires=expires,
        )
        ds.risk_acceptances.append(ra)
        ds.add_edge(ra.id, fid, "ON")
        ds.add_edge(ra.id, person.id, "APPROVED_BY")

    # --- semantic: the org's most repeated CVE keeps coming back ------------
    cve_count = Counter(v.cve for v in ds.vulns)
    cve, n = min(cve_count.items(), key=lambda kv: (-kv[1], kv[0]))
    vulns = sorted(v.id for v in ds.vulns if v.cve == cve)[:3]
    sw_of = {e.dst: e.src for e in ds.edges if e.type == "HAS_VULN"}
    software = sorted({sw_of[v] for v in vulns})
    sw = next(s for s in ds.software if s.id == software[0])
    product = sw.product if sw.vendor == sw.product else f"{sw.vendor} {sw.product}"
    pat = Pattern(
        id=b._id("pattern"),
        kind="recurring_cve",
        description=f"The {product} golden image keeps reintroducing {cve} "
        f"({n} instances in this org): patching hosts one by one does not stick, "
        "rebuild the image.",
        ts=recent.ts,
    )
    ds.patterns.append(pat)
    for x in software + vulns:
        ds.add_edge(pat.id, x, "ABOUT")
    for t in (old, recent):
        ds.add_edge(pat.id, t.id, "SEEN_IN")

    # --- procedural: versioned starter playbooks ----------------------------
    for tid, (name, versions) in PLAYBOOKS.items():
        ds.techniques.append(Technique(id=tid, name=name))
        older = None
        for i, body in enumerate(versions, start=1):
            pb = Playbook(
                id=f"{b.org}:playbook:{tid}:v{i}",
                technique=tid,
                version=i,
                body=body,
                ts=NOW - (300 - 260 * (i - 1)) * DAY,
            )
            ds.playbooks.append(pb)
            ds.add_edge(tid, pb.id, "HANDLED_BY")
            if older:
                ds.add_edge(pb.id, older.id, "SUPERSEDES")
            older = pb
