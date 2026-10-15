"""Orchestration: generate an org end-to-end and compute its ground truth.

generate_org  -> background + planted paths/decoys, then run the oracle to fill
                 the min-cut and finding-priority ground truth and validate.
drift_org     -> scan v2: same org a week later with some fixes applied (one of
                 them on a planted path, which disappears), some new findings,
                 and ONE config change that opens ONE new path.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass

from .catalog import Catalog
from .company import plant_company
from .generate import GenConfig, generate_background
from .ground_truth import GroundTruth, PlantedPath
from .memory_seed import seed_memory
from .model import Dataset
from .oracle import OracleResult, run_oracle
from .planters import DB, Planter, Spine, plant_org


@dataclass
class OrgBuild:
    dataset: Dataset
    ground_truth: GroundTruth
    oracle: OracleResult


def _finalise(ds: Dataset, gt: GroundTruth) -> OracleResult:
    """Run the oracle and copy its min-cut + finding priority into the labels."""
    res = run_oracle(ds)
    gt.min_cut = res.min_cut
    gt.finding_priority = res.finding_priority
    return res


def generate_org(org: str, seed: int, cfg: GenConfig) -> OrgBuild:
    catalog = Catalog()
    b = generate_background(org, seed, cfg, catalog)
    gt = plant_org(b, catalog)
    plant_company(b, gt)
    seed_memory(b, gt)
    res = _finalise(b.ds, gt)
    return OrgBuild(dataset=b.ds, ground_truth=gt, oracle=res)


def drift_org(org: str, seed: int, cfg: GenConfig) -> tuple[OrgBuild, PlantedPath]:
    """Build scan v2: identical to v1, then apply a deterministic week-later drift.

    Returns the v2 build and the single NEW path the config change opened.
    """
    catalog = Catalog()
    b = generate_background(org, seed, cfg, catalog)
    bg_software = list(b.ds.software)  # before planting: never touch a planted spine
    gt = plant_org(b, catalog)
    plant_company(b, gt)
    seed_memory(b, gt)

    drng = random.Random(f"{org}:{seed}:drift")

    # 1. Some fixes applied: close a handful of open background findings...
    open_findings = [f for f in b.ds.findings if f.status == "open"]
    for f in drng.sample(open_findings, min(20, len(open_findings))):
        f.status = "fixed"

    # ...and the web team patched the entry point of the easy planted path. Every
    # path that depended on that finding must disappear from v2 (the oracle and
    # the Cypher derivation both ignore fixed findings).
    easy = next(p for p in gt.paths if p.name == "easy_web_db")
    entry = easy.hops[0].dst.split(":", 1)[1]  # "asset:<id>" -> "<id>"
    on = {e.src for e in b.ds.edges if e.type == "ON" and e.dst == entry}
    patched = [f for f in b.ds.findings if f.id in on]
    for f in patched:
        f.status = "fixed"
    gt.fixed_findings = sorted(f.id for f in patched)

    # 2. Some new findings since last week (new CVEs on existing background
    #    software). A CVE the software already has is not a new finding: a
    #    rescan reports one finding per (host, CVE), so skip it.
    for sw in drng.sample(bg_software, min(15, len(bg_software))):
        rec = catalog.pick(drng, f"{sw.vendor}:{sw.product}")
        if rec is None or f"{sw.id}:{rec.id}" in b._vulns:
            continue
        # Attach to one asset running this software.
        on = next((e.src for e in b.ds.edges if e.type == "RUNS" and e.dst == sw.id), None)
        if on is None:
            continue
        asset = b.by_id[on]
        vuln = b.add_vuln(sw, rec)
        b.add_finding(asset, vuln)

    # 3. ONE config change opens ONE new path: a fresh spine to the crown jewel.
    crown = next(d for d in b.ds.datastores if d.crown_jewel)
    p = Planter(b, catalog)
    s = Spine("v2_new_path", "medium")
    web = p._asset(b.shape.exposed_zone, "web_server")
    p.start_public(s, web, medium=True)
    dbhost = p._asset(b.shape.crown_zone, "db_host")
    p.remote(s, web, dbhost, products=DB)
    sec = b.secret("db_password")
    p.creds(s, p._node("asset", dbhost), dbhost, sec)
    p.db_unlock(s, sec, crown)
    s.path.target = f"ds:{crown.id}"

    # The planted paths through the patched entry are gone in v2.
    gt.removed_paths = [p.name for p in gt.paths if p.hops[0].dst == easy.hops[0].dst]
    gt.paths = [p for p in gt.paths if p.name not in gt.removed_paths] + [s.path]

    res = _finalise(b.ds, gt)
    return OrgBuild(dataset=b.ds, ground_truth=gt, oracle=res), s.path


# --- determinism hash ------------------------------------------------------
def dataset_hash(ds: Dataset) -> str:
    """Stable content hash of a Dataset (nodes + edges), for the determinism test."""
    payload = {
        "assets": sorted((a.id, a.kind, a.zone, a.env, a.hostname, a.cloud) for a in ds.assets),
        "software": sorted((s.id, s.vendor, s.product, s.version) for s in ds.software),
        "vulns": sorted((v.id, v.cve, v.cvss, v.av) for v in ds.vulns),
        "findings": sorted((f.id, f.scanner, f.first_seen, f.status) for f in ds.findings),
        "identities": sorted((i.id, i.kind, i.name, i.over_broad) for i in ds.identities),
        "secrets": sorted((s.id, s.kind, s.requires_priv) for s in ds.secrets),
        "datastores": sorted((d.id, d.kind, d.crown_jewel, d.sensitivity) for d in ds.datastores),
        "controls": sorted((c.id, c.kind) for c in ds.controls),
        "persons": sorted((p.id, p.name, p.role) for p in ds.persons),
        "teams": sorted((t.id, t.name, t.change_effort) for t in ds.teams),
        "oncalls": sorted((o.id, o.window, o.current) for o in ds.oncalls),
        "adrs": sorted((a.id, a.title, a.decision, a.date) for a in ds.adrs),
        "tickets": sorted((t.id, t.title, t.status, t.opened) for t in ds.tickets),
        "memory": sorted(
            (o.id, json.dumps(vars(o), sort_keys=True))
            for lst in (
                ds.runs,
                ds.steps,
                ds.triages,
                ds.verdicts,
                ds.risk_acceptances,
                ds.patterns,
                ds.techniques,
                ds.playbooks,
            )
            for o in lst
        ),
        "edges": sorted(
            (e.src, e.dst, e.type, json.dumps(e.props, sort_keys=True)) for e in ds.edges
        ),
    }
    blob = json.dumps(payload, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()
