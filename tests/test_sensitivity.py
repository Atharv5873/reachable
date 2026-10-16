"""S9: crown jewels carry a sensitivity tier, which reorders priority and nothing else.

* every org has crown jewels of at least two tiers, and at least one org has a
  cross-tier case inside the oracle's top 10 (a route to a lower-tier store ranks
  below a route to a higher-tier one), which the ranker reproduces;
* every crown-path finding still outranks every decoy;
* the attack paths and the min cut are exactly what they were with one crown
  jewel per org: fingerprints taken from the pre-S9 generator, crown jewel ids
  normalised (only the target of some routes' last hop moved).
"""

from __future__ import annotations

import hashlib
import json
import math

from conftest import ORGS, TEST_SCALE, TEST_SEED

from reachable_graph.criticality import CrownPath, rank_by_criticality, sensitivity_weight
from reachable_orggen.build import drift_org
from reachable_orggen.generate import GenConfig
from reachable_orggen.model import CROWN_TIERS, SENSITIVITY_WEIGHT

# (oracle path count, path-set hash, min-cut size, min-cut hash) per org and scan,
# computed with the generator at 3b541fc (S8: one crown jewel per org).
PRE_S9 = {
    ("org_a", "v1"): (9, "e66f58b366ba", 7, "4aa7db72edf7"),
    ("org_a", "v2"): (9, "6d456dcecc2c", 7, "a05935e4e278"),
    ("org_b", "v1"): (4, "305b7fcc205d", 4, "c6af52328693"),
    ("org_b", "v2"): (4, "bb8dc1f7e8b6", 4, "17f64f6e7d9c"),
    ("org_c", "v1"): (6, "46f4e7fd5240", 5, "f985a167e2a7"),
    ("org_c", "v2"): (6, "305c68b3d2c1", 5, "64d1209598c8"),
}


def fingerprint(ob) -> tuple[int, str, int, str]:
    crown = {d.id for d in ob.dataset.datastores if d.crown_jewel}

    def norm(s: str) -> str:
        for c in crown:
            s = s.replace(c, "CROWN")
        return s

    paths = sorted(
        json.dumps([[h.rule, norm(h.src), norm(h.dst), norm(h.fix)] for h in hops])
        for plist in ob.oracle.paths.values()
        for hops in plist
    )
    cut = sorted(norm(t) for t in ob.oracle.min_cut)

    def h(x) -> str:
        return hashlib.sha256(json.dumps(x).encode()).hexdigest()[:12]

    return len(paths), h(paths), len(cut), h(cut)


def tiers_through(ob) -> dict[str, set[str]]:
    """Finding id -> the tiers of the crown jewels its crown paths end at."""
    tier = {f"ds:{d.id}": d.sensitivity for d in ob.dataset.datastores if d.crown_jewel}
    out: dict[str, set[str]] = {}
    for c, plist in ob.oracle.paths.items():
        for hops in plist:
            for h in hops:
                if ":finding:" in h.fix:
                    out.setdefault(h.fix, set()).add(tier[c])
    return out


def test_every_org_has_crown_jewels_of_two_tiers_or_more(builds):
    for org, ob in builds.items():
        crown = [d for d in ob.dataset.datastores if d.crown_jewel]
        tiers = {d.sensitivity for d in crown}
        assert tiers <= set(CROWN_TIERS) and len(tiers) >= 2, (org, tiers)
        assert len(crown) == len(tiers)  # one crown jewel per tier
        gt = ob.ground_truth
        assert gt.crown_tiers == {f"ds:{d.id}": d.sensitivity for d in crown}
        # every crown jewel is the target of some planted route
        assert {p.target for p in gt.paths} == set(gt.crown_jewels), org


def test_crown_tiers_outrank_every_decoy(builds):
    assert min(SENSITIVITY_WEIGHT[t] for t in CROWN_TIERS) > 0
    for org, ob in builds.items():
        pri = ob.oracle.finding_priority
        on_path = [pri[f] for f in tiers_through(ob)]
        decoys = [pri[f] for d in ob.ground_truth.decoys for f in d.finding_ids]
        assert min(on_path) > 0 and max(decoys) == 0, org


def test_a_cross_tier_case_inside_the_top_10_and_the_ranker_agrees(builds):
    """Some org has two findings, each on routes to ONE tier, both in the oracle's
    top 10, the higher tier's ranked above the lower's; the ranker's weights
    (fixed in S8, different numbers) order them the same way."""
    cases = []
    for org, ob in builds.items():
        pri = ob.oracle.finding_priority
        top10 = sorted(pri, key=lambda f: -pri[f])[:10]
        through = tiers_through(ob)
        weight = SENSITIVITY_WEIGHT
        single = {f: next(iter(t)) for f, t in through.items() if len(t) == 1 and f in top10}
        for hi, t_hi in single.items():
            for lo, t_lo in single.items():
                if weight[t_hi] > weight[t_lo] and pri[hi] > pri[lo]:
                    cases.append((org, hi, lo))
    assert cases, "no org has a cross-tier ordering case in its top 10"

    for org, hi, lo in cases:
        ob = builds[org]
        tier = {f"ds:{d.id}": d.sensitivity for d in ob.dataset.datastores if d.crown_jewel}
        paths = [
            CrownPath(
                c,
                sensitivity_weight(tier[c]),
                math.prod(h.likelihood for h in hops),
                tuple(h.fix for h in hops),
                hops[0].fix,
            )
            for c, plist in ob.oracle.paths.items()
            for hops in plist
        ]
        order = [c.token for c in rank_by_criticality(paths)]
        assert order.index(hi) < order.index(lo), (org, hi, lo)


def test_paths_and_min_cut_are_unchanged_by_the_tiers(builds):
    cfg = GenConfig(scale=TEST_SCALE)
    for org in ORGS:
        assert fingerprint(builds[org]) == PRE_S9[(org, "v1")], org
        v2, _ = drift_org(org, TEST_SEED, cfg)
        assert fingerprint(v2) == PRE_S9[(org, "v2")], org
