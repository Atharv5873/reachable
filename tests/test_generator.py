"""Generator determinism and CVE/Finding integrity."""

from __future__ import annotations

from conftest import ORGS, TEST_SCALE, TEST_SEED

from reachable_orggen.build import dataset_hash, drift_org, generate_org
from reachable_orggen.generate import GenConfig


def test_determinism_same_seed_same_hash():
    cfg = GenConfig(scale=TEST_SCALE)
    for org in ORGS:
        a = dataset_hash(generate_org(org, TEST_SEED, cfg).dataset)
        b = dataset_hash(generate_org(org, TEST_SEED, cfg).dataset)
        assert a == b, f"{org} not deterministic"


def test_different_seed_differs():
    cfg = GenConfig(scale=TEST_SCALE)
    a = dataset_hash(generate_org("org_a", TEST_SEED, cfg).dataset)
    b = dataset_hash(generate_org("org_a", TEST_SEED + 1, cfg).dataset)
    assert a != b


def test_every_finding_cve_affects_its_software_product(builds, snapshot_cves):
    """Finding -> OF -> Vuln(cve); the CVE must exist in threatintel and the
    Software the vuln sits on must run a product that CVE affects."""
    for org, ob in builds.items():
        ds = ob.dataset
        vuln_by_id = {v.id: v for v in ds.vulns}
        sw_by_id = {s.id: s for s in ds.software}
        # software -> vuln ids
        has_vuln: dict[str, list[str]] = {}
        for e in ds.edges:
            if e.type == "HAS_VULN":
                has_vuln.setdefault(e.src, []).append(e.dst)
        # vuln -> software (reverse)
        sw_of_vuln: dict[str, str] = {}
        for sw_id, vids in has_vuln.items():
            for vid in vids:
                sw_of_vuln[vid] = sw_id
        finding_of = {e.src: e.dst for e in ds.edges if e.type == "OF"}

        for vid in finding_of.values():
            v = vuln_by_id[vid]
            assert v.cve in snapshot_cves, f"{org}: {v.cve} not in snapshot"
            sw = sw_by_id[sw_of_vuln[vid]]
            product_id = f"{sw.vendor}:{sw.product}"
            affected = snapshot_cves[v.cve]["products"]
            assert product_id in affected, (
                f"{org}: {v.cve} does not affect {product_id} (affects {affected})"
            )


def test_realism_targets(builds):
    """Most assets are not internet-exposed; criticals are present."""
    for org, ob in builds.items():
        ds = ob.dataset
        exposed = {e.dst for e in ds.edges if e.type == "EXPOSES"}
        assert len(exposed) < len(ds.assets) * 0.5, f"{org}: too many exposed assets"
        crits = [v for v in ds.vulns if v.cvss >= 9.0]
        assert crits, f"{org}: no critical vulns"


def test_scan_v2_new_path_only_in_v2():
    cfg = GenConfig(scale=TEST_SCALE)
    for org in ORGS:
        v1 = generate_org(org, TEST_SEED, cfg)
        v2, new_path = drift_org(org, TEST_SEED, cfg)

        def seqs(ob):
            out = set()
            for plist in ob.oracle.paths.values():
                for hops in plist:
                    out.add(tuple([hops[0].src] + [h.dst for h in hops]))
            return out

        ns = tuple(new_path.node_sequence())
        assert ns in seqs(v2), f"{org}: v2 new path missing from v2 oracle"
        assert ns not in seqs(v1), f"{org}: v2 new path already existed in v1"
