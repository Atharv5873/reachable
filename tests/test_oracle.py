"""The oracle: planted paths, decoys, min cut, finding priority."""

from __future__ import annotations

from reachable_core.attack_rules import RULES
from reachable_orggen.oracle import paths_exist_after_removal


def _oracle_sequences(ob):
    out = set()
    for plist in ob.oracle.paths.values():
        for hops in plist:
            out.add(tuple([hops[0].src] + [h.dst for h in hops]))
    return out


def test_every_planted_path_is_valid_and_found(builds):
    for org, ob in builds.items():
        seqs = _oracle_sequences(ob)
        for p in ob.ground_truth.paths:
            # hops reference real rules with the right technique
            for h in p.hops:
                assert h.rule in RULES, f"{org}: unknown rule {h.rule}"
                assert RULES[h.rule].technique == h.technique
            # 3..8 hops
            assert 3 <= len(p.hops) <= 8, f"{org}:{p.name} has {len(p.hops)} hops"
            # appears in the oracle's independently-computed path set
            assert tuple(p.node_sequence()) in seqs, f"{org}: planted {p.name} not an oracle path"


def test_difficulty_requirements(builds):
    for org, ob in builds.items():
        diffs = {p.difficulty for p in ob.ground_truth.paths}
        assert "easy" in diffs and "hard" in diffs
        # Hard paths must use at least one non-network (identity/secret) hop.
        network_rules = {"exploit_public_facing", "exploit_remote_service"}
        for p in ob.ground_truth.paths:
            if p.difficulty == "hard":
                assert any(h.rule not in network_rules for h in p.hops), (
                    f"{org}:{p.name} is hard but only network hops"
                )
        # At least one path starts from a medium-severity CVE exploit.
        assert any(p.name.startswith("medium_start") for p in ob.ground_truth.paths)


def test_no_decoy_on_any_oracle_path(builds):
    for org, ob in builds.items():
        on_path = set()
        for plist in ob.oracle.paths.values():
            for hops in plist:
                for h in hops:
                    on_path.add(h.src)
                    on_path.add(h.dst)
        for d in ob.ground_truth.decoys:
            assert f"asset:{d.asset}" not in on_path, f"{org}: decoy {d.kind} on an oracle path"


def test_min_cut_removal_disconnects_all_crown_jewels(builds):
    for org, ob in builds.items():
        cut = set(ob.ground_truth.min_cut)
        assert cut, f"{org}: empty min cut"
        still = paths_exist_after_removal(ob.dataset, cut, hop_cap=8)
        assert not still, f"{org}: crown jewel still reachable after min-cut removal"


def test_finding_priority_high_on_true_paths_zero_on_decoys(builds):
    for org, ob in builds.items():
        prio = ob.oracle.finding_priority
        # Decoy findings are not on true paths -> ~0 priority.
        for d in ob.ground_truth.decoys:
            for fid in d.finding_ids:
                assert prio.get(fid, 0.0) == 0.0, f"{org}: decoy finding {fid} has priority"
        # At least one finding has top priority.
        assert max(prio.values(), default=0.0) == 1.0
