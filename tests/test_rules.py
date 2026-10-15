"""The attack rules and their ATT&CK technique ids."""

from __future__ import annotations

from reachable_core.attack_rules import RULES, TECHNIQUE_IDS, VulnSignals, exploit_likelihood


def test_every_rule_technique_exists_in_snapshot(snapshot_attack):
    """Validate every ATT&CK id the rules cite against the committed snapshot."""
    snapshot_ids = {t["id"] for t in snapshot_attack["techniques"]}
    missing = TECHNIQUE_IDS - snapshot_ids
    assert not missing, f"technique ids not in ATT&CK snapshot: {missing}"


def test_rule_names_match_technique_field():
    for name, rule in RULES.items():
        assert rule.name == name
        assert rule.technique.startswith("T")


def test_exploit_likelihood_bounds_and_kev_floor():
    low = VulnSignals(av="NETWORK", pr="NONE", ui="NONE", epss=0.0, kev=False)
    assert 0.05 <= exploit_likelihood(low) <= 0.99
    # KEV floors the base at 0.85 before the CVSS 'ease' factor.
    kev = VulnSignals(av="NETWORK", pr="NONE", ui="NONE", epss=0.01, kev=True)
    assert exploit_likelihood(kev) >= 0.85
    # User interaction reduces likelihood.
    ui = VulnSignals(av="NETWORK", pr="NONE", ui="REQUIRED", epss=0.5, kev=False)
    no_ui = VulnSignals(av="NETWORK", pr="NONE", ui="NONE", epss=0.5, kev=False)
    assert exploit_likelihood(ui) < exploit_likelihood(no_ui)
