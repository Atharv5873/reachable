"""Ground-truth types: planted paths, decoys, and the assembled label set.

These are what gets written to data/orgs/<org>/labels.json and are NEVER loaded
into FalkorDB — they are the answer key the agents (S2+) are graded against.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PlantedHop:
    rule: str
    technique: str
    src: str  # attack-graph state node id (e.g. "asset:org_a:asset:00042")
    dst: str


@dataclass
class PlantedPath:
    name: str
    difficulty: str  # easy | medium | hard
    target: str  # crown-jewel DataStore node id ("ds:...")
    hops: list[PlantedHop] = field(default_factory=list)

    def node_sequence(self) -> list[str]:
        if not self.hops:
            return []
        seq = [self.hops[0].src]
        for h in self.hops:
            seq.append(h.dst)
        return seq


@dataclass
class Decoy:
    kind: str  # severity | mitigated | dead_end
    note: str
    asset: str = ""
    finding_ids: list[str] = field(default_factory=list)
    vuln_cves: list[str] = field(default_factory=list)


@dataclass
class SharedInfra:
    """A node several planted paths could funnel through ("one fix, many paths").

    `paths` names the planted paths that cross it. `blocked_by` is set when the
    shared hop exists but a Control blocks it, so no path crosses it (the
    contrast case: every path then needs its own fix)."""

    kind: str  # ci_runner | jump_host | vpn_gateway
    node: str  # attack-state id, e.g. "asset:org_a:asset:01234"
    note: str
    paths: list[str] = field(default_factory=list)
    blocked_by: str = ""


@dataclass
class GroundTruth:
    org: str
    seed: int
    scale: float
    paths: list[PlantedPath] = field(default_factory=list)
    decoys: list[Decoy] = field(default_factory=list)
    crown_jewels: list[str] = field(default_factory=list)  # ds node ids
    crown_tiers: dict[str, str] = field(default_factory=dict)  # ds node id -> tier (S9)
    shared_infra: list[SharedInfra] = field(default_factory=list)
    # Filled in by the oracle after the graph is built:
    min_cut: list[str] = field(default_factory=list)
    finding_priority: dict[str, float] = field(default_factory=dict)
    # Scan v2 only: planted findings the drift marked fixed, and the planted
    # paths that disappeared because they depended on one of them.
    fixed_findings: list[str] = field(default_factory=list)
    removed_paths: list[str] = field(default_factory=list)
