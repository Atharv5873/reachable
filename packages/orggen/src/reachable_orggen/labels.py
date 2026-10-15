"""Serialise ground truth to data/orgs/<org>/labels.json (never loaded into FalkorDB)."""

from __future__ import annotations

import json
from pathlib import Path

from .build import OrgBuild
from .ground_truth import GroundTruth, PlantedPath


def _path_dict(p: PlantedPath) -> dict:
    return {
        "name": p.name,
        "difficulty": p.difficulty,
        "target": p.target,
        "hops": [
            {"rule": h.rule, "technique": h.technique, "from": h.src, "to": h.dst} for h in p.hops
        ],
        "nodes": p.node_sequence(),
    }


def labels_payload(ob: OrgBuild, *, scan: str = "v1", new_path: PlantedPath | None = None) -> dict:
    gt: GroundTruth = ob.ground_truth
    # Only findings with nonzero priority are worth listing in full; the rest
    # are implicitly ~0. Keep the whole map, though, so graders can diff.
    priorities = ob.oracle.finding_priority
    return {
        "org": gt.org,
        "seed": gt.seed,
        "scale": gt.scale,
        "scan": scan,
        "crown_jewels": gt.crown_jewels,
        "paths": [_path_dict(p) for p in gt.paths],
        "new_path_v2": _path_dict(new_path) if new_path else None,
        "fixed_findings_v2": gt.fixed_findings,
        "removed_paths_v2": gt.removed_paths,
        "decoys": [
            {
                "kind": d.kind,
                "note": d.note,
                "asset": d.asset,
                "finding_ids": d.finding_ids,
                "vuln_cves": d.vuln_cves,
            }
            for d in gt.decoys
        ],
        "min_cut": gt.min_cut,
        "min_cut_size": len(gt.min_cut),
        "finding_priority": priorities,
        "oracle_path_count": sum(len(v) for v in ob.oracle.paths.values()),
    }


def write_labels(out_dir: Path, ob: OrgBuild, *, scan: str = "v1", new_path=None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    name = "labels.json" if scan == "v1" else "labels_v2.json"
    path = out_dir / name
    path.write_text(json.dumps(labels_payload(ob, scan=scan, new_path=new_path), indent=2), "utf-8")
    return path
