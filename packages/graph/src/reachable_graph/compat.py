"""Translate between graph ids and the oracle's attack-state ids.

Used ONLY for scoring and tests (path equivalence, Gate A). The tools never read
labels or the oracle.

The oracle names attack states by prefix:  internet | asset:<id> | secret:<id> |
ident:<id> | ds:<id> | priv:<id>.  The graph uses the entity's own id and its
label. The one structural difference is local_privesc: the oracle routes it
through a priv:<asset> state, the graph folds it onto the root-owned secret.
`fold_privesc` applies the same fold to an oracle path so the two compare 1:1.
"""

from __future__ import annotations

from dataclasses import dataclass

# Graph label -> oracle prefix. Order matters: an Identity also carries Role etc.
LABEL_PREFIX = {
    "Internet": None,
    "Asset": "asset",
    "Secret": "secret",
    "Identity": "ident",
    "DataStore": "ds",
}


def to_oracle_id(node_id: str, labels: list[str] | str) -> str:
    labels = [labels] if isinstance(labels, str) else labels
    for label, prefix in LABEL_PREFIX.items():
        if label in labels:
            return "internet" if prefix is None else f"{prefix}:{node_id}"
    raise ValueError(f"no attack-state label among {labels} for {node_id}")


def from_oracle_id(state: str) -> str:
    """'asset:org_a:asset:00001' -> 'org_a:asset:00001'; 'internet' -> 'internet'."""
    return state if state == "internet" else state.split(":", 1)[1]


@dataclass(frozen=True)
class CHop:
    """A comparable hop: oracle-style state ids + rule + fix token."""

    src: str
    dst: str
    rule: str
    fix: str


def fold_privesc(hops: list[CHop]) -> list[CHop]:
    """Collapse  asset -[local_privesc]-> priv:asset -[creds_in_files]-> secret
    into     asset -[local_privesc]-> secret   (fix = the privesc finding)."""
    out: list[CHop] = []
    i = 0
    while i < len(hops):
        h = hops[i]
        nxt = hops[i + 1] if i + 1 < len(hops) else None
        if h.dst.startswith("priv:") and nxt is not None and nxt.src == h.dst:
            out.append(CHop(h.src, nxt.dst, h.rule, h.fix))
            i += 2
        else:
            out.append(h)
            i += 1
    return out


def oracle_path_set(oracle_paths: dict) -> set[tuple[CHop, ...]]:
    """All oracle Internet->crown paths (OracleResult.paths), folded, as a set."""
    out = set()
    for plist in oracle_paths.values():
        for hops in plist:
            chops = [CHop(h.src, h.dst, h.rule, h.fix) for h in hops]
            out.add(tuple(fold_privesc(chops)))
    return out


def planted_node_sequence(path: dict) -> tuple[str, ...]:
    """A labels.json planted path as a folded node sequence (no fix tokens there)."""
    hops = [CHop(h["from"], h["to"], h["rule"], "") for h in path["hops"]]
    folded = fold_privesc(hops)
    return tuple([folded[0].src] + [h.dst for h in folded])


def graph_path_to_chops(nodes: list[dict], steps: list[dict]) -> tuple[CHop, ...]:
    """A tool path ({id, labels} nodes + step dicts) as comparable hops."""
    ids = [to_oracle_id(n["id"], n["labels"]) for n in nodes]
    return tuple(CHop(ids[i], ids[i + 1], s["rule"], s["fix_token"]) for i, s in enumerate(steps))
