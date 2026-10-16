"""Path-criticality: how much of the attack surface to the crown jewels one fix closes.

The ranking signal of S8. Its only inputs are the Internet -> crown-jewel paths the
graph returns at runtime (FalkorDB path enumeration, or attack_paths) and each
target's sensitivity. It never sees labels, the oracle or a planted path's name
(tests/test_eval_leakage.py checks this module's imports and strings).

For every fix token on some path:

    criticality(t) = sum, over the DISTINCT crown paths t lies on, of the target's
                     sensitivity weight

i.e. how many weighted routes to a crown jewel fixing t would close. The order is
greedy, one pick at a time, by:

  1. criticality, descending: a funnel on three routes before a step on one;
  2. the weight of the routes it covers that nothing ranked above it covers yet:
     among equal criticality, a finding on a route the list has not touched beats
     a second finding of a route it already has (without this, ties stack on one
     route and a top 10 can leave a route out);
  3. its best route's likelihood x weight: the likelier route first;
  4. Internet-facing (the token's step leaves the Internet): a minor tiebreak;
  5. a hash of the token, never the token itself (ids carry generation order).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

# Per-target weight by DataStore.sensitivity. S9: crown jewels carry a tier,
# critical | high | medium ("crown" before S9). The product's own weights, set in S8;
# the ground truth weights tiers independently (and differently: 1 / 0.6 / 0.3).
SENSITIVITY_WEIGHT = {"critical": 1.0, "crown": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}


def sensitivity_weight(sensitivity: str | None) -> float:
    return SENSITIVITY_WEIGHT.get(sensitivity or "crown", 1.0)


@dataclass(frozen=True)
class CrownPath:
    """One Internet -> crown-jewel path, as the graph returned it."""

    target: str
    weight: float  # the target's sensitivity weight
    likelihood: float  # product of the step likelihoods (exp(-cost))
    tokens: tuple[str, ...]  # the fix token of every step, in order
    entry: str | None = None  # the fix token of the step that leaves the Internet


@dataclass
class Criticality:
    token: str
    criticality: float = 0.0  # sum of target weights over the distinct paths through it
    paths: list[int] = field(default_factory=list)  # indices into the path list
    best: float = 0.0  # max over its paths of likelihood x weight
    entry: bool = False  # some path enters the network through it
    rank: int = 0  # 1-based position in the greedy order

    def view(self) -> dict:
        return {
            "crown_paths": len(self.paths),
            "criticality": round(self.criticality, 4),
            "best_path_score": round(self.best, 4),
        }


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def rank_by_criticality(
    paths: Iterable[CrownPath], include: Callable[[str], bool] = lambda t: True
) -> list[Criticality]:
    """Every token `include` accepts that lies on some path, most critical first."""
    plist = list(paths)
    per: dict[str, Criticality] = {}
    for i, p in enumerate(plist):
        score = p.likelihood * p.weight
        for tok in dict.fromkeys(p.tokens):  # a path counts once per token
            if not include(tok):
                continue
            c = per.setdefault(tok, Criticality(tok))
            c.criticality += p.weight
            c.paths.append(i)
            c.best = max(c.best, score)
            c.entry = c.entry or tok == p.entry
    covered: set[int] = set()
    left = dict(per)
    order: list[Criticality] = []
    while left:

        def key(c: Criticality) -> tuple:
            fresh = sum(plist[i].weight for i in c.paths if i not in covered)
            crit = -round(c.criticality, 9)
            return (crit, -round(fresh, 9), -c.best, not c.entry, _hash(c.token))

        pick = min(left.values(), key=key)
        del left[pick.token]
        covered.update(pick.paths)
        pick.rank = len(order) + 1
        order.append(pick)
    return order


def dedupe(paths: Iterable[tuple[tuple[str, ...], CrownPath]]) -> list[CrownPath]:
    """Paths keyed by their step keys; the first of each kept (a path returned by
    two calls, e.g. attack_paths per target and from the Internet, counts once)."""
    seen: dict[tuple[str, ...], CrownPath] = {}
    for sig, p in paths:
        seen.setdefault(sig, p)
    return list(seen.values())
