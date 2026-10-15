"""The interface every prioritiser implements, and the two that need no model.

    rank(scan) -> Ranking: an order over EXACTLY the scan's open findings
                           (+ optionally the fix set it would apply)

An LLM prioritiser names a short head (up to 20 findings); the rest of the order
is the same severity tail for all three, so a metric at K <= 20 measures what
the model chose. The tail is documented in every raw output (`tail_rule`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from .store import FindingRow, ScanData, tiebreak

HEAD_KEEP = 100  # raw outputs keep the top 100: every metric at K <= 100 recomputes


@dataclass
class Ranking:
    prioritiser: str
    order: list[str]  # every open finding of the scan, most urgent first
    fix_set: list[str] | None = None  # fix tokens the prioritiser itself chose
    head: list[str] = field(default_factory=list)  # what the prioritiser named itself
    tail_rule: str | None = None  # how the rest of `order` was filled
    why: dict[str, str] = field(default_factory=dict)
    invalid_ids: list[str] = field(default_factory=list)  # named, but not an open finding
    reasoning: str = ""
    meta: dict = field(default_factory=dict)  # calls, tokens, cost, wall time, stop reason
    tool_log: list[dict] = field(default_factory=list)


class Prioritiser(Protocol):
    name: str
    uses_llm: bool

    async def rank(self, data: ScanData, *, seed: int = 0) -> Ranking: ...


def complete(head: list[str], data: ScanData, tail: list[str]) -> tuple[list[str], list[str]]:
    """head (deduplicated, open findings only) + the tail minus the head.
    Returns (full order, invalid ids the head named)."""
    universe = data.by_id
    seen: dict[str, None] = {}
    invalid = []
    for f in head:
        if f in universe:
            seen.setdefault(f)
        elif f not in invalid:
            invalid.append(f)
    order = list(seen) + [f for f in tail if f not in seen]
    return order, invalid


# ----------------------------------------------------------- severity_sort
def severity_order(data: ScanData) -> list[str]:
    """CVSS descending; ties by a hash of the id."""
    return [f.id for f in sorted(data.findings, key=lambda f: (-f.cvss, tiebreak(f.id)))]


class SeveritySort:
    """What most teams do today: sort the scanner export by CVSS."""

    name = "severity_sort"
    uses_llm = False

    async def rank(self, data: ScanData, *, seed: int = 0) -> Ranking:
        order = severity_order(data)
        return Ranking(self.name, order, head=order, meta=_free())


# ------------------------------------------------------------- smart_score
# Fixed a priori (S7 design, before any result was seen) and never tuned on the
# labels. Severity, likelihood of exploitation, known exploitation, exposure.
W_CVSS, W_EPSS, W_KEV, W_EXPOSED = 0.30, 0.25, 0.20, 0.25
MITIGATED_FACTOR = 0.25  # a recorded compensating control (e.g. a WAF rule) on this host


def smart_score(f: FindingRow) -> float:
    """A transparent risk score over CVSS + EPSS + KEV + internet exposure, with a
    compensating-control discount. Reachability-blind: it knows whether the
    finding's own host faces the Internet, never what that host connects to."""
    s = W_CVSS * f.cvss / 10 + W_EPSS * f.epss + W_KEV * f.kev + W_EXPOSED * f.internet_facing
    return s * (MITIGATED_FACTOR if f.mitigated_by else 1.0)


class SmartScore:
    """The best non-graph practice (an EPSS/KEV-aware, exposure-aware score)."""

    name = "smart_score"
    uses_llm = False

    async def rank(self, data: ScanData, *, seed: int = 0) -> Ranking:
        order = [
            f.id for f in sorted(data.findings, key=lambda f: (-smart_score(f), tiebreak(f.id)))
        ]
        return Ranking(self.name, order, head=order, meta=_free())


def _free() -> dict:
    return {"llm_calls": 0, "tool_calls": 0, "tokens_in": 0, "tokens_out": 0, "usd": 0.0}
