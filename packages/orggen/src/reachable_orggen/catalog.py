"""Access to the committed threat-intel snapshot, indexed for the generator.

The generator never invents CVEs: it draws REAL CVE ids from the snapshot that
actually affect the product a piece of Software runs. This module loads
cves.json once and builds:

  * by_product : vendor:product -> list of CVE records affecting it
  * network_cves / local_cves : partitioned by CVSS attack vector, so the
    planter can ask for "a network-exploitable CVE on nginx" or "a local
    privilege-escalation CVE on the Linux kernel".
"""

from __future__ import annotations

import functools
import json
import random
from dataclasses import dataclass

from reachable_core.attack_rules import NETWORK_VECTORS
from reachable_core.settings import get_settings


@dataclass(frozen=True)
class CveRec:
    id: str
    cvss: float
    av: str
    pr: str
    ui: str
    epss: float
    kev: bool
    ransomware: bool
    severity: str
    products: tuple[str, ...]

    @property
    def is_network(self) -> bool:
        return self.av in NETWORK_VECTORS

    @property
    def is_local(self) -> bool:
        return self.av == "LOCAL"

    @property
    def is_privesc(self) -> bool:
        # A local-vector CVE that gains privilege: LOCAL vector + high impact.
        return self.is_local and self.cvss >= 6.0


@functools.lru_cache(maxsize=1)
def _load() -> list[CveRec]:
    snap = get_settings().threatintel_dir / "snapshot" / "cves.json"
    raw = json.loads(snap.read_text(encoding="utf-8"))
    out = []
    for r in raw:
        out.append(
            CveRec(
                id=r["id"],
                cvss=r["cvss"],
                av=r["av"],
                pr=r["pr"],
                ui=r["ui"],
                epss=r["epss"],
                kev=r["kev"],
                ransomware=r["kev_ransomware"],
                severity=r["severity"],
                products=tuple(r["products"]),
            )
        )
    return out


class Catalog:
    """Queryable view over the snapshot for one generation run."""

    def __init__(self) -> None:
        recs = _load()
        self.by_product: dict[str, list[CveRec]] = {}
        for r in recs:
            for p in r.products:
                self.by_product.setdefault(p, []).append(r)
        # Stable ordering so a fixed seed picks the same CVEs every run.
        for lst in self.by_product.values():
            lst.sort(key=lambda c: c.id)

    def for_product(self, product_id: str) -> list[CveRec]:
        return self.by_product.get(product_id, [])

    def pick(
        self,
        rng: random.Random,
        product_id: str,
        *,
        network: bool | None = None,
        local: bool | None = None,
        privesc: bool | None = None,
        min_cvss: float | None = None,
        max_cvss: float | None = None,
        kev: bool | None = None,
    ) -> CveRec | None:
        """Pick one CVE affecting the product, matching the given predicates.

        Returns None if nothing matches (caller decides whether that's fatal).
        """
        pool = self.for_product(product_id)

        def ok(c: CveRec) -> bool:
            if network is not None and c.is_network != network:
                return False
            if local is not None and c.is_local != local:
                return False
            if privesc is not None and c.is_privesc != privesc:
                return False
            if min_cvss is not None and c.cvss < min_cvss:
                return False
            if max_cvss is not None and c.cvss > max_cvss:
                return False
            return not (kev is not None and c.kev != kev)

        matches = [c for c in pool if ok(c)]
        return rng.choice(matches) if matches else None

    def pick_for(
        self, rng: random.Random, product_ids: list[str], **preds
    ) -> tuple[str, CveRec] | None:
        """Try each product in order; return (product_id, CVE) for the first match.

        The planter uses this so a path hop can say 'a network-exploitable CVE
        on any web product', staying robust to which CVEs the snapshot happens
        to contain for a given product.
        """
        for pid in product_ids:
            rec = self.pick(rng, pid, **preds)
            if rec is not None:
                return pid, rec
        return None
