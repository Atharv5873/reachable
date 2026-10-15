"""Deterministic synthetic-org generator.

`generate_org(org, seed, cfg)` returns a Dataset (background infrastructure)
plus a Builder the planters use to carve exact ground-truth paths and decoys on
top. Same seed => byte-identical dataset (tested).

Design:
  * A Shape describes each org's zones, the internet-exposed zone, the
    firewall rules (zone->zone allow rules, modelled as DATA), the product mix
    per zone, and which zone holds crown jewels.
  * The engine scatters BACKGROUND assets/software/findings to hit realism
    counts. Background infrastructure is deliberately kept away from crown
    jewels: no background asset or identity can reach a crown-jewel DataStore.
    That is what lets the planter own every true path, and lets the oracle
    confirm no decoy lies on a path (tested).
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from reachable_intel.products import PRODUCTS_BY_ID, ProductSpec

from .catalog import Catalog, CveRec
from .model import (
    Asset,
    Control,
    Dataset,
    DataStore,
    Finding,
    Identity,
    ReachRule,
    Secret,
    Software,
    Vuln,
    Zone,
)
from .names import host_name

# A fixed reference "now" (epoch seconds) so first_seen timestamps are
# deterministic and don't drift with wall-clock. 2024-01-01T00:00:00Z.
NOW = 1_704_067_200
WEEK = 7 * 24 * 3600


@dataclass(frozen=True)
class GenConfig:
    scale: float = 1.0


@dataclass
class ZoneSpec:
    id: str
    name: str
    trust: int
    categories: tuple[str, ...]
    base_assets: int  # at scale 1.0


@dataclass
class Shape:
    display: str
    cloud: bool
    zones: list[ZoneSpec]
    exposed_zone: str  # zone the Internet exposes
    firewall: list[tuple[str, str, int]]  # (src_zone, dst_zone, port)
    crown_zone: str


# Products grouped by category, for picking software per zone.
def _by_category() -> dict[str, list[ProductSpec]]:
    out: dict[str, list[ProductSpec]] = {}
    for p in PRODUCTS_BY_ID.values():
        out.setdefault(p.category, []).append(p)
    for lst in out.values():
        lst.sort(key=lambda s: s.id)
    return out


PRODUCTS_BY_CATEGORY = _by_category()


SHAPES: dict[str, Shape] = {
    # --- org_a: cloud-native SaaS -----------------------------------------
    "org_a": Shape(
        display="Nimbarix",
        cloud=True,
        zones=[
            ZoneSpec("edge", "Ingress / LB", 1, ("web",), 180),
            ZoneSpec("k8s", "Kubernetes services", 2, ("web", "framework", "orchestrator"), 900),
            ZoneSpec("ci", "CI runners", 2, ("ci",), 220),
            ZoneSpec("data", "Managed data", 3, ("db", "cache"), 400),
            ZoneSpec("vault", "Secrets vault", 3, ("secrets",), 40),
        ],
        exposed_zone="edge",
        firewall=[
            ("internet", "edge", 443),
            ("edge", "k8s", 8080),
            ("edge", "k8s", 8443),
            ("k8s", "ci", 8080),
            ("k8s", "data", 5432),
            ("k8s", "data", 27017),
            ("k8s", "data", 9200),
            ("k8s", "data", 6379),
            ("k8s", "vault", 8200),
        ],
        crown_zone="data",
    ),
    # --- org_b: retail web (classic DMZ -> app -> data) -------------------
    "org_b": Shape(
        display="Marketly",
        cloud=False,
        zones=[
            ZoneSpec("dmz", "DMZ (CDN/WAF + web)", 1, ("web",), 220),
            ZoneSpec("app", "App tier", 2, ("web", "framework"), 780),
            ZoneSpec("data", "Data tier", 3, ("db",), 560),
            ZoneSpec("admin", "Legacy admin panel", 2, ("web", "framework"), 60),
        ],
        exposed_zone="dmz",
        firewall=[
            ("internet", "dmz", 443),
            ("internet", "dmz", 80),
            ("dmz", "app", 8080),
            ("dmz", "app", 8443),
            ("dmz", "admin", 8080),  # legacy: DMZ can still reach the old admin panel
            ("app", "data", 3306),
            ("app", "data", 1433),
            ("app", "data", 5432),
            ("admin", "app", 8080),
        ],
        crown_zone="data",
    ),
    # --- org_c: hybrid (on-prem + VPN/vendor gateway + corp) --------------
    "org_c": Shape(
        display="Ferrocast",
        cloud=False,
        zones=[
            ZoneSpec("vpn", "VPN / vendor gateway", 1, ("vpn",), 40),
            ZoneSpec("corp", "Corp workstations", 2, ("os", "ssh"), 800),
            ZoneSpec("mgmt", "Management zone", 3, ("os", "fileshare"), 200),
            ZoneSpec("onprem", "On-prem servers", 3, ("os", "ssh", "db"), 400),
            ZoneSpec("data", "Data / file shares", 4, ("fileshare", "db"), 160),
        ],
        exposed_zone="vpn",
        firewall=[
            ("internet", "vpn", 443),
            ("vpn", "corp", 445),
            ("corp", "mgmt", 445),
            ("mgmt", "onprem", 22),
            ("mgmt", "onprem", 445),
            ("onprem", "data", 445),
            ("onprem", "data", 3306),
        ],
        crown_zone="data",
    ),
}


class Builder:
    """Mutable builder around a Dataset, shared by the engine and the planters.

    Every node gets a stable id prefixed by the org, so ids are unique across
    graphs and readable in the FalkorDB Browser.
    """

    def __init__(self, org: str, seed: int, cfg: GenConfig, catalog: Catalog) -> None:
        self.org = org
        self.cfg = cfg
        self.rng = random.Random(f"{org}:{seed}")
        self.catalog = catalog
        self.shape = SHAPES[org]
        self.ds = Dataset(org=org, seed=seed, scale=cfg.scale, scan_ts=NOW)
        self._n: dict[str, int] = {}
        self.zone_assets: dict[str, list[str]] = {z.id: [] for z in self.shape.zones}
        # Track which Vuln node already exists for a (software, cve) pair.
        self._vulns: dict[str, str] = {}
        # id -> object indexes, so lookups stay O(1) on large orgs.
        self.by_id: dict[str, object] = {}

    def _id(self, kind: str) -> str:
        self._n[kind] = self._n.get(kind, 0) + 1
        return f"{self.org}:{kind}:{self._n[kind]:05d}"

    # --- node creators -----------------------------------------------------
    def zone(self, spec: ZoneSpec) -> Zone:
        z = Zone(id=f"{self.org}:zone:{spec.id}", name=spec.name, trust=spec.trust)
        self.ds.zones.append(z)
        return z

    def asset(self, zone: str, kind: str, env: str, *, cloud: bool | None = None) -> Asset:
        n = len(self.zone_assets[zone]) + 1
        a = Asset(
            id=self._id("asset"),
            kind=kind,
            zone=f"{self.org}:zone:{zone}",
            env=env,
            hostname=host_name(self.rng, zone, n),
            cloud=self.shape.cloud if cloud is None else cloud,
        )
        self.ds.assets.append(a)
        self.by_id[a.id] = a
        self.zone_assets[zone].append(a.id)
        self.ds.add_edge(a.id, a.zone, "IN_ZONE")
        return a

    def run_software(self, asset: Asset, spec: ProductSpec) -> Software:
        version = self.rng.choice(spec.versions) if spec.versions else "0"
        sw = Software(
            id=self._id("sw"),
            vendor=spec.vendor,
            product=spec.product,
            version=version,
            cpe=f"cpe:2.3:{spec.part}:{spec.vendor}:{spec.product}:{version}",
        )
        self.ds.software.append(sw)
        self.ds.add_edge(asset.id, sw.id, "RUNS")
        return sw

    def add_vuln(self, sw: Software, rec: CveRec) -> Vuln:
        key = f"{sw.id}:{rec.id}"
        if key in self._vulns:
            return self.by_id[self._vulns[key]]  # type: ignore[return-value]
        v = Vuln(
            id=self._id("vuln"),
            cve=rec.id,
            cvss=rec.cvss,
            av=rec.av,
            pr=rec.pr,
            ui=rec.ui,
            epss=rec.epss,
            kev=rec.kev,
            ransomware=rec.ransomware,
        )
        self.ds.vulns.append(v)
        self.by_id[v.id] = v
        self._vulns[key] = v.id
        self.ds.add_edge(sw.id, v.id, "HAS_VULN")
        return v

    def add_finding(self, asset: Asset, vuln: Vuln, *, status: str = "open") -> Finding:
        first_seen = NOW - self.rng.randint(0, 180) * 24 * 3600
        f = Finding(
            id=self._id("finding"),
            scanner=self.rng.choice(["tenable", "qualys", "trivy", "openvas"]),
            first_seen=first_seen,
            status=status,
        )
        self.ds.findings.append(f)
        self.ds.add_edge(f.id, asset.id, "ON")
        self.ds.add_edge(f.id, vuln.id, "OF")
        return f

    def identity(self, kind: str, name: str, *, over_broad: bool = False) -> Identity:
        i = Identity(id=self._id("ident"), kind=kind, name=name, over_broad=over_broad)
        self.ds.identities.append(i)
        self.by_id[i.id] = i
        return i

    def secret(self, kind: str, *, requires_priv: bool = False) -> Secret:
        s = Secret(id=self._id("secret"), kind=kind, requires_priv=requires_priv)
        self.ds.secrets.append(s)
        self.by_id[s.id] = s
        return s

    def datastore(self, kind: str, *, crown: bool, sensitivity: str) -> DataStore:
        d = DataStore(id=self._id("ds"), kind=kind, crown_jewel=crown, sensitivity=sensitivity)
        self.ds.datastores.append(d)
        self.by_id[d.id] = d
        return d

    def control(self, kind: str, vuln_id: str, asset_id: str) -> Control:
        """A Control that MITIGATES a vuln, SCOPED to one asset.

        Scoping (the WHY): a patch/WAF rule protects a *specific* host, not the
        CVE everywhere. We encode the scope on the MITIGATES edge as
        `asset = <asset_id>`, so a query only treats the step as blocked when
        the compromised asset matches. The oracle reads the same scope.
        """
        c = Control(id=self._id("control"), kind=kind)
        self.ds.controls.append(c)
        self.ds.add_edge(c.id, vuln_id, "MITIGATES", asset=asset_id)
        return c

    # --- edge helpers ------------------------------------------------------
    def expose(self, asset: Asset, port: int) -> None:
        self.ds.add_edge(self.ds.internet_id, asset.id, "EXPOSES", port=port)

    def reach(self, a: Asset, b: Asset, port: int, protocol: str = "tcp") -> None:
        self.ds.add_edge(a.id, b.id, "CAN_REACH", port=port, protocol=protocol)

    def holds(self, asset: Asset, secret: Secret) -> None:
        self.ds.add_edge(asset.id, secret.id, "HOLDS")

    def unlocks(self, secret: Secret, target_id: str) -> None:
        self.ds.add_edge(secret.id, target_id, "UNLOCKS")

    def assumes(self, asset: Asset, role: Identity) -> None:
        self.ds.add_edge(asset.id, role.id, "ASSUMES")

    def can(self, ident: Identity, target_id: str, action: str) -> None:
        self.ds.add_edge(ident.id, target_id, "CAN", action=action)

    def can_assume(self, ident: Identity, role: Identity) -> None:
        self.ds.add_edge(ident.id, role.id, "CAN_ASSUME")


def _scaled(n: int, scale: float) -> int:
    return max(1, round(n * scale))


def _pick_cve(builder: Builder, product_id: str) -> CveRec | None:
    """Pick a background CVE for a product, biased toward high severity so the
    data has plenty of criticals (a realism target)."""
    pool = builder.catalog.for_product(product_id)
    if not pool:
        return None
    crits = [c for c in pool if c.cvss >= 9.0]
    if crits and builder.rng.random() < 0.45:
        return builder.rng.choice(crits)
    return builder.rng.choice(pool)


def generate_background(org: str, seed: int, cfg: GenConfig, catalog: Catalog) -> Builder:
    """Build zones, background assets, software and findings for one org."""
    b = Builder(org, seed, cfg, catalog)
    shape = b.shape

    for zspec in shape.zones:
        b.zone(zspec)

    # Background assets per zone.
    for zspec in shape.zones:
        count = _scaled(zspec.base_assets, cfg.scale)
        cats = [c for c in zspec.categories if PRODUCTS_BY_CATEGORY.get(c)]
        for _ in range(count):
            env = "prod" if zspec.trust >= 1 else "corp"
            kind = _asset_kind(zspec)
            asset = b.asset(zspec.id, kind, env)
            # 1-3 products from the zone's categories.
            for _ in range(b.rng.randint(1, 3)):
                if not cats:
                    break
                cat = b.rng.choice(cats)
                spec = b.rng.choice(PRODUCTS_BY_CATEGORY[cat])
                sw = b.run_software(asset, spec)
                # 1-3 findings per software, each a real CVE for its product.
                for _ in range(b.rng.randint(1, 3)):
                    rec = _pick_cve(b, spec.id)
                    if rec is None:
                        continue
                    vuln = b.add_vuln(sw, rec)
                    b.add_finding(asset, vuln)

    # Expose a small fraction of the internet-facing zone (most assets are NOT
    # exposed, a realism target).
    exposed_pool = b.zone_assets[shape.exposed_zone]
    n_exposed = max(1, len(exposed_pool) // 6)
    for aid in b.rng.sample(exposed_pool, min(n_exposed, len(exposed_pool))):
        b.expose(b.by_id[aid], 443)

    # Firewall rules as data.
    for src, dst, port in shape.firewall:
        b.ds.reach_rules.append(ReachRule(src_zone=src, dst_zone=dst, port=port))

    # Derive a BOUNDED set of CAN_REACH edges from the rules. A real security
    # group allows a whole subnet; materialising every pair would be O(n^2) and
    # explode the graph, so we cap the fan-out per source asset. Planted paths
    # add their own explicit CAN_REACH edges, so correctness never depends on
    # this sampling — it only adds realistic lateral-movement noise.
    _derive_can_reach(b)
    return b


def _asset_kind(zspec: ZoneSpec) -> str:
    mapping = {
        "edge": "load_balancer",
        "k8s": "k8s_node",
        "ci": "ci_runner",
        "data": "managed_db",
        "vault": "secrets_vault",
        "dmz": "web_server",
        "app": "app_server",
        "admin": "admin_host",
        "vpn": "gateway",
        "corp": "workstation",
        "mgmt": "mgmt_server",
        "onprem": "server",
    }
    return mapping.get(zspec.id, "server")


def _derive_can_reach(b: Builder, fanout: int = 4) -> None:
    for rule in b.ds.reach_rules:
        if rule.src_zone == "internet":
            continue
        srcs = b.zone_assets.get(rule.src_zone, [])
        dsts = b.zone_assets.get(rule.dst_zone, [])
        if not srcs or not dsts:
            continue
        for sid in srcs:
            src = b.by_id[sid]
            targets = b.rng.sample(dsts, min(fanout, len(dsts)))
            for tid in targets:
                if tid == sid:
                    continue
                b.reach(src, b.by_id[tid], rule.port)
