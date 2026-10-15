"""Plant ground-truth attack paths and decoys on top of a background org.

Every TRUE path is built as an isolated "spine" of freshly-created nodes wired
with explicit edges, so the ONLY way the attack graph reaches a crown jewel is
through a planted spine. Background infrastructure never reaches crown jewels
(see generate.py), which is what lets the oracle confirm:
  * every planted path is a real oracle path, and
  * no decoy ever lies on an oracle path.

Decoys are built to be provably safe:
  * severity  — a critical (incl. KEV) vuln in an ISOLATED zone with no route
                in or out, so it is unreachable despite its score.
  * mitigated — an internet-exposed exploitable asset where a Control blocks the
                exploit step (MITIGATES scoped to that asset+vuln).
  * dead_end  — an internet-exposed exploitable asset the attacker DOES land on,
                but with no onward reach and no useful secret: a dead end.

Product choices per hop use the real snapshot via Catalog.pick_for, so every
planted CVE genuinely affects the Software it sits on.
"""

from __future__ import annotations

from .catalog import Catalog, CveRec
from .generate import Builder
from .ground_truth import Decoy, GroundTruth, PlantedHop, PlantedPath, SharedInfra
from .model import Asset, DataStore, Identity, Secret, Software
from .names import role_name

WEB = ["apache:tomcat", "apache:http_server", "oracle:weblogic_server", "apache:struts"]
VPN = ["fortinet:fortios", "ivanti:connect_secure", "paloaltonetworks:pan-os", "cisco:ios_xe"]
DB = ["postgresql:postgresql", "oracle:mysql", "microsoft:sql_server", "mongodb:mongodb"]
SSH = ["openbsd:openssh"]
PRIVESC = [
    "linux:linux_kernel",
    "canonical:ubuntu_linux",
    "redhat:enterprise_linux",
    "polkit_project:polkit",
]
APP = ["vmware:spring_framework", "jenkins:jenkins", "atlassian:confluence_server"]


class Spine:
    """Accumulates a planted path's hops as the planter wires its edges."""

    def __init__(self, name: str, difficulty: str) -> None:
        self.path = PlantedPath(name=name, difficulty=difficulty, target="")

    def hop(self, rule: str, technique: str, src: str, dst: str) -> str:
        self.path.hops.append(PlantedHop(rule, technique, src, dst))
        return dst


class Planter:
    def __init__(self, b: Builder, catalog: Catalog) -> None:
        self.b = b
        self.cat = catalog
        self.rng = b.rng
        self.shape = b.shape
        self.gt = GroundTruth(org=b.org, seed=b.ds.seed, scale=b.ds.scale)

    # --- low-level node + hop helpers -------------------------------------
    def _asset(self, zone: str, kind: str, *, cloud: bool | None = None) -> Asset:
        return self.b.asset(zone, kind, "prod", cloud=cloud)

    def _vuln_software(
        self, asset: Asset, product_ids: list[str], **preds
    ) -> tuple[Software, CveRec, str, object]:
        """Put software on `asset` that carries a CVE matching `preds`, with a
        Finding. Returns (software, cve, finding_id, product_spec)."""
        from reachable_intel.products import PRODUCTS_BY_ID

        hit = self.cat.pick_for(self.rng, product_ids, **preds)
        if hit is None:  # widen to the whole catalog if this product group had none
            hit = self.cat.pick_for(self.rng, list(self.cat.by_product), **preds)
        assert hit is not None, f"no CVE in snapshot matching {preds}"
        pid, rec = hit
        spec = PRODUCTS_BY_ID[pid]
        sw = self.b.run_software(asset, spec)
        vuln = self.b.add_vuln(sw, rec)
        finding = self.b.add_finding(asset, vuln)
        return sw, rec, finding.id, spec

    def _node(self, prefix: str, obj) -> str:
        return f"{prefix}:{obj.id}"

    # --- hop builders (each wires edges AND records the hop) --------------
    def start_public(self, spine: Spine, asset: Asset, *, medium: bool = False) -> str:
        preds = (
            dict(network=True, min_cvss=4.0, max_cvss=6.9)
            if medium
            else dict(network=True, min_cvss=7.0)
        )
        products = WEB if self.shape.exposed_zone in ("edge", "dmz") else VPN
        self._vuln_software(asset, products, **preds)
        self.b.expose(asset, 443)
        return spine.hop("exploit_public_facing", "T1190", "internet", self._node("asset", asset))

    def remote(self, spine: Spine, src: Asset, dst: Asset, products: list[str]) -> str:
        # The CAN_REACH port must match the service's real listening port, or
        # the oracle's exploit_remote_service port check won't fire.
        _, _, _, spec = self._vuln_software(dst, products, network=True, min_cvss=7.0)
        port = spec.ports[0] if spec.ports else 443
        self.b.reach(src, dst, port)
        return spine.hop(
            "exploit_remote_service", "T1210", self._node("asset", src), self._node("asset", dst)
        )

    def privesc(self, spine: Spine, asset: Asset) -> str:
        self._vuln_software(asset, PRIVESC, local=True, privesc=True)
        return spine.hop("local_privesc", "T1068", self._node("asset", asset), f"priv:{asset.id}")

    def creds(self, spine: Spine, holder_node: str, asset: Asset, secret: Secret) -> str:
        self.b.holds(asset, secret)
        return spine.hop("creds_in_files", "T1552.001", holder_node, self._node("secret", secret))

    def ssh(self, spine: Spine, secret: Secret, asset: Asset) -> str:
        self.b.unlocks(secret, asset.id)
        return spine.hop(
            "ssh_with_stolen_key",
            "T1021.004",
            self._node("secret", secret),
            self._node("asset", asset),
        )

    def db_unlock(self, spine: Spine, secret: Secret, ds: DataStore) -> str:
        self.b.unlocks(secret, ds.id)
        return spine.hop(
            "db_with_password", "T1078", self._node("secret", secret), self._node("ds", ds)
        )

    def imds(self, spine: Spine, asset: Asset, role: Identity) -> str:
        self.b.assumes(asset, role)
        return spine.hop(
            "instance_metadata", "T1552.005", self._node("asset", asset), self._node("ident", role)
        )

    def use_key(self, spine: Spine, secret: Secret, role: Identity) -> str:
        self.b.unlocks(secret, role.id)
        return spine.hop(
            "use_cloud_account",
            "T1078.004",
            self._node("secret", secret),
            self._node("ident", role),
        )

    def assume(self, spine: Spine, role: Identity, role2: Identity) -> str:
        self.b.can_assume(role, role2)
        return spine.hop(
            "use_cloud_account", "T1078.004", self._node("ident", role), self._node("ident", role2)
        )

    def read_store(self, spine: Spine, role: Identity, ds: DataStore) -> str:
        self.b.can(role, ds.id, "read")
        return spine.hop(
            "read_cloud_storage", "T1530", self._node("ident", role), self._node("ds", ds)
        )

    # --- crown jewels ------------------------------------------------------
    def make_crown(self) -> DataStore:
        kind = "bucket" if self.shape.cloud else "warehouse"
        ds = self.b.datastore(kind, crown=True, sensitivity="crown")
        self.gt.crown_jewels.append(f"ds:{ds.id}")
        return ds

    # --- path templates ----------------------------------------------------
    def path_easy_web_db(self, crown: DataStore, medium: bool = False) -> PlantedPath:
        """internet -> web (exploit) -> db host (exploit) -> db_password -> crown."""
        name = "medium_start_web_db" if medium else "easy_web_db"
        s = Spine(name, "medium" if medium else "easy")
        web = self._asset(self.shape.exposed_zone, "web_server")
        self.start_public(s, web, medium=medium)
        dbhost = self._asset(self.shape.crown_zone, "db_host")
        self.remote(s, web, dbhost, products=DB)
        sec = self.b.secret("db_password")
        self.creds(s, self._node("asset", dbhost), dbhost, sec)
        self.db_unlock(s, sec, crown)
        s.path.target = f"ds:{crown.id}"
        return s.path

    def path_ssh_chain(self, crown: DataStore) -> PlantedPath:
        """internet -> web(MEDIUM) -> ssh_key creds -> ssh to box -> db_password -> crown."""
        s = Spine("hard_ssh_chain", "hard")
        web = self._asset(self.shape.exposed_zone, "web_server")
        self.start_public(s, web, medium=True)
        key = self.b.secret("ssh_key")
        self.creds(s, self._node("asset", web), web, key)
        box = self._asset(self.shape.crown_zone, "server")
        self.ssh(s, key, box)
        dbpw = self.b.secret("db_password")
        self.creds(s, self._node("asset", box), box, dbpw)
        self.db_unlock(s, dbpw, crown)
        s.path.target = f"ds:{crown.id}"
        return s.path

    def path_privesc_root_secret(self, crown: DataStore) -> PlantedPath:
        """internet -> web -> local privesc -> root-owned ssh_key -> ssh -> db_password -> crown."""
        s = Spine("hard_privesc_root_secret", "hard")
        web = self._asset(self.shape.exposed_zone, "web_server")
        self.start_public(s, web)
        self.privesc(s, web)
        rootkey = self.b.secret("ssh_key", requires_priv=True)
        self.creds(s, f"priv:{web.id}", web, rootkey)  # needs privilege to read
        box = self._asset(self.shape.crown_zone, "server")
        self.ssh(s, rootkey, box)
        dbpw = self.b.secret("db_password")
        self.creds(s, self._node("asset", box), box, dbpw)
        self.db_unlock(s, dbpw, crown)
        s.path.target = f"ds:{crown.id}"
        return s.path

    def path_imds_bucket(self, crown: DataStore) -> PlantedPath:
        """internet -> web -> remote -> instance role (IMDS) -> read bucket (crown). Cloud only."""
        s = Spine("hard_imds_bucket", "hard")
        web = self._asset(self.shape.exposed_zone, "web_server", cloud=True)
        self.start_public(s, web)
        svc = self._asset("k8s", "k8s_node", cloud=True)
        self.remote(s, web, svc, products=APP)
        role = self.b.identity("Role", role_name("node", 1))
        self.imds(s, svc, role)
        self.read_store(s, role, crown)
        s.path.target = f"ds:{crown.id}"
        return s.path

    def path_cloudkey_assume(self, crown: DataStore) -> PlantedPath:
        """internet -> web -> cloud_key -> assume role -> assume admin role -> read bucket."""
        s = Spine("hard_cloudkey_assume", "hard")
        web = self._asset(self.shape.exposed_zone, "web_server", cloud=True)
        self.start_public(s, web)
        ckey = self.b.secret("cloud_key")
        self.creds(s, self._node("asset", web), web, ckey)
        role = self.b.identity("Role", role_name("ci", 1))
        self.use_key(s, ckey, role)
        admin = self.b.identity("Role", role_name("data-admin", 1), over_broad=True)
        self.assume(s, role, admin)
        self.read_store(s, admin, crown)
        s.path.target = f"ds:{crown.id}"
        return s.path

    # --- shared infrastructure ----------------------------------------------
    # The spines above share no intermediate node, so every path needs its own
    # fix and min-cut == path count. Real orgs have funnels: one CI runner every
    # service can call, one jump host, one vendor VPN gateway. These templates
    # plant such a funnel; the shared hop's single fix token then cuts several
    # paths at once.

    def _reach_existing(self, spine: Spine, src: Asset, dst: Asset, port: int) -> str:
        """exploit_remote_service into an asset whose vulnerable software is
        ALREADY planted: reuse its one Finding, so every path into it shares one
        fix token (that is what makes it a funnel)."""
        self.b.reach(src, dst, port)
        return spine.hop(
            "exploit_remote_service", "T1210", self._node("asset", src), self._node("asset", dst)
        )

    def paths_shared_ci_runner(self, crown: DataStore, services: int = 3) -> list[PlantedPath]:
        """org_a. Several internet-facing services post build hooks to ONE CI
        runner; the runner carries a deploy cloud key whose role reads the crown.
            internet -> svc_i (exploit) -> ci runner (exploit, one shared finding)
                     -> deploy cloud_key -> role-deploy -> crown bucket
        """
        runner = self._asset("ci", "ci_runner", cloud=True)
        _, _, _, spec = self._vuln_software(runner, ["jenkins:jenkins"], network=True, min_cvss=7.0)
        port = spec.ports[0] if spec.ports else 8080
        key = self.b.secret("cloud_key")
        role = self.b.identity("Role", role_name("deploy", 1))
        self.b.holds(runner, key)
        self.b.unlocks(key, role.id)
        self.b.can(role, crown.id, "read")
        runner_n, key_n, role_n = (
            self._node("asset", runner),
            self._node("secret", key),
            self._node("ident", role),
        )
        paths = []
        for i in range(services):
            s = Spine(f"hard_shared_ci_runner_{i + 1}", "hard")
            web = self._asset(self.shape.exposed_zone, "web_server", cloud=True)
            self.start_public(s, web)
            self._reach_existing(s, web, runner, port)
            s.hop("creds_in_files", "T1552.001", runner_n, key_n)
            s.hop("use_cloud_account", "T1078.004", key_n, role_n)
            s.hop("read_cloud_storage", "T1530", role_n, self._node("ds", crown))
            s.path.target = f"ds:{crown.id}"
            paths.append(s.path)
        self.gt.shared_infra.append(
            SharedInfra(
                kind="ci_runner",
                node=runner_n,
                note=f"Shared CI runner reachable from {services} internet-facing services on "
                f":{port}; it holds the deploy cloud key. Patching it cuts all {services} paths.",
                paths=[p.name for p in paths],
            )
        )
        return paths

    def shared_jump_host_blocked(self, crown: DataStore, via: list[PlantedPath]) -> None:
        """org_b, the contrast case. The DMZ web servers of `via` can all reach
        ONE legacy admin jump host that holds a DB password for the crown store,
        but a WAF rule blocks the jump host's vuln. The funnel exists on the
        network, yet no attack path crosses it, so min-cut stays == path count."""
        jump = self._asset("admin", "jump_host")
        sw, rec, _, spec = self._vuln_software(jump, APP + WEB, network=True, min_cvss=7.0)
        port = spec.ports[0] if spec.ports else 8080
        ctl = self.b.control("waf", self.b._vulns[f"{sw.id}:{rec.id}"], jump.id)
        pw = self.b.secret("db_password")
        self.b.holds(jump, pw)
        self.b.unlocks(pw, crown.id)
        for p in via:
            self.b.reach(self.b.by_id[p.hops[0].dst.split(":", 1)[1]], jump, port)
        self.gt.shared_infra.append(
            SharedInfra(
                kind="jump_host",
                node=self._node("asset", jump),
                note=f"Legacy admin jump host reachable from {len(via)} DMZ web servers on "
                f":{port} and holding a crown DB password, but its vuln is blocked by WAF "
                f"control {ctl.id}: no path crosses it.",
                blocked_by=ctl.id,
            )
        )

    def paths_shared_vpn_gateway(self, crown: DataStore) -> list[PlantedPath]:
        """org_c. ONE vendor VPN gateway is the shared entry of two routes:
            a) gateway -> on-prem server (exploit) -> db_password -> crown
            b) gateway -> vendor-support ssh_key -> mgmt server -> db_password -> crown
        Patching the gateway (one fix) cuts both."""
        gw = self._asset(self.shape.exposed_zone, "gateway")
        a = Spine("medium_shared_vpn_onprem", "medium")
        v = Spine("hard_shared_vpn_vendor_key", "hard")
        self.start_public(a, gw)
        v.path.hops.append(a.path.hops[0])  # the same entry hop (same finding) for both
        srv = self._asset("onprem", "server")
        self.remote(a, gw, srv, products=DB)
        pw1 = self.b.secret("db_password")
        self.creds(a, self._node("asset", srv), srv, pw1)
        self.db_unlock(a, pw1, crown)
        key = self.b.secret("ssh_key")
        self.creds(v, self._node("asset", gw), gw, key)
        mgmt = self._asset("mgmt", "mgmt_server")
        self.ssh(v, key, mgmt)
        pw2 = self.b.secret("db_password")
        self.creds(v, self._node("asset", mgmt), mgmt, pw2)
        self.db_unlock(v, pw2, crown)
        a.path.target = v.path.target = f"ds:{crown.id}"
        self.gt.shared_infra.append(
            SharedInfra(
                kind="vpn_gateway",
                node=self._node("asset", gw),
                note="Vendor VPN gateway is the shared entry of two routes (on-prem exploit, "
                "vendor-support SSH key). Patching it cuts both.",
                paths=[a.path.name, v.path.name],
            )
        )
        return [a.path, v.path]

    # --- decoys ------------------------------------------------------------
    def decoy_severity(self) -> Decoy:
        """Critical + KEV vuln in an isolated zone: unreachable despite the score."""
        iso = self.b.zone(_iso_zonespec(self.b.org))
        a = self._asset_in_zone_id(iso.id, "isolated_host")
        sw, rec, fid, _ = self._vuln_software(a, WEB + DB, network=True, kev=True, min_cvss=9.0)
        return Decoy(
            kind="severity",
            note="CVSS>=9.0 KEV vuln with no route from the Internet (isolated zone).",
            asset=a.id,
            finding_ids=[fid],
            vuln_cves=[rec.id],
        )

    def decoy_mitigated(self) -> Decoy:
        """Exposed exploitable asset where a Control blocks the exploit step."""
        a = self._asset(self.shape.exposed_zone, "web_server")
        sw, rec, fid, _ = self._vuln_software(a, WEB, network=True, min_cvss=9.0)
        self.b.expose(a, 443)
        vuln_id = self.b._vulns[f"{sw.id}:{rec.id}"]
        self.b.control("waf", vuln_id, a.id)
        return Decoy(
            kind="mitigated",
            note="Internet-exposed critical vuln, but a WAF Control MITIGATES it on this asset.",
            asset=a.id,
            finding_ids=[fid],
            vuln_cves=[rec.id],
        )

    def decoy_dead_end(self) -> Decoy:
        """Exposed exploitable asset that the attacker lands on but that reaches nothing."""
        a = self._asset(self.shape.exposed_zone, "web_server")
        sw, rec, fid, _ = self._vuln_software(a, WEB, network=True, min_cvss=9.0)
        self.b.expose(a, 443)
        return Decoy(
            kind="dead_end",
            note="Internet-exposed, exploitable, but no onward reach and no useful secret.",
            asset=a.id,
            finding_ids=[fid],
            vuln_cves=[rec.id],
        )

    def _asset_in_zone_id(self, zone_id_full: str, kind: str) -> Asset:
        short = zone_id_full.split("zone:")[1]
        if short not in self.b.zone_assets:
            self.b.zone_assets[short] = []
        return self.b.asset(short, kind, "prod")

    # --- over-broad roles (realism) ---------------------------------------
    def over_broad_roles(self) -> None:
        """A couple of over-permissive roles with read on NON-crown stores."""
        for i in range(2):
            ds = self.b.datastore("bucket", crown=False, sensitivity="high")
            role = self.b.identity("Role", role_name("broad", i + 1), over_broad=True)
            self.b.can(role, ds.id, "read")


def _iso_zonespec(org: str):
    from .generate import ZoneSpec

    return ZoneSpec(
        id="quarantine", name="Isolated / quarantine", trust=9, categories=(), base_assets=0
    )


def plant_org(b: Builder, catalog: Catalog) -> GroundTruth:
    p = Planter(b, catalog)
    crown = p.make_crown()

    p.over_broad_roles()

    # Choose templates per org shape. Every org gets >=1 easy, >=1 medium-start,
    # and >=2 hard with a non-network hop.
    paths: list[PlantedPath] = [
        p.path_easy_web_db(crown),
        p.path_easy_web_db(crown, medium=True),  # medium CVE on an internet asset
        p.path_ssh_chain(crown),
        p.path_privesc_root_secret(crown),
    ]
    if b.shape.cloud:
        paths.append(p.path_imds_bucket(crown))
        paths.append(p.path_cloudkey_assume(crown))

    # Shared infrastructure: org_a and org_c get a real funnel (min-cut < path
    # count); org_b keeps independent paths for contrast (its funnel is blocked).
    if b.org == "org_a":
        paths += p.paths_shared_ci_runner(crown)
    elif b.org == "org_b":
        p.shared_jump_host_blocked(crown, via=paths[:2])
    elif b.org == "org_c":
        paths += p.paths_shared_vpn_gateway(crown)
    p.gt.paths = paths

    p.gt.decoys = [p.decoy_severity(), p.decoy_mitigated(), p.decoy_dead_end()]
    return p.gt
