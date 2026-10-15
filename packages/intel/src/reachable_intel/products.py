"""The catalog of vendor:product pairs the synthetic orgs run.

Every pair uses a REAL NVD CPE vendor:product string, so the NVD
`virtualMatchString=cpe:2.3:a:<vendor>:<product>` filter actually returns that
product's CVEs. The org generator (packages/orggen) only ever references these
products, which is how a Finding's CVE is guaranteed to affect the Software it
sits on.

We deliberately include LOCAL-vector-heavy products (linux_kernel, sudo,
polkit, openssh) so the `local_privesc` attack rule has genuine CVEs to use,
not just network-exploitable ones.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProductSpec:
    vendor: str  # NVD CPE vendor
    product: str  # NVD CPE product
    name: str  # human label
    category: str  # placement hint for the org generator
    ports: tuple[int, ...]  # ports this product typically listens on
    versions: tuple[str, ...] = field(default_factory=tuple)  # plausible versions
    # CPE "part": 'a' application (default), 'o' operating system / network OS.
    # It must match NVD's CPE or virtualMatchString returns nothing — kernels,
    # Linux distros and firewall OSes are 'o', not 'a'.
    part: str = "a"

    @property
    def id(self) -> str:
        return f"{self.vendor}:{self.product}"


# ~40 pairs across web servers, VPN gateways, CI tools, databases, frameworks,
# remote access, and OS packages.
KNOWN_PRODUCTS: list[ProductSpec] = [
    # --- Web servers / reverse proxies (DMZ, internet-facing) ---
    ProductSpec(
        "apache", "http_server", "Apache httpd", "web", (80, 443), ("2.4.49", "2.4.52", "2.4.58")
    ),
    ProductSpec("nginx", "nginx", "nginx", "web", (80, 443), ("1.20.1", "1.24.0", "1.25.3")),
    ProductSpec(
        "apache", "tomcat", "Apache Tomcat", "web", (8080, 8443), ("9.0.46", "9.0.75", "10.1.8")
    ),
    ProductSpec(
        "oracle",
        "weblogic_server",
        "Oracle WebLogic",
        "web",
        (7001,),
        ("12.2.1.3", "12.2.1.4", "14.1.1"),
    ),
    # --- VPN / remote-access gateways (internet-facing, KEV-heavy) ---
    ProductSpec(
        "fortinet",
        "fortios",
        "Fortinet FortiOS",
        "vpn",
        (443, 10443),
        ("7.0.5", "7.2.1", "7.2.4"),
        part="o",
    ),
    ProductSpec(
        "ivanti", "connect_secure", "Ivanti Connect Secure", "vpn", (443,), ("9.1", "22.3", "22.5")
    ),
    ProductSpec(
        "citrix",
        "application_delivery_controller",
        "Citrix ADC/NetScaler",
        "vpn",
        (443,),
        ("12.1", "13.0", "13.1"),
    ),
    ProductSpec(
        "paloaltonetworks",
        "pan-os",
        "Palo Alto PAN-OS",
        "vpn",
        (443,),
        ("10.1", "10.2", "11.0"),
        part="o",
    ),
    # --- CI / developer tooling ---
    ProductSpec("jenkins", "jenkins", "Jenkins", "ci", (8080,), ("2.361", "2.401", "2.426")),
    ProductSpec("gitlab", "gitlab", "GitLab", "ci", (443, 80), ("15.6.0", "16.1.0", "16.5.0")),
    ProductSpec(
        "jetbrains",
        "teamcity",
        "JetBrains TeamCity",
        "ci",
        (8111,),
        ("2022.10", "2023.05", "2023.11"),
    ),
    ProductSpec(
        "atlassian",
        "confluence_server",
        "Atlassian Confluence",
        "ci",
        (8090,),
        ("7.13", "7.19", "8.5"),
    ),
    ProductSpec(
        "atlassian", "jira_server", "Atlassian Jira", "ci", (8080,), ("8.20", "9.4", "9.11")
    ),
    # --- Secrets / orchestration ---
    ProductSpec(
        "hashicorp", "vault", "HashiCorp Vault", "secrets", (8200,), ("1.11.0", "1.13.0", "1.15.0")
    ),
    ProductSpec(
        "kubernetes",
        "kubernetes",
        "Kubernetes API server",
        "orchestrator",
        (6443,),
        ("1.24.0", "1.27.0", "1.28.2"),
    ),
    # --- Databases / data stores ---
    ProductSpec("postgresql", "postgresql", "PostgreSQL", "db", (5432,), ("13.7", "14.9", "15.4")),
    ProductSpec("oracle", "mysql", "MySQL", "db", (3306,), ("5.7.38", "8.0.33", "8.0.35")),
    ProductSpec("mongodb", "mongodb", "MongoDB", "db", (27017,), ("4.4.18", "5.0.14", "6.0.6")),
    ProductSpec("redis", "redis", "Redis", "cache", (6379,), ("6.2.7", "7.0.11", "7.2.1")),
    ProductSpec(
        "elastic", "elasticsearch", "Elasticsearch", "db", (9200,), ("7.17.0", "8.6.0", "8.10.0")
    ),
    ProductSpec(
        "microsoft", "sql_server", "Microsoft SQL Server", "db", (1433,), ("2016", "2019", "2022")
    ),
    # --- Application frameworks / libraries (bundled into app assets) ---
    ProductSpec(
        "vmware",
        "spring_framework",
        "Spring Framework",
        "framework",
        (8080,),
        ("5.3.17", "5.3.26", "6.0.9"),
    ),
    ProductSpec(
        "apache", "struts", "Apache Struts", "framework", (8080,), ("2.5.26", "2.5.30", "6.1.2")
    ),
    ProductSpec("apache", "log4j", "Apache Log4j", "framework", (), ("2.14.1", "2.17.0", "2.20.0")),
    ProductSpec(
        "fasterxml",
        "jackson-databind",
        "Jackson Databind",
        "framework",
        (),
        ("2.9.10", "2.13.0", "2.15.2"),
    ),
    ProductSpec("openssl", "openssl", "OpenSSL", "framework", (), ("1.1.1", "3.0.7", "3.0.11")),
    # --- Remote access / OS packages (SSH, local privesc targets) ---
    ProductSpec("openbsd", "openssh", "OpenSSH", "ssh", (22,), ("8.2p1", "8.9p1", "9.3p1")),
    ProductSpec(
        "linux", "linux_kernel", "Linux kernel", "os", (), ("5.4.0", "5.15.0", "6.1.0"), part="o"
    ),
    ProductSpec(
        "canonical", "ubuntu_linux", "Ubuntu", "os", (), ("20.04", "22.04", "23.04"), part="o"
    ),
    ProductSpec("redhat", "enterprise_linux", "RHEL", "os", (), ("8.6", "9.0", "9.2"), part="o"),
    ProductSpec("sudo", "sudo", "sudo", "os", (), ("1.8.31", "1.9.11", "1.9.14")),
    ProductSpec("polkit_project", "polkit", "polkit", "os", (), ("0.105", "0.117", "0.120")),
    ProductSpec("samba", "samba", "Samba", "fileshare", (445,), ("4.13.0", "4.17.0", "4.19.0")),
    # --- Collaboration / mail / transfer (internet-facing, KEV favourites) ---
    ProductSpec(
        "microsoft",
        "exchange_server",
        "Microsoft Exchange",
        "mail",
        (443,),
        ("2016", "2019", "2019-cu12"),
    ),
    ProductSpec(
        "progress",
        "moveit_transfer",
        "Progress MOVEit Transfer",
        "transfer",
        (443,),
        ("2021.0", "2022.0", "2023.0"),
    ),
    ProductSpec("grafana", "grafana", "Grafana", "bi", (3000,), ("8.5.0", "9.5.0", "10.1.0")),
    ProductSpec("zabbix", "zabbix", "Zabbix", "bi", (10051,), ("5.0", "6.0", "6.4")),
    ProductSpec(
        "apache", "activemq", "Apache ActiveMQ", "mq", (61616,), ("5.16.0", "5.17.0", "5.18.0")
    ),
    ProductSpec(
        "vmware", "vcenter_server", "VMware vCenter", "orchestrator", (443,), ("6.7", "7.0", "8.0")
    ),
    ProductSpec(
        "cisco", "ios_xe", "Cisco IOS XE", "vpn", (443,), ("16.12", "17.3", "17.6"), part="o"
    ),
]

PRODUCTS_BY_ID: dict[str, ProductSpec] = {p.id: p for p in KNOWN_PRODUCTS}
KNOWN_PAIRS: set[str] = set(PRODUCTS_BY_ID)


def cpe_match_string(spec: ProductSpec) -> str:
    """NVD virtualMatchString for an application CPE."""
    return f"cpe:2.3:{spec.part}:{spec.vendor}:{spec.product}"
