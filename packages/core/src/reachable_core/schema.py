"""Graph names, node labels, edge types and index declarations.

One place that names every graph and every label so loaders, the API and tests
cannot drift apart. FalkorDB keeps all graphs in one server keyed by name.
"""

from __future__ import annotations

# --- Graph names ---
THREATINTEL_GRAPH = "threatintel"
ORG_GRAPHS = ["org_a", "org_b", "org_c"]

# --- Threat-intel node labels + id property for each ---
# Indexes go on the id property of every node so joins/merges are index-backed.
THREATINTEL_INDEXES: dict[str, str] = {
    "CVE": "id",
    "CWE": "id",
    "Product": "id",
    "Technique": "id",
    "Tactic": "id",
}

# --- Org graph node labels + the property we index (all ids) ---
# Identity is a supertype carrying one of the labels User / Role / ServiceAccount.
ORG_INDEXES: dict[str, str] = {
    "Asset": "id",
    "Software": "id",
    "Vuln": "id",
    "Finding": "id",
    "Identity": "id",
    "Secret": "id",
    "DataStore": "id",
    "Control": "id",
    "Zone": "id",
    "Internet": "id",
}

# Identity sub-labels (an Identity node also carries exactly one of these).
IDENTITY_KINDS = ["User", "Role", "ServiceAccount"]


# Severity bands by CVSS v3 base score (NVD's own thresholds).
def severity_band(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0.0:
        return "LOW"
    return "NONE"
