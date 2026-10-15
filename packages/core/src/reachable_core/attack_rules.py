"""Attack rules: the single source of truth for "when can an attacker take one step".

These pure, documented Python rules define the *semantics* of an attack edge.
Two independent consumers implement exactly this spec:

  1. The generator's networkx oracle (packages/orggen/oracle.py), which builds
     the attack graph in pure Python and computes ground-truth paths + min-cut.
  2. S2's FalkorDB Cypher derivation, which must reproduce the same edges.

Keeping the rules here — as data plus a documented likelihood formula — means
the oracle and the graph queries can never silently disagree: both cite the
same rule names and the same ATT&CK technique ids.

Each rule is one *step* an attacker takes to move from a precondition (a node
they already control / a capability they already hold) to a new foothold.

ATT&CK technique ids are validated against the committed ATT&CK snapshot by a
test (tests/test_rules.py); if MITRE renames or revokes one we find out there.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackRule:
    """One attacker step.

    name       : stable identifier, used in labels.json and Cypher comments.
    step       : plain-English precondition -> postcondition.
    technique  : MITRE ATT&CK (Enterprise) technique id.
    cost       : traversal weight for "cheapest path" ranking. Higher = harder.
                 A modelling choice: exploitation costs more than reusing a
                 credential the attacker already holds.
    exploit    : True if the step's likelihood is computed from a CVE's signals
                 (via exploit_likelihood); False if it is a fixed likelihood
                 because no exploitation is involved (e.g. reusing a stolen key).
    likelihood : the fixed 0..1 likelihood for non-exploit steps. Ignored for
                 exploit steps, whose likelihood comes from the vuln.
    """

    name: str
    step: str
    technique: str
    cost: float
    exploit: bool
    likelihood: float = 1.0


# ---------------------------------------------------------------------------
# The rule table. Order is roughly "how an intrusion unfolds".
# ---------------------------------------------------------------------------
RULES: dict[str, AttackRule] = {
    "exploit_public_facing": AttackRule(
        name="exploit_public_facing",
        step=(
            "Internet -> an internet-exposed Asset running Software with a "
            "network-vector CVE, where no Control blocks the step."
        ),
        technique="T1190",  # Exploit Public-Facing Application
        cost=2.0,
        exploit=True,
    ),
    "exploit_remote_service": AttackRule(
        name="exploit_remote_service",
        step=(
            "A compromised Asset -> another Asset it CAN_REACH on the vulnerable "
            "port, where that asset runs software with a network/adjacent-vector CVE."
        ),
        technique="T1210",  # Exploitation of Remote Services
        cost=2.0,
        exploit=True,
    ),
    "ssh_with_stolen_key": AttackRule(
        name="ssh_with_stolen_key",
        step=(
            "A compromised Asset HOLDS an ssh_key Secret that UNLOCKS another Asset -> that asset."
        ),
        technique="T1021.004",  # Remote Services: SSH
        cost=1.0,
        exploit=False,
        likelihood=0.95,  # holding the key makes the hop near-certain
    ),
    "creds_in_files": AttackRule(
        name="creds_in_files",
        step="A compromised Asset -> a Secret stored on it (HOLDS).",
        technique="T1552.001",  # Unsecured Credentials: Credentials In Files
        cost=1.0,
        exploit=False,
        likelihood=0.9,
    ),
    "instance_metadata": AttackRule(
        name="instance_metadata",
        step=(
            "A compromised cloud Asset -> its attached Role via the instance "
            "metadata service (ASSUMES)."
        ),
        technique="T1552.005",  # Unsecured Credentials: Cloud Instance Metadata API
        cost=1.0,
        exploit=False,
        likelihood=0.9,
    ),
    "use_cloud_account": AttackRule(
        name="use_cloud_account",
        step=(
            "The holder of a Role or cloud_key -> the permissions of that Role "
            "(CAN / CAN_ASSUME edges become usable)."
        ),
        technique="T1078.004",  # Valid Accounts: Cloud Accounts
        cost=1.0,
        exploit=False,
        likelihood=0.95,
    ),
    "read_cloud_storage": AttackRule(
        name="read_cloud_storage",
        step="A Role with read on a bucket/DataStore -> that DataStore (CAN {read}).",
        technique="T1530",  # Data from Cloud Storage
        cost=1.0,
        exploit=False,
        likelihood=0.95,
    ),
    "db_with_password": AttackRule(
        name="db_with_password",
        step="The holder of a db_password Secret -> the DataStore it UNLOCKS.",
        technique="T1078",  # Valid Accounts
        cost=1.0,
        exploit=False,
        likelihood=0.95,
    ),
    "local_privesc": AttackRule(
        name="local_privesc",
        step=(
            "A compromised Asset with a local-vector privilege-escalation CVE -> "
            "'privileged on asset' (required before reading root-owned secrets)."
        ),
        technique="T1068",  # Exploitation for Privilege Escalation
        cost=3.0,
        exploit=True,
    ),
}

# Technique ids referenced above, for the validation test.
TECHNIQUE_IDS: set[str] = {r.technique for r in RULES.values()}


@dataclass(frozen=True)
class VulnSignals:
    """The public signals we denormalise onto each Vuln node and feed the formula."""

    av: str  # CVSS attack vector: NETWORK | ADJACENT_NETWORK | LOCAL | PHYSICAL
    pr: str  # privileges required: NONE | LOW | HIGH
    ui: str  # user interaction: NONE | REQUIRED
    epss: float  # FIRST EPSS probability (0..1)
    kev: bool  # CISA Known Exploited Vulnerability flag
    cvss: float = 0.0  # base score, kept for banding (not used in likelihood)


# Vectors that let one host reach another over the wire. local_privesc is the
# exception: it needs a LOCAL vector (you're already on the box).
NETWORK_VECTORS = {"NETWORK", "ADJACENT_NETWORK"}

# local_privesc only fires for LOCAL-vector vulns at or above this CVSS score
# (low-scoring local bugs are rarely a working root exploit).
PRIVESC_MIN_CVSS = 6.0

# CAN actions on a DataStore that let an identity read it (read_cloud_storage).
READ_ACTIONS = ("read", "*", "readwrite")

# Only findings a scanner still reports as open power an exploit step. A fixed
# finding is history: it stays in the graph (tickets point at it) but enables
# nothing. Shared by the oracle and the Cypher derivation.
OPEN_STATUS = "open"

# Longest attack path we enumerate or search, in hops. Shared by the oracle,
# the Cypher derivation and the tools so "a path" means the same thing everywhere.
HOP_CAP = 8


def exploit_likelihood(v: VulnSignals) -> float:
    """How likely an attacker actually pulls off exploiting this vuln (0..1).

    THIS IS A MODELLING CHOICE, NOT A FACT. We combine four public signals:

      * EPSS  — FIRST's predicted probability of exploitation in the wild. Used
                as the empirical base rate.
      * KEV   — CISA's flag that the vuln HAS been exploited in the wild. Ground
                truth beats prediction, so KEV floors the base rate at 0.85.
      * CVSS exploitability, read off the vector:
            UI:REQUIRED  -> x0.6   needs a victim to act; slower, not unattended.
            PR:HIGH      -> x0.7   attacker must already hold high privileges.
            PR:LOW       -> x0.9   a small barrier.
            PR:NONE      -> x1.0
      * The ransomware flag is deliberately NOT used here: it speaks to impact,
        not to the odds of the step succeeding.

    Clamped to [0.05, 0.99]: any known vuln has *some* chance (never 0), and we
    never claim certainty (never 1). The exact constants are tunable; what
    matters is that EPSS/KEV dominate and the CVSS vector only nudges.
    """
    base = v.epss
    if v.kev:
        base = max(base, 0.85)

    ease = 1.0
    if v.ui.upper() == "REQUIRED":
        ease *= 0.6
    pr = v.pr.upper()
    if pr == "HIGH":
        ease *= 0.7
    elif pr == "LOW":
        ease *= 0.9

    return max(0.05, min(0.99, base * ease))
