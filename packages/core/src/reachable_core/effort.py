"""Effort estimates for fix tokens (1 = trivial .. 5 = a project).

min_cut's default answers "the FEWEST fixes that cut every path". Fixes are not
equally hard, though: patching a web server is an afternoon, upgrading a vendor
VPN appliance needs a maintenance window and the vendor. With an effort per fix
token, max-flow can use effort as the capacity instead of 1, and the minimum
cut becomes the CHEAPEST set of fixes by total effort.

THIS IS A MODELLING CHOICE, NOT A FACT, exactly like exploit_likelihood. Two
inputs, both already in the graph:

  * what the fix touches:
      - a Finding token -> the kind of Asset it is ON (KIND_EFFORT);
      - a step:* token  -> the kind of step (STEP_EFFORT), e.g. rotating a
        production DB password (3) vs removing one read grant (2);
  * who owns it: +Team.change_effort (1 for a team under a change freeze).

Clamped to [1, 5]. Shared by the Cypher derivation (which stamps `effort` on
each fix gate of the FLOW layer) and the oracle (which recomputes it in Python),
so the two cheapest cuts can be compared.
"""

from __future__ import annotations

MIN_EFFORT, MAX_EFFORT = 1, 5

# Patch / upgrade effort by the kind of asset the finding is on.
KIND_EFFORT: dict[str, int] = {
    "web_server": 1,
    "workstation": 1,
    "load_balancer": 2,
    "k8s_node": 2,
    "app_server": 2,
    "server": 2,
    "isolated_host": 2,
    "db_host": 3,
    "managed_db": 3,
    "mgmt_server": 3,
    "admin_host": 3,
    "jump_host": 3,
    "secrets_vault": 3,
    "ci_runner": 4,  # every pipeline depends on it
    "gateway": 5,  # vendor appliance: firmware, maintenance window, vendor ticket
}
DEFAULT_KIND_EFFORT = 2

# Effort of removing a credential / permission step, by attack rule.
STEP_EFFORT: dict[str, int] = {
    "creds_in_files": 2,  # move the secret into a vault
    "ssh_with_stolen_key": 2,  # rotate the key, prune authorized_keys
    "db_with_password": 3,  # rotate a production DB password used by apps
    "use_cloud_account": 2,  # revoke a key / drop an assume-role grant
    "instance_metadata": 3,  # detach the role or enforce IMDSv2 hop limits
    "read_cloud_storage": 2,  # remove one read grant
}

# For a step token, the node whose owner pays for the fix: the rule's source
# (the host holding the secret, the instance with the role) or its target
# (the host trusting the key, the data store whose password rotates).
FIX_AT_SOURCE = {"creds_in_files", "instance_metadata", "use_cloud_account"}


def clamp_effort(x: int) -> int:
    return max(MIN_EFFORT, min(MAX_EFFORT, x))


def finding_effort(asset_kind: str | None, change_effort: int = 0) -> int:
    return clamp_effort(KIND_EFFORT.get(asset_kind or "", DEFAULT_KIND_EFFORT) + change_effort)


def step_effort(rule: str, change_effort: int = 0) -> int:
    return clamp_effort(STEP_EFFORT.get(rule, DEFAULT_KIND_EFFORT) + change_effort)
