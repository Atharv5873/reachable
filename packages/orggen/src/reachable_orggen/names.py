"""Deterministic fictional naming. Invented words only.

No real company names and no real people's names. Persons/users get synthetic
handles (role + number), not human names, which also keeps the data obviously
fictional for the hackathon's "public or synthetic only" rule.
"""

from __future__ import annotations

import random

# Invented org display names, one per org id.
ORG_DISPLAY = {
    "org_a": "Nimbarix",  # cloud-native SaaS
    "org_b": "Marketly",  # retail web
    "org_c": "Ferrocast",  # hybrid industrial
}

_ADJ = ["swift", "amber", "cobalt", "ember", "fjord", "quartz", "vireo", "zephyr", "onyx", "larch"]
_NOUN = [
    "falcon",
    "harbor",
    "meadow",
    "pylon",
    "tessera",
    "basalt",
    "cinder",
    "willow",
    "sol",
    "vane",
]


def host_name(rng: random.Random, zone: str, n: int) -> str:
    """A stable-looking hostname like 'cobalt-falcon-dmz-07'."""
    return f"{rng.choice(_ADJ)}-{rng.choice(_NOUN)}-{zone}-{n:02d}"


def user_handle(n: int) -> str:
    return f"user-{n:04d}"


def role_name(purpose: str, n: int) -> str:
    return f"role-{purpose}-{n:02d}"


def service_account(purpose: str, n: int) -> str:
    return f"svc-{purpose}-{n:02d}"
