"""Deterministic fictional naming. Invented words only.

No real company names and no real people's names. Users and roles get
synthetic handles (role + number). People in the company layer get a name built
from two invented word lists (fantasy given names + made-up compound surnames),
so they read like people in a demo but are obviously fictional, in keeping with
the hackathon's "public or synthetic only" rule.
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


# Invented given names and compound surnames. Combinations are drawn without
# replacement, so a person name is unique within an org.
_GIVEN = [
    "Avrel",
    "Brisa",
    "Corvan",
    "Dalia",
    "Emrik",
    "Fenna",
    "Galen",
    "Hollis",
    "Isolde",
    "Jarek",
    "Kesia",
    "Lorcan",
    "Mireth",
    "Nilo",
    "Orrin",
    "Pell",
    "Quenna",
    "Rowan",
    "Sefa",
    "Tamsin",
    "Ulric",
    "Vesna",
    "Wrenna",
    "Yara",
    "Zev",
]
_SURNAME = [
    "Ashgrove",
    "Brindlecombe",
    "Coldwater",
    "Dunmere",
    "Elderhaze",
    "Fallowmere",
    "Greythorn",
    "Hollowell",
    "Ironvale",
    "Juniperfield",
    "Kestrelholm",
    "Larkspur",
    "Mossbank",
    "Northwick",
    "Oakenshaw",
    "Pebblestone",
    "Quarrington",
    "Ravensmere",
    "Saltmarsh",
    "Thistledown",
]

# Invented partner names for decision records ("opened for the X integration").
PARTNERS = [
    "Vantirra Pay",
    "Oskelund Media",
    "Marrowgate Supply",
    "Quillon Travel",
    "Brightfen Health",
    "Calderra Freight",
    "Lumisk Analytics",
]


def person_names(rng: random.Random, n: int) -> list[str]:
    """n distinct invented 'Given Surname' names."""
    pool = [f"{g} {s}" for g in _GIVEN for s in _SURNAME]
    return rng.sample(pool, n)


def user_handle(n: int) -> str:
    return f"user-{n:04d}"


def role_name(purpose: str, n: int) -> str:
    return f"role-{purpose}-{n:02d}"


def service_account(purpose: str, n: int) -> str:
    return f"svc-{purpose}-{n:02d}"
