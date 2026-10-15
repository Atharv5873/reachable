"""Fetch raw public threat-intel feeds into data/threatintel/raw/.

Sources (see data/threatintel/ATTRIBUTION.md for licences):
  * CISA KEV           — one JSON download.
  * FIRST EPSS         — one gzipped CSV of the current scores.
  * NVD CVE API 2.0    — paged JSON; we pull all KEV CVEs in one shot via the
                         hasKev filter, then a capped page of recent CVEs per
                         catalog product via virtualMatchString.
  * MITRE ATT&CK       — the Enterprise STIX 2.1 bundle (one big JSON).

Raw files are gitignored; only the normalised, filtered snapshot is committed.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx

from reachable_core.settings import Settings

from .products import KNOWN_PRODUCTS, cpe_match_string

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Cap on non-KEV CVEs pulled per product, to land the total in the 2k-4k band
# without an unbounded fetch for noisy products like the Linux kernel.
PER_PRODUCT_CAP = 40


def raw_dir(settings: Settings) -> Path:
    d = settings.threatintel_dir / "raw"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _nvd_headers(settings: Settings) -> dict[str, str]:
    return {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}


def _nvd_delay(settings: Settings) -> float:
    # NVD: 50 req / 30s with a key, 5 / 30s without. Add a margin so a clock
    # skew or a retry doesn't trip the limiter.
    return (30.0 / 50.0) + 0.1 if settings.nvd_api_key else (30.0 / 5.0) + 0.5


def fetch_kev(settings: Settings) -> Path:
    out = raw_dir(settings) / "kev.json"
    with httpx.Client(timeout=60, follow_redirects=True) as c:
        out.write_bytes(c.get(KEV_URL).raise_for_status().content)
    return out


def fetch_epss(settings: Settings) -> Path:
    out = raw_dir(settings) / "epss.csv.gz"
    with httpx.Client(timeout=120, follow_redirects=True) as c:
        out.write_bytes(c.get(EPSS_URL).raise_for_status().content)
    return out


def fetch_attack(settings: Settings) -> Path:
    out = raw_dir(settings) / "attack.json"
    with httpx.Client(timeout=180, follow_redirects=True) as c:
        out.write_bytes(c.get(ATTACK_URL).raise_for_status().content)
    return out


def _nvd_page(client: httpx.Client, settings: Settings, params: dict) -> dict:
    """GET one NVD page, retrying on the transient 403/503/429 it loves to throw."""
    last_exc: Exception | None = None
    for attempt in range(5):
        try:
            r = client.get(NVD_URL, params=params, headers=_nvd_headers(settings))
            if r.status_code in (403, 429, 503):
                raise httpx.HTTPStatusError("throttled", request=r.request, response=r)
            return r.raise_for_status().json()
        except Exception as exc:  # noqa: BLE001 - retry any transient failure
            last_exc = exc
            time.sleep(2**attempt)  # 1,2,4,8,16s backoff
    raise RuntimeError(f"NVD request failed after retries: {last_exc}")


def _nvd_collect(client: httpx.Client, settings: Settings, base: dict, cap: int) -> list[dict]:
    """Page through an NVD query up to `cap` results."""
    out: list[dict] = []
    start = 0
    page = min(2000, cap)
    while True:
        params = dict(base, resultsPerPage=page, startIndex=start)
        data = _nvd_page(client, settings, params)
        out.extend(data.get("vulnerabilities", []))
        total = data.get("totalResults", 0)
        start += page
        if start >= total or len(out) >= cap:
            break
        time.sleep(_nvd_delay(settings))
    return out[:cap]


def fetch_nvd(settings: Settings) -> Path:
    """Fetch all KEV CVEs plus a capped page of CVEs per catalog product.

    Returns the path to the combined raw NVD dump (keyed by CVE id, so the two
    passes dedupe naturally).
    """
    out = raw_dir(settings) / "nvd.json"
    by_id: dict[str, dict] = {}
    with httpx.Client(timeout=120, follow_redirects=True) as c:
        # Pass 1: every KEV CVE, with full NVD data (CVSS, CWE, CPE).
        kev = _nvd_collect(c, settings, {"hasKev": ""}, cap=5000)
        for v in kev:
            by_id[v["cve"]["id"]] = v
        time.sleep(_nvd_delay(settings))

        # Pass 2: recent CVEs per catalog product (noRejected drops withdrawn ids).
        for spec in KNOWN_PRODUCTS:
            base = {"virtualMatchString": cpe_match_string(spec), "noRejected": ""}
            for v in _nvd_collect(c, settings, base, cap=PER_PRODUCT_CAP):
                by_id.setdefault(v["cve"]["id"], v)
            time.sleep(_nvd_delay(settings))

    out.write_text(json.dumps(list(by_id.values())), encoding="utf-8")
    return out


def fetch_all(settings: Settings) -> dict[str, Path]:
    """Fetch every raw feed. Returns a map of name -> path."""
    return {
        "kev": fetch_kev(settings),
        "epss": fetch_epss(settings),
        "attack": fetch_attack(settings),
        "nvd": fetch_nvd(settings),
    }
