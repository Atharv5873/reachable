"""Normalise raw feeds into the committed, filtered snapshot.

Output (data/threatintel/snapshot/, all committed so the build is reproducible
offline):
  * cves.json    — list of normalised CVE records (CVSS, vector, CWE, CPE
                   products, published epoch seconds, KEV + EPSS merged in).
  * attack.json  — the ATT&CK techniques/tactics the attack rules reference.
  * meta.json    — counts + snapshot dates + source URLs for the report.

GOTCHA (FalkorDB): timestamps are stored as INTEGER epoch seconds, never as a
datetime — see db/attack_rules and the learning notes. We bake that in here so
the loader never has to touch dates.
"""

from __future__ import annotations

import csv
import gzip
import json
from datetime import UTC, datetime
from pathlib import Path

from reachable_core.attack_rules import TECHNIQUE_IDS
from reachable_core.schema import severity_band
from reachable_core.settings import Settings

from .fetch import (
    ATTACK_URL,
    EPSS_URL,
    KEV_URL,
    NVD_URL,
    raw_dir,
)
from .products import KNOWN_PAIRS


def snapshot_dir(settings: Settings) -> Path:
    d = settings.threatintel_dir / "snapshot"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _epoch_seconds(iso: str) -> int:
    """Parse an NVD/ISO timestamp to integer epoch seconds (UTC).

    NVD stamps look like '2021-12-10T10:15:09.143'. We treat them as UTC.
    """
    iso = iso.replace("Z", "")
    dt = datetime.fromisoformat(iso)
    return int(dt.timestamp())


# --- KEV -------------------------------------------------------------------
def load_kev(settings: Settings) -> tuple[dict[str, dict], str, str]:
    raw = json.loads((raw_dir(settings) / "kev.json").read_text(encoding="utf-8"))
    out: dict[str, dict] = {}
    for v in raw.get("vulnerabilities", []):
        out[v["cveID"]] = {
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown").strip().lower() == "known",
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "date_added": v.get("dateAdded", ""),
        }
    return out, raw.get("catalogVersion", ""), raw.get("dateReleased", "")


# --- EPSS ------------------------------------------------------------------
def load_epss(settings: Settings, needed: set[str]) -> tuple[dict[str, tuple[float, float]], str]:
    """Parse the gzipped EPSS CSV, keeping only CVEs we use.

    The file begins with a '#model_version:...,score_date:...' comment line,
    then a 'cve,epss,percentile' header, then rows.
    """
    path = raw_dir(settings) / "epss.csv.gz"
    model_line = ""
    out: dict[str, tuple[float, float]] = {}
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        first = fh.readline()
        if first.startswith("#"):
            model_line = first.strip().lstrip("#")
        else:
            fh.seek(0)
        reader = csv.DictReader(fh)
        for row in reader:
            cve = row.get("cve")
            if cve in needed:
                out[cve] = (float(row["epss"]), float(row["percentile"]))
    return out, model_line


# --- NVD -------------------------------------------------------------------
def _cvss_from_metrics(metrics: dict) -> dict | None:
    """Pull base score + vector components, preferring CVSS v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            d = metrics[key][0]["cvssData"]
            return {
                "cvss": float(d.get("baseScore", 0.0)),
                "vector": d.get("vectorString", ""),
                "av": d.get("attackVector", "NETWORK"),
                "pr": d.get("privilegesRequired", "NONE"),
                "ui": d.get("userInteraction", "NONE"),
                "scope": d.get("scope", "UNCHANGED"),
            }
    if metrics.get("cvssMetricV2"):
        d = metrics["cvssMetricV2"][0]["cvssData"]
        # v2 has no PR/UI/scope; map accessVector and leave the rest neutral.
        return {
            "cvss": float(d.get("baseScore", 0.0)),
            "vector": d.get("vectorString", ""),
            "av": d.get("accessVector", "NETWORK"),
            "pr": "NONE",
            "ui": "NONE",
            "scope": "UNCHANGED",
        }
    return None


def _catalog_products(cve: dict) -> list[str]:
    """vendor:product pairs from the CVE's CPE criteria, kept to our catalog."""
    found: set[str] = set()
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                # cpe:2.3:part:vendor:product:...
                if len(parts) > 4:
                    pair = f"{parts[3]}:{parts[4]}"
                    if pair in KNOWN_PAIRS:
                        found.add(pair)
    return sorted(found)


def _cwes(cve: dict) -> list[str]:
    out: set[str] = set()
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-") and val[4:].isdigit():
                out.add(val)
    return sorted(out)


def normalise_cves(settings: Settings) -> list[dict]:
    raw = json.loads((raw_dir(settings) / "nvd.json").read_text(encoding="utf-8"))
    kev, _, _ = load_kev(settings)

    records: list[dict] = []
    for entry in raw:
        cve = entry["cve"]
        cid = cve["id"]
        cvss = _cvss_from_metrics(cve.get("metrics", {}))
        if cvss is None:
            continue  # no scoring metrics -> useless for likelihood; drop it
        products = _catalog_products(cve)
        kev_info = kev.get(cid)
        if not products and kev_info:
            # KEV CVE outside our catalog: fall back to its KEV vendor/product
            # so it still AFFECTS a Product node in the threatintel graph.
            vend = kev_info["vendor"].lower().replace(" ", "_") or "unknown"
            prod = kev_info["product"].lower().replace(" ", "_") or "unknown"
            products = [f"{vend}:{prod}"]
        published = cve.get("published")
        records.append(
            {
                "id": cid,
                **cvss,
                "severity": severity_band(cvss["cvss"]),
                "cwes": _cwes(cve),
                "products": products,
                "published": _epoch_seconds(published) if published else 0,
                "kev": kev_info is not None,
                "kev_ransomware": bool(kev_info and kev_info["ransomware"]),
                # epss filled in by merge_epss once we know which CVEs we keep
                "epss": 0.0,
                "epss_percentile": 0.0,
            }
        )
    return records


def merge_epss(settings: Settings, records: list[dict]) -> str:
    needed = {r["id"] for r in records}
    epss, model_line = load_epss(settings, needed)
    for r in records:
        if r["id"] in epss:
            r["epss"], r["epss_percentile"] = epss[r["id"]]
    return model_line


# --- ATT&CK ----------------------------------------------------------------
def normalise_attack(settings: Settings) -> dict:
    bundle = json.loads((raw_dir(settings) / "attack.json").read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])

    # Tactics: x-mitre-tactic, keyed by x_mitre_shortname (what techniques cite).
    tactic_by_shortname: dict[str, dict] = {}
    for o in objects:
        if o.get("type") != "x-mitre-tactic":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = _mitre_ext(o)
        if ext:
            tactic_by_shortname[o["x_mitre_shortname"]] = {
                "id": ext["id"],
                "name": o["name"],
                "shortname": o["x_mitre_shortname"],
                "url": ext["url"],
            }

    techniques: list[dict] = []
    tactics_used: dict[str, dict] = {}
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = _mitre_ext(o)
        if not ext or ext["id"] not in TECHNIQUE_IDS:
            continue
        phase_shortnames = [p["phase_name"] for p in o.get("kill_chain_phases", [])]
        tactic_ids = []
        for sn in phase_shortnames:
            t = tactic_by_shortname.get(sn)
            if t:
                tactics_used[t["id"]] = t
                tactic_ids.append(t["id"])
        techniques.append(
            {
                "id": ext["id"],
                "name": o["name"],
                "url": ext["url"],
                "tactics": tactic_ids,
            }
        )

    return {
        "techniques": sorted(techniques, key=lambda t: t["id"]),
        "tactics": sorted(tactics_used.values(), key=lambda t: t["id"]),
        "spec_version": bundle.get("spec_version", "2.1"),
    }


def _mitre_ext(o: dict) -> dict | None:
    for ref in o.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return {"id": ref["external_id"], "url": ref.get("url", "")}
    return None


# --- Orchestration ---------------------------------------------------------
def build_snapshot(settings: Settings) -> dict:
    """Normalise every raw feed into the committed snapshot. Returns meta/counts."""
    kev, kev_version, kev_released = load_kev(settings)
    records = normalise_cves(settings)
    epss_model = merge_epss(settings, records)
    attack = normalise_attack(settings)

    out = snapshot_dir(settings)
    (out / "cves.json").write_text(json.dumps(records, indent=0), encoding="utf-8")
    (out / "attack.json").write_text(json.dumps(attack, indent=2), encoding="utf-8")

    meta = {
        "built_at": datetime.now(tz=UTC).strftime("%Y-%m-%d"),
        "sources": {
            "kev": KEV_URL,
            "epss": EPSS_URL,
            "nvd": NVD_URL,
            "attack": ATTACK_URL,
        },
        "kev_catalog_version": kev_version,
        "kev_date_released": kev_released,
        "epss_model": epss_model,
        "counts": {
            "cves": len(records),
            "kev_cves": sum(1 for r in records if r["kev"]),
            "ransomware_cves": sum(1 for r in records if r["kev_ransomware"]),
            "epss_rows": sum(1 for r in records if r["epss"] > 0),
            "critical": sum(1 for r in records if r["severity"] == "CRITICAL"),
            "techniques": len(attack["techniques"]),
            "tactics": len(attack["tactics"]),
        },
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta
