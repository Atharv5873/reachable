# Threat-intel snapshot — sources & attribution

Reachable uses a **filtered, committed snapshot** of public threat intelligence
so the build is reproducible offline. Refetch it with `make intel REFETCH=1`
(set `NVD_API_KEY` first). The snapshot lives in `snapshot/`; the raw downloads
in `raw/` are gitignored.

Snapshot build date and exact counts are recorded in `snapshot/meta.json`.

## Sources

### CISA Known Exploited Vulnerabilities (KEV)
- URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Mirror: https://github.com/cisagov/kev-data
- Fields used: `cveID`, `vendorProject`, `product`, `dateAdded`,
  `knownRansomwareCampaignUse`, `requiredAction`.
- **Terms:** KEV is a work of the U.S. Government (CISA) and is in the public
  domain / free to use. See https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### FIRST EPSS (Exploit Prediction Scoring System)
- URL: https://epss.cyentia.com/epss_scores-current.csv.gz
- API: https://api.first.org/data/v1/epss
- Fields used: `epss` (probability), `percentile`, per CVE we reference.
- **Terms:** EPSS is produced by FIRST.org and is **free to use with
  attribution**. "EPSS data courtesy of FIRST.org (https://www.first.org/epss)."
  See https://www.first.org/epss/

### NVD CVE API 2.0 (NIST National Vulnerability Database)
- URL: https://services.nvd.nist.gov/rest/json/cves/2.0
- We fetch: all KEV CVEs (`hasKev` filter) plus recent CVEs for the ~40
  `vendor:product` pairs the synthetic orgs run (`virtualMatchString`).
- Fields used per CVE: CVSS v3.x base score + vector (attack vector,
  privileges required, user interaction, scope), CWE ids, CPE vendor:product,
  published date.
- Rate limits respected: 50 requests / 30 s with an API key, 5 / 30 s without.
- **Terms:** NVD data is a **U.S. Government work** (NIST), free to use.
  NIST requests acknowledgement: "This product uses data from the NVD API but
  is not endorsed or certified by the NVD." See
  https://nvd.nist.gov/developers/terms-of-use

### MITRE ATT&CK® — Enterprise (STIX 2.1)
- URL: https://github.com/mitre-attack/attack-stix-data (`enterprise-attack/enterprise-attack.json`)
- We commit **only** the techniques/tactics the attack rules reference
  (`id`, `name`, `tactic`, `url`), excluding revoked and deprecated objects.
  The full STIX bundle is **not** committed.
- **Terms:** ATT&CK is © The MITRE Corporation, provided under MITRE's Terms of
  Use. **ATT&CK® is a registered trademark of The MITRE Corporation.** Reachable
  is not affiliated with or endorsed by MITRE. See
  https://attack.mitre.org/resources/legal-and-branding/ and
  https://attack.mitre.org/resources/terms-of-use/

## Synthetic data note

All company infrastructure, identities, secrets, findings and attack paths in
`data/orgs/` are **fully synthetic and fictional**. Only the threat
intelligence above (CVE ids, CVSS, EPSS, KEV flags, ATT&CK techniques) is real
public data. No real company names and no real people's names are used.
