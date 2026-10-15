"""A tiny hand-built org graph with answers worked out by hand.

    Internet --EXPOSES--> web1 (f1: NETWORK vuln, p=0.9)
             --EXPOSES--> web2 (f2: NETWORK vuln, p=0.5)
             --EXPOSES--> web3 (f3: NETWORK vuln, MITIGATED by a WAF on web3)  <- decoy
    web1 --CAN_REACH:5432--> dbhost (f4: postgres NETWORK vuln, p=0.8)
    web2 --CAN_REACH:5432--> dbhost
    web1 --CAN_REACH:22----> dbhost   (nothing listens on 22: no extra step)
    dbhost HOLDS s1 (db_password) --UNLOCKS--> ds1 (crown jewel)
    web1 runs a LOCAL privesc vuln (f5, CVSS 7.8, p=0.6)
    web1 HOLDS s2 (ssh_key, root-owned) --UNLOCKS--> box
    box  HOLDS s3 (db_password) --UNLOCKS--> ds1
    ds2: a non-crown bucket nobody can reach.

Internet -> ds1 paths (likelihood):
    P1  internet -f1-> web1 -f4-> dbhost -creds-> s1 -db-> ds1        0.9*0.8*0.9*0.95      = 0.6156
    P3  internet -f1-> web1 -f5(privesc, folded)-> s2 -ssh-> box -creds-> s3 -db-> ds1
                                                  0.9*(0.6*0.9)*0.95*0.9*0.95 = 0.3947...
    P2  internet -f2-> web2 -f4-> dbhost -creds-> s1 -db-> ds1        0.5*0.8*0.9*0.95      = 0.342
Max flow = 2. Entry-side min cut = {f1, f2}; crown-side = {step:db:s1:ds1, step:db:s3:ds1}.
"""

from __future__ import annotations

ORG = "test_tiny"
P = "tiny"


def nid(kind: str, n: int) -> str:
    return f"{P}:{kind}:{n:05d}"


WEB1, WEB2, WEB3, DBHOST, BOX = (nid("asset", i) for i in range(1, 6))
F1, F2, F3, F4, F5 = (nid("finding", i) for i in range(1, 6))
S1, S2, S3 = (nid("secret", i) for i in range(1, 4))
DS1, DS2 = nid("ds", 1), nid("ds", 2)

CREATE = f"""
CREATE (i:Internet {{id: 'internet'}}),
  (web1:Asset {{id: '{WEB1}', hostname: 'web1', kind: 'web_server', cloud: false}}),
  (web2:Asset {{id: '{WEB2}', hostname: 'web2', kind: 'web_server', cloud: false}}),
  (web3:Asset {{id: '{WEB3}', hostname: 'web3', kind: 'web_server', cloud: false}}),
  (db:Asset   {{id: '{DBHOST}', hostname: 'dbhost', kind: 'db_host', cloud: false}}),
  (box:Asset  {{id: '{BOX}', hostname: 'box', kind: 'server', cloud: false}}),
  (sw1:Software {{id: '{nid("sw", 1)}', product: 'tomcat', ports: [8080]}}),
  (sw2:Software {{id: '{nid("sw", 2)}', product: 'tomcat', ports: [8080]}}),
  (sw3:Software {{id: '{nid("sw", 3)}', product: 'tomcat', ports: [8080]}}),
  (sw4:Software {{id: '{nid("sw", 4)}', product: 'postgresql', ports: [5432]}}),
  (sw5:Software {{id: '{nid("sw", 5)}', product: 'linux_kernel', ports: []}}),
  (v1:Vuln {{id: '{nid("vuln", 1)}', cve: 'CVE-2021-44228',
     av: 'NETWORK', cvss: 9.8, likelihood: 0.9}}),
  (v2:Vuln {{id: '{nid("vuln", 2)}', cve: 'CVE-2020-1938',
     av: 'NETWORK', cvss: 6.5, likelihood: 0.5}}),
  (v3:Vuln {{id: '{nid("vuln", 3)}', cve: 'CVE-2017-5638',
     av: 'NETWORK', cvss: 10.0, likelihood: 0.95}}),
  (v4:Vuln {{id: '{nid("vuln", 4)}', cve: 'CVE-2019-9193',
     av: 'NETWORK', cvss: 7.2, likelihood: 0.8}}),
  (v5:Vuln {{id: '{nid("vuln", 5)}', cve: 'CVE-2021-4034',
     av: 'LOCAL', cvss: 7.8, likelihood: 0.6}}),
  (f1:Finding {{id: '{F1}'}}), (f2:Finding {{id: '{F2}'}}), (f3:Finding {{id: '{F3}'}}),
  (f4:Finding {{id: '{F4}'}}), (f5:Finding {{id: '{F5}'}}),
  (c1:Control {{id: '{nid("control", 1)}', kind: 'waf'}}),
  (s1:Secret {{id: '{S1}', kind: 'db_password', requires_priv: false}}),
  (s2:Secret {{id: '{S2}', kind: 'ssh_key', requires_priv: true}}),
  (s3:Secret {{id: '{S3}', kind: 'db_password', requires_priv: false}}),
  (ds1:DataStore {{id: '{DS1}', kind: 'warehouse', crown_jewel: true, sensitivity: 'crown'}}),
  (ds2:DataStore {{id: '{DS2}', kind: 'bucket', crown_jewel: false, sensitivity: 'low'}}),
  (i)-[:EXPOSES {{port: 443}}]->(web1), (i)-[:EXPOSES {{port: 443}}]->(web2),
  (i)-[:EXPOSES {{port: 443}}]->(web3),
  (web1)-[:RUNS]->(sw1), (web2)-[:RUNS]->(sw2), (web3)-[:RUNS]->(sw3),
  (db)-[:RUNS]->(sw4), (web1)-[:RUNS]->(sw5),
  (sw1)-[:HAS_VULN]->(v1), (sw2)-[:HAS_VULN]->(v2), (sw3)-[:HAS_VULN]->(v3),
  (sw4)-[:HAS_VULN]->(v4), (sw5)-[:HAS_VULN]->(v5),
  (f1)-[:ON]->(web1), (f1)-[:OF]->(v1), (f2)-[:ON]->(web2), (f2)-[:OF]->(v2),
  (f3)-[:ON]->(web3), (f3)-[:OF]->(v3), (f4)-[:ON]->(db), (f4)-[:OF]->(v4),
  (f5)-[:ON]->(web1), (f5)-[:OF]->(v5),
  (c1)-[:MITIGATES {{asset: '{WEB3}'}}]->(v3),
  (web1)-[:CAN_REACH {{port: 5432}}]->(db), (web2)-[:CAN_REACH {{port: 5432}}]->(db),
  (web1)-[:CAN_REACH {{port: 22}}]->(db),
  (db)-[:HOLDS]->(s1), (s1)-[:UNLOCKS]->(ds1),
  (web1)-[:HOLDS]->(s2), (s2)-[:UNLOCKS]->(box),
  (box)-[:HOLDS]->(s3), (s3)-[:UNLOCKS]->(ds1)
"""

INDEXES = ["Asset", "Software", "Vuln", "Finding", "Secret", "DataStore", "Control", "Internet"]


def build(db) -> object:
    """(Re)create the tiny graph and return its handle (not yet derived)."""
    if ORG in db.list_graphs():
        db.select_graph(ORG).delete()
    g = db.select_graph(ORG)
    for label in INDEXES:
        g.query(f"CREATE INDEX FOR (n:{label}) ON (n.id)")
    g.query(CREATE)
    return g
