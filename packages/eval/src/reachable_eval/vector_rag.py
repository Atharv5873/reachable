"""vector_rag: the same LLM loop; its context layer is semantic search over text.

Documents (one per row, built from the eval views only, store.py):
  * every open finding: host, kind, zone, env, Internet-facing or not, the CVE
    and product, CVSS / EPSS / KEV / ransomware, attack vector, and a
    compensating control if one is recorded;
  * every asset: kind, zone + trust, env, Internet exposure, software, its open
    findings (count, max CVSS, KEV), what it CAN_REACH (first 8, "+N more"),
    the secrets it holds, the roles it assumes;
  * every secret, identity and data store, with their one-hop relations (what a
    secret unlocks, what an identity can read, what can read a data store).

So the one-hop facts ARE in the text. What retrieval does not do is chain them:
a query returns the documents most similar to it, not the ones connected to it.

Embedding: BAAI/bge-small-en-v1.5 (384 dimensions), run locally on the CPU with
fastembed (ONNX Runtime; no torch, no key, no cost, deterministic). We tried
gemini-embedding-001 first: this project's key is on its FREE tier for
embeddings (100 documents per minute), ~4 hours for the six scans. Documents
use bge's passage form, queries its query form (fastembed adds bge's "Represent
this sentence for searching relevant passages: " prefix). Vectors are cached on
disk by text hash in evals/cache/embeddings.sqlite, so a rerun embeds only what
changed (v2 differs from v1 by a few dozen rows). Index: a pgvector
table rag_<graph>.docs, searched EXACTLY (ORDER BY embedding <=> query, no
ANN index): deterministic, and fast enough at ~9k rows. k = 12 per query by
default (the model may ask for up to 15; 15 documents fit the 6,000-char
tool-result cap the other two toolboxes get).
"""

from __future__ import annotations

import array
import asyncio
import hashlib
import json
import sqlite3
import threading
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

import psycopg
from psycopg import sql

from reachable_core.settings import REPO_ROOT, Settings, get_settings

from .agent import LLMPrioritiser, LocalTool, LocalToolbox
from .store import ScanData, ro_connect

EMBED_MODEL = "BAAI/bge-small-en-v1.5"
EMBED_DIM = 384
EMBED_BATCH = 256
K_DEFAULT, K_MAX = 12, 15
REACH_LIST = 8
CACHE = REPO_ROOT / "evals" / "cache" / "embeddings.sqlite"
MODEL_DIR = REPO_ROOT / "evals" / "cache" / "fastembed"


def rag_schema(graph: str) -> str:
    return f"rag_{graph}"


# ------------------------------------------------------------------ documents
def build_docs(data: ScanData) -> list[tuple[str, str, str]]:
    """(id, kind, text) for every finding, asset, secret, identity, data store."""
    with ro_connect(data.ref.graph) as conn, conn.cursor() as cur:
        cur.execute("SELECT id, kind, zone, env, hostname, cloud FROM assets")
        assets = {r[0]: r[1:] for r in cur.fetchall()}
        cur.execute("SELECT id, name, trust FROM zones")
        zones = {i: (n, t) for i, n, t in cur.fetchall()}
        cur.execute("SELECT id, vendor, product, version FROM software")
        software = {i: f"{v} {p} {ver}" for i, v, p, ver in cur.fetchall()}
        cur.execute("SELECT id, kind, requires_priv FROM secrets")
        secrets = {i: (k, rp) for i, k, rp in cur.fetchall()}
        cur.execute("SELECT id, kind, name, over_broad FROM identities")
        idents = {i: (k, n, ob) for i, k, n, ob in cur.fetchall()}
        cur.execute("SELECT id, kind, crown_jewel FROM datastores")
        stores = {i: (k, c) for i, k, c in cur.fetchall()}
        cur.execute("SELECT src, dst, type, props FROM edges WHERE type <> 'ON' AND type <> 'OF'")
        edges = cur.fetchall()

    out_e: dict[tuple[str, str], list[tuple[str, dict]]] = defaultdict(list)
    in_e: dict[tuple[str, str], list[tuple[str, dict]]] = defaultdict(list)
    for src, dst, typ, props in edges:
        out_e[(src, typ)].append((dst, props or {}))
        in_e[(dst, typ)].append((src, props or {}))

    def name(x: str) -> str:
        if x in assets:
            return assets[x][3] or x
        if x in idents:
            return f"{idents[x][1]} ({x})"
        if x in stores:
            return f"{stores[x][0]} {x}"
        return x

    by_asset: dict[str, list] = defaultdict(list)
    for f in data.findings:
        if f.asset:
            by_asset[f.asset].append(f)

    docs: list[tuple[str, str, str]] = []
    for f in data.findings:
        exp = "Internet-facing" if f.internet_facing else "not Internet-facing"
        ctl = f"; a {f.mitigated_by} control mitigates it on this host" if f.mitigated_by else ""
        docs.append(
            (
                f.id,
                "finding",
                f"Finding {f.id} on host {f.hostname} ({f.kind}, zone {f.zone}, {f.env}, {exp}): "
                f"{f.cve} in {f.product}. CVSS {f.cvss}, EPSS {f.epss:.3f}, "
                f"KEV {'yes' if f.kev else 'no'}{', ransomware use' if f.ransomware else ''}, "
                f"attack vector {f.av}{ctl}.",
            )
        )
    for a, (kind, zone, env, host, cloud) in assets.items():
        zname, trust = zones.get(zone, (zone, "?"))
        ports = sorted({p.get("port") for _, p in in_e[(a, "EXPOSES")] if p.get("port")})
        exp = f"Internet-facing on port(s) {ports}" if in_e[(a, "EXPOSES")] else "not exposed"
        sw = [software.get(s, s) for s, _ in out_e[(a, "RUNS")]]
        fs = by_asset.get(a, [])
        reach = [f"{name(d)}:{p.get('port')}" for d, p in out_e[(a, "CAN_REACH")]]
        more = f" (+{len(reach) - REACH_LIST} more)" if len(reach) > REACH_LIST else ""
        held = [f"{s} ({secrets.get(s, ('?',))[0]})" for s, _ in out_e[(a, "HOLDS")]]
        roles = [name(r) for r, _ in out_e[(a, "ASSUMES")]]
        text = (
            f"Asset {host} ({a}): {kind} in zone {zname} (trust {trust}), {env}"
            f"{', cloud' if cloud else ''}; {exp}. Runs {', '.join(sw) or 'nothing listed'}. "
            f"{len(fs)} open finding(s)"
            + (f", max CVSS {max(f.cvss for f in fs)}, {sum(f.kev for f in fs)} KEV" if fs else "")
            + f". Can reach {', '.join(reach[:REACH_LIST]) or 'nothing'}{more}."
            + (f" Holds secrets {', '.join(held)}." if held else "")
            + (f" Assumes role {', '.join(roles)}." if roles else "")
        )
        docs.append((a, "asset", text))
    for s, (kind, rp) in secrets.items():
        on = [name(x) for x, _ in in_e[(s, "HOLDS")]]
        unl = [name(x) for x, _ in out_e[(s, "UNLOCKS")]]
        docs.append(
            (
                s,
                "secret",
                f"Secret {s}: {kind}{' (root-owned)' if rp else ''}, stored on "
                f"{', '.join(on) or 'nowhere listed'}; unlocks {', '.join(unl) or 'nothing'}.",
            )
        )
    for i, (kind, nm, ob) in idents.items():
        can = [f"{p.get('action')} {name(d)}" for d, p in out_e[(i, "CAN")]]
        assume = [name(x) for x, _ in out_e[(i, "CAN_ASSUME")]]
        by = [name(x) for x, _ in in_e[(i, "ASSUMES")]] + [name(x) for x, _ in in_e[(i, "UNLOCKS")]]
        docs.append(
            (
                i,
                "identity",
                f"Identity {nm} ({i}): {kind}{', over-broad permissions' if ob else ''}. "
                f"Can {', '.join(can) or 'nothing listed'}"
                + (f"; can assume {', '.join(assume)}" if assume else "")
                + (f"; used by {', '.join(by)}" if by else "")
                + ".",
            )
        )
    for d, (kind, crown) in stores.items():
        unl = [name(x) for x, _ in in_e[(d, "UNLOCKS")]]
        can = [f"{name(x)} ({p.get('action')})" for x, p in in_e[(d, "CAN")]]
        docs.append(
            (
                d,
                "datastore",
                f"Data store {d}: {kind}{', CROWN JEWEL' if crown else ''}. Unlocked by "
                f"{', '.join(unl) or 'no secret listed'}; readable by {', '.join(can) or 'none'}.",
            )
        )
    return docs


# ----------------------------------------------------------------- embeddings
class EmbeddingCache:
    def __init__(self, path: Path = CACHE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Used from worker threads (asyncio.to_thread); one lock per connection,
        # and a busy timeout for the other runs' connections writing at once.
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.lock = threading.Lock()
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS emb "
            "(model TEXT, sha TEXT, vec BLOB, PRIMARY KEY (model, sha))"
        )

    def get(self, shas: list[str]) -> dict[str, list[float]]:
        with self.lock:
            return self._get(shas)

    def _get(self, shas: list[str]) -> dict[str, list[float]]:
        out = {}
        for i in range(0, len(shas), 500):
            chunk = shas[i : i + 500]
            marks = ",".join("?" * len(chunk))
            q = f"SELECT sha, vec FROM emb WHERE model = ? AND sha IN ({marks})"
            for sha, blob in self.db.execute(q, [EMBED_MODEL, *chunk]):
                out[sha] = array.array("f", blob).tolist()
        return out

    def put(self, items: dict[str, list[float]]) -> None:
        with self.lock:
            self._put(items)

    def _put(self, items: dict[str, list[float]]) -> None:
        self.db.executemany(
            "INSERT OR REPLACE INTO emb VALUES (?, ?, ?)",
            [(EMBED_MODEL, k, array.array("f", v).tobytes()) for k, v in items.items()],
        )
        self.db.commit()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


_model = None
_model_lock = threading.Lock()


def _bge():
    """The one fastembed model per process (ONNX sessions are thread-safe)."""
    global _model
    with _model_lock:
        if _model is None:
            from fastembed import TextEmbedding

            MODEL_DIR.mkdir(parents=True, exist_ok=True)
            _model = TextEmbedding(EMBED_MODEL, cache_dir=str(MODEL_DIR))
        return _model


class Embedder:
    """Cached local embeddings. `calls` / `tokens` count what was actually
    embedded (not cache hits); tokens ~ chars / 4, for the record (it is free)."""

    def __init__(self, settings: Settings | None = None, cache: EmbeddingCache | None = None):
        self.cache = cache or EmbeddingCache()
        self.calls = self.tokens = self.cached = 0

    def _embed_now(self, texts: list[str], kind: str) -> list[list[float]]:
        m = _bge()
        fn = m.query_embed if kind == "query" else m.passage_embed
        return [v.tolist() for v in fn(texts, batch_size=EMBED_BATCH)]

    async def embed(self, texts: list[str], kind: str = "passage") -> list[list[float]]:
        keys = [_sha(f"{kind}:{t}") for t in texts]
        have = await asyncio.to_thread(self.cache.get, list(dict.fromkeys(keys)))
        todo = list(dict.fromkeys(t for t, h in zip(texts, keys, strict=True) if h not in have))
        self.cached += len(texts) - len(todo)
        if todo:
            vecs = await asyncio.to_thread(self._embed_now, todo, kind)
            new = {_sha(f"{kind}:{t}"): v for t, v in zip(todo, vecs, strict=True)}
            await asyncio.to_thread(self.cache.put, new)
            have.update(new)
            self.calls += 1
            self.tokens += sum(len(t) for t in todo) // 4
        return [have[h] for h in keys]

    def usd(self) -> float:
        return 0.0  # local model


# ---------------------------------------------------------------------- index
def _vec(v: list[float]) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in v) + "]"


async def ensure_index(
    data: ScanData, embedder: Embedder, settings: Settings | None = None
) -> dict:
    """Build rag_<graph>.docs unless it already holds exactly these documents."""
    s = settings or get_settings()
    docs = await asyncio.to_thread(build_docs, data)
    digest = _sha(json.dumps(docs) + EMBED_MODEL + str(EMBED_DIM))[:16]
    schema = sql.Identifier(rag_schema(data.ref.graph))
    with psycopg.connect(s.postgres_dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
        cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(schema))
        cur.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {}.meta (digest text)").format(schema))
        cur.execute(sql.SQL("SELECT digest FROM {}.meta").format(schema))
        row = cur.fetchone()
        if row and row[0] == digest:
            return {"docs": len(docs), "digest": digest, "rebuilt": False}
    vecs = await embedder.embed([t for _, _, t in docs])
    with psycopg.connect(s.postgres_dsn) as conn, conn.cursor() as cur:
        cur.execute(sql.SQL("DROP TABLE IF EXISTS {}.docs").format(schema))
        cur.execute(
            sql.SQL(
                "CREATE TABLE {}.docs (id text PRIMARY KEY, kind text, body text, "
                "embedding vector({}))"
            ).format(schema, sql.Literal(EMBED_DIM))
        )
        with cur.copy(
            sql.SQL("COPY {}.docs (id, kind, body, embedding) FROM STDIN").format(schema)
        ) as cp:
            for (i, k, t), v in zip(docs, vecs, strict=True):
                cp.write_row((i, k, t, _vec(v)))
        cur.execute(sql.SQL("DELETE FROM {}.meta").format(schema))
        cur.execute(sql.SQL("INSERT INTO {}.meta VALUES (%s)").format(schema), (digest,))
        conn.commit()
    return {"docs": len(docs), "digest": digest, "rebuilt": True}


def search(graph: str, qvec: list[float], k: int, settings: Settings | None = None) -> list:
    s = settings or get_settings()
    with psycopg.connect(s.postgres_dsn) as conn, conn.cursor() as cur:
        cur.execute(
            sql.SQL(
                "SELECT id, kind, body, 1 - (embedding <=> %s::vector) FROM {}.docs "
                "ORDER BY embedding <=> %s::vector, id LIMIT %s"
            ).format(sql.Identifier(rag_schema(graph))),
            (_vec(qvec), _vec(qvec), k),
        )
        return cur.fetchall()


def rag_toolbox_factory(embedder_factory=Embedder):
    @asynccontextmanager
    async def make(data: ScanData):
        emb = embedder_factory()
        await ensure_index(data, emb)

        async def search_inventory(args: dict) -> dict:
            query = str(args.get("query") or "").strip()
            if not query:
                raise ValueError("query must be a non-empty string")
            k = max(1, min(int(args.get("k") or K_DEFAULT), K_MAX))
            (qv,) = await emb.embed([query], kind="query")
            rows = await asyncio.to_thread(search, data.ref.graph, qv, k)
            return {
                "summary": f"top {len(rows)} documents for {query[:80]!r}",
                "data": {
                    "results": [
                        {"id": i, "kind": kd, "similarity": round(sim, 4), "text": body}
                        for i, kd, body, sim in rows
                    ]
                },
                "truncated": False,
            }

        box = LocalToolbox(
            [
                LocalTool(
                    "search_inventory",
                    "Semantic search over this organisation's findings and asset inventory: one "
                    "text document per open finding, asset, secret, identity and data store. "
                    "Returns the k documents most similar to your query (cosine similarity).",
                    {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "What to look for."},
                            "k": {
                                "type": "integer",
                                "description": f"How many documents (default {K_DEFAULT}, "
                                f"max {K_MAX}).",
                            },
                        },
                        "required": ["query"],
                    },
                    search_inventory,
                )
            ]
        )
        # This run's query embeddings (the index is built once, before the runs).
        box.meta = lambda: {
            "embed_calls": emb.calls,
            "embed_tokens": emb.tokens,
            "embed_usd": emb.usd(),
        }
        yield box

    return make


def vector_rag(llm_factory=None, embedder_factory=Embedder) -> LLMPrioritiser:
    kw = {"llm_factory": llm_factory} if llm_factory else {}
    return LLMPrioritiser(
        "vector_rag", rag_toolbox_factory(embedder_factory), ("search_inventory",), **kw
    )
