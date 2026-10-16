"""S7 leakage: the baselines provably cannot see the answer key or any path field.

Three walls, each tested:
  1. the database: the read-only role reads eval_<graph> views only (no raw
     mirror, no company layer, no memory edges), and cannot write;
  2. what the baselines are handed: the CONTEXT and every RAG document carry no
     label, path, step or memory field, nor any planted path's name;
  3. the code: no baseline module imports the scorer or the generator, or names
     the label file.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import psycopg
import pytest

from reachable_eval.agent import build_context
from reachable_eval.sql_agent import check_sql, run_sql
from reachable_eval.store import INFRA_EDGES, INFRA_TABLES, eval_schema, ro_connect
from reachable_eval.vector_rag import build_docs

pytestmark = pytest.mark.integration

FORBIDDEN = (
    "attack_step",
    "crownpath",
    "crown_path",
    "finding_priority",
    "priority",
    "best_likelihood",
    "likelihood",
    "fix_token",
    "verdict",
    "riskacc",
    "acceptance",
    "planted",
    "decoy",
    "labels",
    "crown_paths",  # S8: the ranking signal is the graph's, never handed over as text
    "criticality",
)


def test_ro_role_reads_only_the_eval_views(eval_env):
    g = eval_env["ref"].graph
    with ro_connect(g) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM findings")
        assert cur.fetchone()[0] > 0  # the views work
    for raw in (f"{g}.adrs", f"{g}.edges", f"{g}.persons", f"{g}.findings"):
        with (
            ro_connect(g) as conn,
            conn.cursor() as cur,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            cur.execute(f"SELECT * FROM {raw} LIMIT 1")


def test_ro_role_cannot_write(eval_env):
    with (
        ro_connect(eval_env["ref"].graph) as conn,
        conn.cursor() as cur,
        pytest.raises(psycopg.Error),
    ):
        cur.execute("DELETE FROM findings")


def test_eval_views_hold_infrastructure_only(eval_env):
    g = eval_env["ref"].graph
    with ro_connect(g) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = %s",
            (eval_schema(g),),
        )
        cols = cur.fetchall()
        cur.execute("SELECT DISTINCT type FROM edges")
        types = {r[0] for r in cur.fetchall()}
        cur.execute("SELECT count(*) FROM edges WHERE type = 'ON' AND src NOT LIKE '%:finding:%'")
        memory_on = cur.fetchone()[0]
    assert {t for t, _ in cols} == {*INFRA_TABLES, "edges"}
    for t, c in cols:
        assert not any(f in c.lower() for f in FORBIDDEN), (t, c)
    assert types <= set(INFRA_EDGES)
    assert memory_on == 0
    # ...and the raw mirror really does hold what the views leave out.
    with psycopg.connect(eval_env_dsn(), autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(f"SELECT count(*) FROM {g}.edges WHERE type = 'ON' AND src LIKE '%:verdict:%'")
        assert cur.fetchone()[0] > 0
        cur.execute(f"SELECT count(*) FROM {g}.adrs")
        assert cur.fetchone()[0] > 0


def eval_env_dsn() -> str:
    from reachable_core.settings import get_settings

    return get_settings().postgres_dsn


@pytest.mark.parametrize(
    "bad",
    [
        "DELETE FROM findings",
        "SELECT 1; SELECT 2",
        "select set_config('role', 'reachable', false)",
        "WITH x AS (SELECT 1) UPDATE findings SET status = 'fixed'",
        "  ",
    ],
)
def test_sql_tool_refuses_non_selects(bad):
    with pytest.raises(ValueError):
        check_sql(bad)


def test_sql_tool_cannot_reach_the_raw_mirror(eval_env):
    g = eval_env["ref"].graph
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        run_sql(g, f"SELECT * FROM {g}.adrs")
    out = run_sql(g, "SELECT id FROM findings ORDER BY id")
    assert out["truncated"] and len(out["data"]["rows"]) == 50  # rows are capped


def test_context_and_rag_documents_carry_no_label_or_path_field(eval_env):
    data = eval_env["data"]
    names = [p["name"].lower() for p in eval_env["labels"]["paths"]]
    texts = [json.dumps(build_context(data))] + [t for _, _, t in build_docs(data)]
    blob = "\n".join(texts).lower()
    for f in (*FORBIDDEN, *names):
        assert f not in blob, f


BASELINE_MODULES = ("store", "base", "agent", "sql_agent", "vector_rag", "reachable")


def _code_strings(tree: ast.AST) -> list[str]:
    """String literals that are not docstrings."""
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docs.add(id(body[0].value))
    return [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs
    ]


def test_baseline_code_never_touches_the_answer_key():
    import reachable_eval

    root = Path(reachable_eval.__file__).parent
    for mod in BASELINE_MODULES:
        tree = ast.parse((root / f"{mod}.py").read_text(encoding="utf-8"))
        imported = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom):
                imported.add(("." * n.level) + (n.module or ""))
            elif isinstance(n, ast.Import):
                imported.update(a.name for a in n.names)
        assert not any("scoring" in m or "orggen" in m for m in imported), (mod, imported)
        for s in _code_strings(tree):
            low = s.lower()
            assert "labels" not in low and "finding_priority" not in low, (mod, s)


# S8: the ranking and fix signals. Each must come from the graph at runtime.
SIGNAL_MODULES = (
    "reachable_graph.criticality",  # path-criticality
    "reachable_graph.tools",  # scan_findings' order, min_cut, simulate_fix
    "reachable_agents.agents",  # the product's Pathfinder and Fixer
    "reachable_eval.reachable",  # the eval's ranking step
)
ANSWER_KEY = ("labels.json", "labels_v2", "finding_priority", "ground_truth", "oracle", "planted")


def test_ranking_signals_never_touch_the_answer_key():
    import importlib

    for name in SIGNAL_MODULES:
        path = Path(importlib.import_module(name).__file__)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom):
                imported.add(("." * n.level) + (n.module or ""))
            elif isinstance(n, ast.Import):
                imported.update(a.name for a in n.names)
        bad = [m for m in imported if any(x in m for x in ("scoring", "orggen", "oracle"))]
        assert not bad, (name, bad)
        for s in _code_strings(tree):
            low = s.lower()
            assert not any(k in low for k in ANSWER_KEY), (name, s)


def test_ranking_step_runs_with_the_answer_key_unreadable(eval_env, monkeypatch):
    """The reachable prioritiser, ranking step and fix set included, with every
    labels file unreadable: it still ranks by path-criticality from the graph."""
    import asyncio
    import builtins

    from test_eval_runs import FIRST_CALL, Policy

    from reachable_eval.reachable import reachable

    real_open, real_read = builtins.open, Path.read_text

    def guard(p):
        if "labels" in str(p).lower():
            raise AssertionError(f"the ranking read the answer key: {p}")

    def open_(file, *a, **k):
        guard(file)
        return real_open(file, *a, **k)

    def read_text(self, *a, **k):
        guard(self)
        return real_read(self, *a, **k)

    monkeypatch.setattr(builtins, "open", open_)
    monkeypatch.setattr(Path, "read_text", read_text)
    r = asyncio.run(
        reachable(llm_factory=lambda s: Policy(FIRST_CALL["reachable"])).rank(eval_env["data"])
    )
    assert r.meta["ranking"] == "graph" and r.meta["graph_ranked"] > 0
