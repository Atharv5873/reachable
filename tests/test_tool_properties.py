"""Property tests: every tool enforces its caps and never writes to an org graph.

A recording proxy sits between the tools and FalkorDB. It logs every call and
REFUSES `.query()` (the write-capable command) on anything but a scratch copy,
so a tool that tried to write would fail loudly here even before the server's
own GRAPH.RO_QUERY check. Hypothesis throws in-range and out-of-range inputs.
"""

from __future__ import annotations

import pytest
import tiny_graph as T
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from reachable_graph.derive import derive
from reachable_graph.models import MAX_FIX_TOKENS, MAX_K, MAX_ROWS
from reachable_graph.tools import SCRATCH_PREFIX, TOOL_NAMES, GraphTools

pytestmark = pytest.mark.integration

SETTINGS = settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


class _GraphProxy:
    def __init__(self, real, calls):
        self._real, self._calls = real, calls
        self.name = real.name

    def ro_query(self, *a, **kw):
        self._calls.append((self.name, "ro_query"))
        return self._real.ro_query(*a, **kw)

    def query(self, *a, **kw):
        self._calls.append((self.name, "query"))
        if not self.name.startswith(SCRATCH_PREFIX):
            raise AssertionError(f"write-capable query() on non-scratch graph {self.name}")
        return self._real.query(*a, **kw)

    def copy(self, clone):
        self._calls.append((self.name, f"copy->{clone}"))
        assert clone.startswith(SCRATCH_PREFIX)
        return self._real.copy(clone)

    def delete(self):
        self._calls.append((self.name, "delete"))
        assert self.name.startswith(SCRATCH_PREFIX), f"tool tried to delete {self.name}"
        return self._real.delete()


class RecordingDB:
    def __init__(self, real):
        self.real, self.calls = real, []

    def select_graph(self, name):
        return _GraphProxy(self.real.select_graph(name), self.calls)

    def list_graphs(self):
        return self.real.list_graphs()


@pytest.fixture(scope="module")
def rec(db):
    g = T.build(db)
    derive(g)
    r = RecordingDB(db)
    yield r, GraphTools(r, allowed_orgs=[T.ORG])
    g.delete()


def _assert_read_only(calls):
    for graph, op in calls:
        if not graph.startswith(SCRATCH_PREFIX):
            assert op == "ro_query" or op.startswith("copy->"), (graph, op)


@SETTINGS
@given(k=st.integers(-3, MAX_K + 20), hops=st.integers(-2, 20))
def test_attack_paths_caps(rec, k, hops):
    r, tools = rec
    r.calls.clear()
    if not (1 <= k <= MAX_K and 1 <= hops <= 8):
        with pytest.raises(ValidationError):
            tools.attack_paths(T.ORG, k=k, max_hops=hops)
        assert r.calls == [], "invalid input reached the database"
        return
    res = tools.attack_paths(T.ORG, k=k, max_hops=hops)
    assert len(res.data["paths"]) <= k
    assert all(len(p["steps"]) <= hops for p in res.data["paths"])
    _assert_read_only(r.calls)


@SETTINGS
@given(limit=st.integers(-3, MAX_ROWS + 50), asked=st.integers(0, 10_000))
def test_run_cypher_caps(rec, limit, asked):
    r, tools = rec
    r.calls.clear()
    q = f"UNWIND range(1, 1000) AS x RETURN x LIMIT {asked}"
    if not 1 <= limit <= MAX_ROWS:
        with pytest.raises(ValidationError):
            tools.run_cypher_readonly(T.ORG, q, limit=limit)
        return
    res = tools.run_cypher_readonly(T.ORG, q, limit=limit)
    assert len(res.data["rows"]) <= limit
    assert res.truncated == (min(asked, 1000) > limit)
    _assert_read_only(r.calls)


@SETTINGS
@given(n=st.integers(0, MAX_FIX_TOKENS + 10))
def test_simulate_fix_caps(rec, n):
    r, tools = rec
    r.calls.clear()
    tokens = [T.F1] + [f"tiny:finding:{90000 + i}" for i in range(max(0, n - 1))]
    if not 1 <= n <= MAX_FIX_TOKENS:
        with pytest.raises(ValidationError):
            tools.simulate_fix(T.ORG, tokens[:n])
        return
    tools.simulate_fix(T.ORG, tokens[:n])
    _assert_read_only(r.calls)
    writes = [g for g, op in r.calls if op == "query"]
    assert writes and all(g.startswith(SCRATCH_PREFIX) for g in writes)


@SETTINGS
@given(top=st.integers(-1, 60), depth=st.integers(-1, 12))
def test_other_tools_caps(rec, top, depth):
    r, tools = rec
    r.calls.clear()
    if 1 <= top <= 50:
        assert len(tools.choke_points(T.ORG, top=top).data["choke_points"]) <= top
    else:
        with pytest.raises(ValidationError):
            tools.choke_points(T.ORG, top=top)
    if 1 <= depth <= 8:
        tools.blast_radius(T.ORG, T.WEB1, max_depth=depth)
    else:
        with pytest.raises(ValidationError):
            tools.blast_radius(T.ORG, T.WEB1, max_depth=depth)
    _assert_read_only(r.calls)


def test_every_tool_is_read_only_on_the_org_graph(rec):
    """One call of every tool in the contract; none may write to the org graph."""
    r, tools = rec
    r.calls.clear()
    paths = tools.attack_paths(T.ORG, k=3)
    calls = {
        "exposure_surface": lambda: tools.exposure_surface(T.ORG),
        "attack_paths": lambda: paths,
        "blast_radius": lambda: tools.blast_radius(T.ORG, T.WEB1),
        "min_cut": lambda: tools.min_cut(T.ORG),
        "choke_points": lambda: tools.choke_points(T.ORG),
        "why_step": lambda: tools.why_step(T.ORG, paths.data["paths"][0]["steps"][0]["key"]),
        "vuln_intel": lambda: tools.vuln_intel("CVE-2021-44228", org=T.ORG),
        "simulate_fix": lambda: tools.simulate_fix(T.ORG, [T.F4]),
        "run_cypher_readonly": lambda: tools.run_cypher_readonly(T.ORG, "MATCH (n) RETURN n"),
        "owners": lambda: tools.owners(T.ORG, T.WEB1),
        "decision_trail": lambda: tools.decision_trail(T.ORG, asset_id=T.WEB1, port=443),
        "company_query": lambda: tools.company_query(T.ORG, "who_owns", {"asset_id": T.WEB1}),
        "triage_memory": lambda: tools.triage_memory(T.ORG, [T.F1, T.F4]),
    }
    assert set(calls) == set(TOOL_NAMES)
    if "threatintel" not in r.list_graphs():  # vuln_intel reads the threatintel graph
        del calls["vuln_intel"]
    for fn in calls.values():
        fn()
    _assert_read_only(r.calls)


def test_write_attempt_is_refused_by_the_server(rec):
    """Belt and braces: even raw ro_query on the org graph rejects writes."""
    r, _ = rec
    with pytest.raises(Exception, match="read-only"):
        r.select_graph(T.ORG).ro_query("CREATE (:Pwned)")
