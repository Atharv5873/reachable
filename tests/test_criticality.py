"""S8: path-criticality, the ranking signal (pure: no database, no labels)."""

from __future__ import annotations

from reachable_graph.criticality import CrownPath, dedupe, rank_by_criticality


def P(*tokens: str, lk: float = 0.5, w: float = 1.0, target: str = "ds:1") -> CrownPath:
    return CrownPath(target=target, weight=w, likelihood=lk, tokens=tokens, entry=tokens[0])


def order(paths, **kw) -> list[str]:
    return [c.token for c in rank_by_criticality(paths, **kw)]


def test_a_funnel_on_three_paths_outranks_internet_facing_steps_on_one():
    # Three entry findings (Internet-facing, likelier) each on one path, all
    # funnelling through one internal finding: the funnel closes three routes.
    paths = [P("e1", "funnel", lk=0.9), P("e2", "funnel", lk=0.8), P("e3", "funnel", lk=0.7)]
    ranked = rank_by_criticality(paths)
    assert ranked[0].token == "funnel"
    assert (ranked[0].criticality, len(ranked[0].paths), ranked[0].entry) == (3.0, 3, False)
    assert [c.token for c in ranked[1:]] == ["e1", "e2", "e3"]  # then by likelihood


def test_target_sensitivity_weights_the_count():
    paths = [P("a", lk=0.1, w=1.0), P("b", lk=0.9, w=0.4), P("b", "x", lk=0.9, w=0.4)]
    # b lies on two paths to a "medium" store (0.8); a on one to a crown jewel (1.0)
    assert order(paths) == ["a", "b", "x"]


def test_ties_cover_a_new_route_before_a_second_finding_of_a_listed_one():
    # Two routes; route 1 has two findings that are likelier than route 2's one.
    paths = [P("r1a", "r1b", lk=0.9), P("r2a", lk=0.1)]
    first_three = order(paths)
    assert first_three[:2] in (["r1a", "r2a"], ["r1b", "r2a"])  # both routes in the top 2


def test_a_path_counts_once_per_token_and_include_filters():
    paths = [P("f1", "step:x", "f1", lk=0.5)]
    ranked = rank_by_criticality(paths, include=lambda t: not t.startswith("step:"))
    assert [(c.token, c.criticality) for c in ranked] == [("f1", 1.0)]


def test_final_tiebreak_is_a_hash_not_the_id():
    # Generated ids carry generation order (planted findings come last); a
    # tie must not be broken by it.
    toks = [f"org:finding:{i:05d}" for i in range(40)]
    ranked = order([P(t, lk=0.5) for t in toks])
    assert sorted(ranked) == toks and ranked != toks and ranked != toks[::-1]


def test_dedupe_keeps_one_path_per_step_sequence():
    a, b = P("x", lk=0.5), P("x", lk=0.4)
    assert dedupe([(("k1",), a), (("k1",), b), (("k2",), b)]) == [a, b]
