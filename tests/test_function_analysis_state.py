"""F3 (ranker identities), F4 (candidate identity / outcomes) and F5 (stale children context). OFFLINE: no model is called;
the analyzer's model-driven steps are replaced by recording stubs."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

try:
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    from faultseeker.function_analysis.function_ranker import FunctionRanker
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

A, B, C = "0x" + "aa" * 20, "0x" + "bb" * 20, "0x" + "cc" * 20


def call(function, address, depth=(0,), call_type="call"):
    return {"function": function, "address": address, "call_type": call_type, "depth": list(depth), "gas": 1, "params": ""}


def rank(patterns, loc_memo=None, inspected=None):
    forensics = SimpleNamespace(address_calls_with_created_contract=[], functions_to_be_inspected=inspected or {})
    analysis = {"repeated_patterns": {"k": deepcopy(patterns)}, "function_call_loc_memo": loc_memo or {}}
    return FunctionRanker().rank(forensics, analysis)


def pattern(*items, repeats=4):
    return {"pattern": list(items), "repeats": repeats, "start_index": 0, "end_index": 9}


def names(result):
    return [[(i["function"], i["address"]) for i in p["pattern"]] for p in result.repeated_patterns]


# ---------------------------------------------------------------------------------------------- F3

def test_distinct_eligible_patterns_do_not_collapse():
    result = rank([pattern(call("foo", A)), pattern(call("bar", A))])
    assert names(result) == [[("foo", A)], [("bar", A)]]


def test_same_function_on_different_contracts_stays_distinct():
    result = rank([pattern(call("foo", A)), pattern(call("foo", B))])
    assert names(result) == [[("foo", A)], [("foo", B)]]


def test_true_duplicates_collapse_regardless_of_depth_and_repeats():
    result = rank([pattern(call("foo", A, (0,)), call("bar", B, (0,)), repeats=4),
                   pattern(call("foo", A, (3, 1)), call("bar", B, (3, 2)), repeats=9),
                   pattern(call("foo", A.upper().replace("0X", "0x")), call("bar", B), repeats=5)])      # address case is normalized
    assert len(result.repeated_patterns) == 1 and result.repeated_patterns[0]["repeats"] == 4


def test_order_and_multiplicity_are_part_of_the_identity():
    ab = pattern(call("foo", A), call("bar", A))
    ba = pattern(call("bar", A), call("foo", A))
    aab = pattern(call("foo", A), call("foo", A), call("bar", A))
    result = rank([ab, ba, aab, deepcopy(ab)])
    assert names(result) == [[("foo", A), ("bar", A)], [("bar", A), ("foo", A)], [("foo", A), ("foo", A), ("bar", A)]]


def test_patterns_containing_filtered_or_unnamed_functions_are_still_skipped():
    result = rank([pattern(call("transfer", A), call("foo", A)), pattern(call(None, A), call("foo", A)),
                   pattern(call("balanceOf", A), repeats=9)])
    assert result.repeated_patterns == []


def test_fallback_populates_address_list_and_applies_the_safe_function_filter():
    memo = {f"foo::{A}": [call("foo", A)], f"transfer::{A}": [call("transfer", A)],
            f"safe_swap::{B}": [call("safe_swap", B), call("safe_swap", B, (1,))],
            f"algebraswapcallback::{C}": [call("algebraswapcallback", C)]}
    result = rank([], loc_memo=memo)
    assert set(result.functions_to_be_inspected) == {f"foo_{A}", f"safe_swap_{B}"}
    assert result.functions_to_be_inspected[f"safe_swap_{B}"]["count"] == 2
    assert result.address_list == [A, B], "addresses of the fallback functions must be listed (and only those)"


def test_fallback_is_not_used_when_the_ordinary_path_found_functions():
    inspected = {"x": [{"function": "foo", "address": A, "gas": 1, "params": "p", "depth": [0]}]}
    result = rank([], loc_memo={f"bar::{B}": [call("bar", B)]}, inspected=inspected)
    assert list(result.functions_to_be_inspected) == [f"foo_{A}"] and result.address_list == [A]


# ---------------------------------------------------------------------------------------------- F4 / F5 harness

def analyzer(inspected=None, created=None, patterns=None, trace=None):
    a = object.__new__(FunctionAnalyzer)
    a.functions_to_be_inspected = inspected or {}
    a.address_calls_with_created_contract_in_params = created or {}
    a.repeated_patterns = patterns or []
    a.trace = trace if trace is not None else [{"children": []}]
    a.txn_seq = {"created_address": []}
    a.fundflow_analysis = {"balance_change": {}}
    a.children_call_memo, a.children_call_memo_single = {}, {}
    a.task_tree = a.current_task = a.processing_result = a.understanding_result = ""
    a.function_call_info_summary = {}
    a.potentially_vulnerable_functions = {}
    a.analyzed = []
    a._retrieve_related_info = lambda address, function: {}

    def fake_init():
        s = a.function_call_info_summary
        ident = (s.get("function"), s.get("address"))
        a.analyzed.append((ident, deepcopy(s.get("high_appreance_count_children_calls"))))
    a._function_analysis_init = fake_init
    return a


def entry(count=1, depth=()):
    return {"count": count, "calls": [{"gas": 1, "params": "", "depth": list(depth)}]}


def idents(a):
    return [i for i, _ in a.analyzed]


# ---------------------------------------------------------------------------------------------- F4

def test_same_name_on_two_contracts_is_analyzed_for_each(capsys):
    a = analyzer(inspected={f"foo_{A}": entry(2), f"foo_{B}": entry(1)})
    a._review_function_calls()
    assert idents(a) == [("foo", A), ("foo", B)]
    out = capsys.readouterr().out
    assert "[1/2] Analyzing foo..." in out and "[2/2] Analyzing foo..." in out, "the displayed [current/total] format is kept"


def test_underscores_in_function_names_are_preserved():
    a = analyzer(inspected={f"safe_transfer_{A}": entry(), f"_internal_mint_{B}": entry()})
    a._review_function_calls()
    assert idents(a) == [("safe_transfer", A), ("_internal_mint", B)]


def test_created_contract_names_with_underscores_are_analyzed():
    created = {"safe_transfer": {"count": 1, "calls": [{"gas": 1, "params": "", "depth": [], "address": A}], "address": [A]}}
    a = analyzer(created=created)
    a._review_function_calls()
    assert [i[0] for i in idents(a)] == ["safe_transfer"]


def test_created_contract_group_does_not_suppress_the_same_name_elsewhere():
    created = {"foo": {"count": 1, "calls": [{"gas": 1, "params": "", "depth": []}], "address": [A, B]}}
    a = analyzer(inspected={f"foo_{B}": entry(), f"foo_{C}": entry()}, created=created)
    a._review_function_calls()
    found = idents(a)
    assert ("foo", C) in found, "foo on a third contract must still be analyzed"
    assert ("foo", B) not in found, "foo@B was already analyzed in the created-contract group (recorded without an address key)"
    assert found == [("foo", None), ("foo", C)]
    assert sorted(a.examined_function_memo) == sorted([f"foo@{A}", f"foo@{B}", f"foo@{C}"])


def test_a_failed_analysis_is_not_marked_examined_and_may_be_retried_once():
    pat = pattern(call("foo", A))
    a = analyzer(inspected={f"foo_{A}": entry()}, patterns=[pat])
    seen = {"n": 0}
    original = a._function_analysis_init

    def failing_first():
        seen["n"] += 1
        original()
        if seen["n"] == 1:
            raise RuntimeError("model call failed")
    a._function_analysis_init = failing_first
    a._review_function_calls()                                   # does not raise: the failure is recorded
    assert seen["n"] == 2, "the pattern attempt failed; the selected-function pass retried it and succeeded"
    assert a.failed_function_memo == {f"foo@{A}": 1}
    assert f"foo@{A}" in a.examined_function_memo


def test_persistent_failure_is_bounded_and_does_not_loop():
    pats = [pattern(call("foo", A)), pattern(call("foo", A), call("bar", A))]
    a = analyzer(inspected={f"foo_{A}": entry()}, patterns=pats)
    attempts = {"n": 0}

    def always_fail():
        attempts["n"] += 1
        raise RuntimeError("model unavailable")
    a._function_analysis_init = always_fail
    a._review_function_calls()
    assert attempts["n"] <= 4 and attempts["n"] >= 2
    assert a.failed_function_memo[f"foo@{A}"] <= 2
    assert f"foo@{A}" not in a.examined_function_memo


def test_candidates_are_recorded_only_after_success():
    a = analyzer(inspected={f"foo_{A}": entry(), f"bar_{A}": entry()})
    first = {"done": False}
    original = a._function_analysis_init

    def check_not_examined_yet():
        assert a.examined_function_memo == [] or first["done"], "a candidate must not be marked before it is analyzed"
        original()
        first["done"] = True
    a._function_analysis_init = check_not_examined_yet
    a._review_function_calls()
    assert sorted(a.examined_function_memo) == sorted([f"foo@{A}", f"bar@{A}"])


# ---------------------------------------------------------------------------------------------- F5

def children_trace():
    child = {"function": "bar", "address": "0x1", "call_type": "call", "type": "call", "params": "p", "children": []}
    return [{"children": [child]}]


def test_miss_returns_empty_context_after_a_hit():
    a = analyzer()
    a.children_call_memo = {f"foo_{A}": {"bar::0x1": {"count": 1, "params": ["p"], "call_details": {}}}}
    a._retrieve_chidlren_calls_memo_single("foo", A)
    assert list(a.children_call_memo_single) == ["bar::0x1"]
    a._retrieve_chidlren_calls_memo_single("baz", B)
    assert a.children_call_memo_single == {}, "a miss must not keep the previous function's children"


def test_retrieval_does_not_mutate_the_stored_memo():
    a = analyzer()
    a.children_call_memo = {f"foo_{A}": {"bar::0x1": {"count": 1, "params": ["p"], "call_details": {}}}}
    a._retrieve_chidlren_calls_memo_single("foo", A)
    a.children_call_memo_single["bar::0x1"]["note"] = "x"
    assert "note" not in a.children_call_memo[f"foo_{A}"]["bar::0x1"]


@pytest.mark.parametrize("stored_key,lookup", [(f"Foo_{A.upper().replace('0X', '0x')}", ("Foo", A)),
                                               (f"Foo_{A}", ("Foo", A.upper().replace("0X", "0x")))])
def test_prepare_and_retrieve_agree_on_address_case(stored_key, lookup):
    """The address part of a key is case-insensitive; the function name is not (see test_candidate_failure_propagation)."""
    a = analyzer(inspected={stored_key: entry(depth=(0,))}, trace=children_trace())
    a._prepare_children_call_memo([stored_key])
    a._retrieve_chidlren_calls_memo_single(*lookup)
    assert list(a.children_call_memo_single) == ["bar::0x1"]


def test_function_name_case_is_not_normalized_in_children_lookup():
    a = analyzer(inspected={f"Foo_{A}": entry(depth=(0,))}, trace=children_trace())
    a._prepare_children_call_memo([f"Foo_{A}"])
    a._retrieve_chidlren_calls_memo_single("foo", A)
    assert a.children_call_memo_single == {}


def test_children_context_does_not_leak_between_candidates():
    a = analyzer(inspected={f"foo_{A}": entry(depth=(0,)), f"qux_{B}": entry(depth=())}, trace=children_trace())
    a._review_function_calls()
    by_ident = dict(a.analyzed)
    assert by_ident[("foo", A)] == {"bar::0x1": 1}
    assert by_ident[("qux", B)] == {}, "qux has no children: it must not see foo's"
