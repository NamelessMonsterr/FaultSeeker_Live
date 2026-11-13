"""Candidate failures must never masquerade as a complete analysis (fail-closed).

Semantics under test: every attempted candidate (function@address) gets at most 2 attempts. If any attempted candidate
still has an unresolved failure when the review ends, Stage 2 raises (`Stage 2 (Function Analysis) incomplete: ...`) through
the normal pipeline failure path - mixed success/failure included. A later successful retry clears the failure. Zero eligible
candidates, or candidates that were already examined, are valid outcomes.
OFFLINE: only the model provider and Stage 1 are fakes (tests/pipeline_fakes.py).
"""
import pytest

try:
    from faultseeker.core.config import FaultSeekerConfig
    from faultseeker.core.pipeline import FaultSeekerPipeline
    from tests import pipeline_fakes as fakes
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

from tests.conftest import USER_KEY, start_run, wait_final

HASH = "0x" + "c0c0" + "0" * 60


def pipeline(tmp_path, monkeypatch, scenario):
    state = fakes.install(scenario, monkeypatch.setattr)
    monkeypatch.setenv("OPENAI_API_KEY", USER_KEY)
    return FaultSeekerPipeline(FaultSeekerConfig(cache_dir=str(tmp_path / "cache"))), state


def analyze(p):
    return p.analyze_transaction(txn_hash=HASH, chain="bsc")


# ------------------------------------------------------------------------------- pipeline level (real analyzer)

def test_all_candidates_failing_raises_with_redacted_details_not_an_empty_success(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "allfail")
    with pytest.raises(RuntimeError) as err:
        analyze(p)
    message = str(err.value)
    assert "Stage 2 (Function Analysis) incomplete" in message
    assert f"foo@{fakes.A}" in message and f"bar@{fakes.B}" in message, "failed identities are named"
    assert "ProviderDown" in message and len(message) <= 480
    for secret in (USER_KEY, fakes.LEAKY, "Bearer sk-"):
        assert secret not in message, "secrets must not leave the analyzer"


def test_mixed_success_and_failure_is_not_a_complete_success(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "mixed")
    with pytest.raises(RuntimeError) as err:
        analyze(p)
    assert "Stage 2 (Function Analysis) incomplete" in str(err.value)
    assert f"bar@{fakes.B}" in str(err.value) and f"foo@{fakes.A}" not in str(err.value), "only unresolved identities are named"
    assert ("foo",) in state.analyzed, "the healthy candidate was still analyzed before the run was failed"


def test_failure_then_successful_retry_leaves_no_stale_failure_and_attempts_are_bounded(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "retry")
    result = analyze(p)                                        # no exception: the retry succeeded
    assert result["transaction_hash"] == HASH
    assert state.attempts["foo"] == 2, "failed once in the pattern pass, retried once, then succeeded"
    assert p.function_analyzer.failed_function_memo == {f"foo@{fakes.A}": 1}, "the history of the failed attempt stays countable"
    assert p.function_analyzer.unresolved_failures == {}


def test_persistent_failure_is_bounded_to_two_attempts(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "allfail")
    with pytest.raises(RuntimeError):
        analyze(p)
    assert state.attempts == {"foo": 1, "bar": 1}, "no pattern pass here: one attempt each, never an unbounded loop"


def test_zero_eligible_candidates_is_a_valid_success(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "zero")
    result = analyze(p)
    assert result["transaction_hash"] == HASH and state.analyzed == []


def test_healthy_candidates_still_succeed(tmp_path, monkeypatch):
    """guard"""
    p, state = pipeline(tmp_path, monkeypatch, "ok")
    result = analyze(p)
    assert result["transaction_hash"] == HASH
    assert [n for n, in state.analyzed] == ["foo", "bar"]


def test_a_failure_hidden_inside_the_task_loop_still_fails_the_candidate(tmp_path, monkeypatch):
    """_function_analysis_init swallows per-step errors; a candidate whose every step failed made no progress."""
    p, state = pipeline(tmp_path, monkeypatch, "inloop")
    with pytest.raises(RuntimeError) as err:
        analyze(p)
    assert "Stage 2 (Function Analysis) incomplete" in str(err.value) and f"foo@{fakes.A}" in str(err.value)
    assert fakes.LEAKY not in str(err.value) and USER_KEY not in str(err.value)


# ------------------------------------------------------------------------------- identity casing

def test_function_names_differing_only_by_case_at_one_address_are_distinct_candidates(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "case")
    analyze(p)
    assert sorted(n for n, in state.analyzed) == ["Foo", "foo"], "both Solidity functions must be analyzed"
    assert sorted(p.function_analyzer.examined_function_memo) == sorted([f"Foo@{fakes.A}", f"foo@{fakes.A}"])


def test_address_case_is_normalized_but_function_case_is_not():
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    from faultseeker.function_analysis.function_ranker import FunctionRanker
    up = "0x" + "AB" * 20
    assert FunctionAnalyzer._identity("Foo", up) == FunctionAnalyzer._identity("Foo", up.lower()) == "Foo@" + up.lower()
    assert FunctionAnalyzer._identity("Foo", up) != FunctionAnalyzer._identity("foo", up)
    item = {"function": "Foo", "address": up}
    assert FunctionRanker._call_identity(item) == "Foo@" + up.lower()


def test_ranker_keeps_case_distinct_patterns_but_collapses_address_case_duplicates():
    from types import SimpleNamespace
    from faultseeker.function_analysis.function_ranker import FunctionRanker
    forensics = SimpleNamespace(address_calls_with_created_contract=[], functions_to_be_inspected={})
    up = fakes.A.upper().replace("0X", "0x")
    patterns = [fakes.pat("Foo", fakes.A), fakes.pat("foo", fakes.A), fakes.pat("foo", up)]
    result = FunctionRanker().rank(forensics, {"repeated_patterns": {"k": patterns}, "function_call_loc_memo": {}})
    assert [[i["function"] for i in x["pattern"]] for x in result.repeated_patterns] == [["Foo"], ["foo"]]


def test_children_context_of_case_distinct_functions_does_not_collide():
    from tests.test_function_analysis_state import analyzer, entry, A
    child = lambda n: {"function": n, "address": "0x1", "call_type": "call", "type": "call", "params": "p", "children": []}
    a = analyzer(inspected={f"Foo_{A}": entry(depth=(0,)), f"foo_{A}": entry(depth=(1,))},
                 trace=[{"children": [child("onlyFoo")]}, {"children": [child("onlyfoo")]}])
    a._prepare_children_call_memo([f"Foo_{A}", f"foo_{A}"])
    a._retrieve_chidlren_calls_memo_single("Foo", A)
    assert list(a.children_call_memo_single) == ["onlyFoo::0x1"]
    a._retrieve_chidlren_calls_memo_single("foo", A)
    assert list(a.children_call_memo_single) == ["onlyfoo::0x1"]


# ------------------------------------------------------------------------------- run / API level (real worker subprocess)

def run_scenario(make_client, scenario):
    c = make_client(FAULTSEEKER_WORKER_MODULE="tests.pipeline_fake_worker")
    run_id = start_run(c, txn_hash="0x" + fakes.HASH_PREFIX[scenario] + "0" * 60)
    return c, run_id, wait_final(c, run_id, 60)["run"]


def test_api_all_candidates_failed_run_fails_with_useful_redacted_error(make_client):
    c, run_id, run = run_scenario(make_client, "allfail")
    assert run["state"] == "failed", run
    err = run["error"]
    assert err["code"] == "analysis_incomplete"
    assert f"foo@{fakes.A}" in err["message"] and f"bar@{fakes.B}" in err["message"]
    for body in (c.get(f"/api/runs/{run_id}").text, c.get("/api/runs").text):
        assert USER_KEY not in body and fakes.LEAKY not in body
    assert c.get(f"/api/runs/{run_id}/result").status_code in (404, 409), "no result may be published for a failed run"


def test_api_mixed_run_fails_and_publishes_no_result(make_client):
    c, run_id, run = run_scenario(make_client, "mixed")
    assert run["state"] == "failed" and run["error"]["code"] == "analysis_incomplete"
    assert f"bar@{fakes.B}" in run["error"]["message"] and f"foo@{fakes.A}" not in run["error"]["message"]
    assert c.get(f"/api/runs/{run_id}/result").status_code in (404, 409)


def test_api_retry_then_success_completes(make_client):
    c, run_id, run = run_scenario(make_client, "retry")
    assert run["state"] == "completed", run
    assert c.get(f"/api/runs/{run_id}/result").status_code == 200


def test_api_zero_candidates_completes(make_client):
    c, run_id, run = run_scenario(make_client, "zero")
    assert run["state"] == "completed", run
