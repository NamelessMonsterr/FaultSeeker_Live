"""Selection and completion honesty (OFFLINE; replies are controlled fakes).

Selection: a narrowing reply is validated against the candidate set. Prioritization is kept (the model's order), every
candidate is accounted for as selected / analyzed / omitted / failed, and omitted candidates never count as analyzed.
Completion: only an explicit, validated response completes a candidate; look-alikes ("not yet, yes later", a quoted
yes, malformed text, a provider failure) do not.
"""
import json
from types import SimpleNamespace

import pytest

try:
    from faultseeker.function_analysis.function_analyzer import CandidateIncomplete, FunctionAnalyzer
    from faultseeker.utils.agent import AbstractAgent, ProviderFailure
    from tests.test_function_analysis_state import analyzer as make_analyzer, entry
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

A = "0x" + "aa" * 20


class Script(AbstractAgent):
    """Replies from a list, the last one repeating. Records every prompt."""

    def __init__(self, *replies):
        super().__init__("", "script")
        self.replies, self.prompts = list(replies), []

    def _send_message(self, user_message, temperature=0):
        self.prompts.append(user_message)
        return self.replies[min(len(self.prompts) - 1, len(self.replies) - 1)]


def review(narrowing_replies, n=7, created=None, failing=()):
    keys = {f"f{i}_{A}": entry() for i in range(n)}
    a = make_analyzer(inspected=keys, created=created)
    a.agent = Script(*narrowing_replies)
    a.function_prompts = SimpleNamespace(narrow_down_functions="{function_call_to_be_inspected}|{balance_change}",
                                         narrow_down_functions_with_created_contracts="{function_call_to_be_inspected}")
    original = a._function_analysis_init

    def init():
        original()
        if a.function_call_info_summary.get("function") in failing:
            raise RuntimeError("model call failed")
    a._function_analysis_init = init
    a._review_function_calls()
    return a


def analyzed_names(a):
    return [i[0] for i, _ in a.analyzed]


# ------------------------------------------------------------------------------------------------- selection

def test_a_narrowing_reply_naming_only_unknown_functions_is_ignored_and_nothing_is_dropped():
    a = review([json.dumps([f"ghost_{A}", "phantom", "x_0x1"])])
    assert analyzed_names(a) == [f"f{i}" for i in range(7)], "an invalid selection must not replace the candidate set"
    cov = a.coverage_report()
    assert cov["omitted"] == [] and cov["status"] == "complete" and cov["selection_replies_ignored"] >= 1


def test_a_narrowing_reply_with_some_unknown_names_keeps_the_valid_ones_in_the_models_order():
    a = review([json.dumps([f"f5_{A}", f"ghost_{A}", f"f2_{A}", f"f2_{A}", f"f0_{A}"])])
    assert analyzed_names(a) == ["f5", "f2", "f0"], "prioritization (the model's order) is preserved; unknown and duplicate names are not"
    cov = a.coverage_report()
    assert cov["selection_rejected"] == 2
    assert cov["omitted"] == sorted(f"f{i}@{A}" for i in (1, 3, 4, 6))


def test_every_candidate_is_accounted_for_and_omitted_ones_are_not_analyzed():
    a = review([json.dumps([f"f1_{A}", f"f2_{A}", f"f3_{A}"])])
    cov = a.coverage_report()
    assert cov["candidates"] == 7 and cov["selected"] == 3 and cov["analyzed"] == 3
    assert len(cov["omitted"]) == 4 and cov["failed"] == []
    assert cov["status"] == "limited" and cov["limited"] is True
    assert sorted(a.examined_function_memo) == sorted(f"f{i}@{A}" for i in (1, 2, 3)), "omitted must not count as examined"
    assert not set(cov["omitted"]) & set(a.examined_function_memo)


def test_failed_candidates_are_reported_separately_from_omitted_ones():
    a = review([json.dumps([f"f1_{A}", f"f2_{A}", f"f3_{A}"])], failing={"f2"})
    cov = a.coverage_report()
    assert cov["failed"] == [f"f2@{A}"] and cov["analyzed"] == 2 and cov["selected"] == 3
    assert f"f2@{A}" not in cov["omitted"] and len(cov["omitted"]) == 4


def test_narrowing_is_only_accepted_when_it_actually_narrows():
    a = review([json.dumps([f"f{i}_{A}" for i in range(7)])])          # the same 7: not smaller, nothing omitted
    assert a.coverage_report()["omitted"] == [] and len(analyzed_names(a)) == 7


def test_case_of_the_function_name_matters_in_a_selection_and_address_case_does_not():
    keys = {f"Foo_{A}": entry(), f"foo_{A}": entry(), **{f"g{i}_{A}": entry() for i in range(5)}}
    a = make_analyzer(inspected=keys)
    a.agent = Script(json.dumps([f"FOO_{A}", f"Foo_{'0x' + A[2:].upper()}"]))
    a.function_prompts = SimpleNamespace(narrow_down_functions="{function_call_to_be_inspected}|{balance_change}",
                                         narrow_down_functions_with_created_contracts="{function_call_to_be_inspected}")
    a._review_function_calls()
    assert analyzed_names(a) == ["Foo"], "FOO is nobody; Foo resolves with a different address case"


def test_created_contract_selection_is_validated_too():
    created = {f"mk{i}": {"count": 1, "calls": [{"gas": 1, "params": "", "depth": [], "address": A}], "address": [A]} for i in range(7)}
    a = make_analyzer(created=created)
    a.agent = Script(json.dumps(["nonexistent", "mk3", "other"]))
    a.function_prompts = SimpleNamespace(narrow_down_functions="x{function_call_to_be_inspected}{balance_change}",
                                         narrow_down_functions_with_created_contracts="{function_call_to_be_inspected}")
    a._review_function_calls()
    assert analyzed_names(a) == ["mk3"]
    cov = a.coverage_report()
    assert cov["candidates"] == 7 and cov["selected"] == 1 and len(cov["omitted"]) == 6 and cov["selection_rejected"] == 2


def test_genuinely_empty_input_is_distinguished_from_an_empty_analysis_caused_by_selection():
    empty = make_analyzer()
    empty._review_function_calls()
    assert empty.coverage_report()["status"] == "no_candidates" and empty.coverage_report()["limited"] is False
    narrowed = review([json.dumps([f"f1_{A}"])])
    cov = narrowed.coverage_report()
    assert cov["status"] == "limited" and cov["candidates"] == 7 and cov["analyzed"] == 1


def test_coverage_travels_in_the_analysis_result_contract():
    a = review([json.dumps([f"f1_{A}"])])
    cov = a.coverage_report()
    assert set(cov) >= {"status", "limited", "candidates", "selected", "analyzed", "omitted", "failed", "selection_rejected",
                        "selection_replies_ignored"}
    json.dumps(cov)


# ------------------------------------------------------------------------------------------------- completion

def run_loop(check_replies, monkeypatch=None, final_steps=40):
    """Drives the production _function_analysis_init loop with stubbed steps; only the adequacy replies are controlled."""
    a = object.__new__(FunctionAnalyzer)
    a.function_prompts = SimpleNamespace(function_analysis_init_prompt="init", check_analysis_adequacy="adequacy?")
    a.function_call_info_summary, a.understanding_result = {}, "u"
    a.reasoning_agent = Script("tree")
    a.organization_agent = Script(*check_replies)
    a.potentially_vulnerable_functions = {}
    a._temp_check = lambda: False
    steps = {"n": 0}

    def step():
        steps["n"] += 1
    a._update_current_understanding = lambda **kw: None
    a._select_task, a._perform_task = step, lambda: None
    a._update_task_tree, a._update_potentially_vulnerable_function = lambda: None, lambda: None
    try:
        a._function_analysis_init()
        outcome = "complete"
    except CandidateIncomplete as exc:
        outcome = exc
    return outcome, steps["n"], len(a.organization_agent.prompts)


@pytest.mark.parametrize("reply", ["Yes", "yes", "YES", " yes\n", "Yes.", "yes!", '{"adequate": true}', '```json\n{"adequate": true}\n```'])
def test_an_explicit_yes_completes_the_candidate(reply):
    outcome, steps, checks = run_loop([reply])
    assert outcome == "complete" and checks == 1 and steps == 3


@pytest.mark.parametrize("reply", ["not yet, yes later", '"yes"', "'yes'", "I think yes", "yes, but it needs more work", "No, not yes",
                                   "Yes/No", "maybe", "", "   ", '{"adequate": "yes"}', '{"adequate": true', '{"adequate": false}',
                                   '{"adequate": 1}', "yesterday", "yes yes", "eyes", "[true]", "no"])
def test_look_alikes_never_complete_and_stay_bounded(reply):
    outcome, steps, checks = run_loop([reply])
    if reply.strip() == "":
        assert isinstance(outcome, CandidateIncomplete) and "provider" in str(outcome)       # empty content is a provider failure
        return
    assert isinstance(outcome, CandidateIncomplete), f"{reply!r} must not mark the candidate complete"
    assert "iteration limit" in str(outcome) and outcome.retryable is False
    assert checks == 10 and steps == 31, "the existing bound is unchanged (31 iterations, a check every third)"


def test_a_later_explicit_yes_completes_after_unusable_replies():
    outcome, steps, checks = run_loop(["no", "not yet, yes later", "Yes"])
    assert outcome == "complete" and checks == 3 and steps == 9


def test_a_provider_failure_at_the_adequacy_check_is_terminal_and_not_read_as_an_answer():
    outcome, steps, checks = run_loop(["An error occurred."])
    assert isinstance(outcome, CandidateIncomplete) and outcome.retryable is False
    assert "provider failure" in str(outcome) and checks == 1 and steps == 3


def test_the_alt_adequacy_check_uses_the_same_validation():
    a = object.__new__(FunctionAnalyzer)
    for reply, expected in (("Yes", True), ("not yet, yes later", False), ('"yes"', False), ("no", False), ("garbage", False)):
        assert a._adequacy_verdict(reply) is expected, reply


# ------------------------------------------------------------------------------------------------- real pipeline contract

def _pipeline(tmp_path, monkeypatch, scenario):
    from faultseeker.core.config import FaultSeekerConfig
    from faultseeker.core.pipeline import FaultSeekerPipeline
    from tests import pipeline_fakes as fakes
    from tests.conftest import USER_KEY
    fakes.install(scenario, monkeypatch.setattr)
    monkeypatch.setenv("OPENAI_API_KEY", USER_KEY)
    p = FaultSeekerPipeline(FaultSeekerConfig(cache_dir=str(tmp_path / "cache")))
    return p.analyze_transaction(txn_hash="0x" + "c5c5" + "0" * 60, chain="bsc")


def test_the_pipeline_result_carries_coverage_and_the_report_states_it(tmp_path, monkeypatch):
    from faultseeker.server import results
    raw = _pipeline(tmp_path, monkeypatch, "ok")
    assert raw["coverage"]["status"] == "complete" and raw["coverage"]["analyzed"] == 2 and raw["verdict_rejections"] == {}
    out = results.normalize(raw)
    assert out["coverage"]["analyzed"] == 2 and out["coverage"]["limited"] is False
    assert any("No potentially vulnerable functions were identified for this transaction." == w for w in out["warnings"])


def test_a_pipeline_with_no_candidates_reports_genuinely_empty_input(tmp_path, monkeypatch):
    from faultseeker.server import results
    raw = _pipeline(tmp_path, monkeypatch, "zero")
    assert raw["coverage"]["status"] == "no_candidates"
    assert any("No candidate functions were found" in w for w in results.normalize(raw)["warnings"])
