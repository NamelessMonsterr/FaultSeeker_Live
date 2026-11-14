"""Model replies are validated before use. OFFLINE tests: no live chain, RPC or model is involved.

Provenance: a live Ethereum run failed in function analysis with `TypeError: list indices must be integers or slices, not
str`, and earlier source lookups used the invalid addresses "0" and "5". These tests reproduce both mechanisms offline
with raw-text model replies (the only fake is the provider call; JSON parsing, validation, the candidate loop, the
failure bookkeeping, the pipeline, the worker and the API are production code). They are regression tests for those
mechanisms, not proof about any real chain or model.

Contract: AbstractAgent.query_json(...) returns a parsed value of the expected type or raises ModelResponseError (never text,
never a guessed structure, never eval). A malformed REQUIRED part (the task) fails the candidate through the existing
failure path; malformed OPTIONAL entries (additional-information items, narrowing replies) are skipped.
"""
import re
from types import SimpleNamespace

import pytest

try:
    from faultseeker.core.config import FaultSeekerConfig
    from faultseeker.core.pipeline import FaultSeekerPipeline
    import faultseeker.function_analysis.function_analyzer as fa
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer, MAX_TASK_SELECTION_ATTEMPTS
    from faultseeker.utils.agent import AbstractAgent, ModelResponseError
    from tests import pipeline_fakes as fakes
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

from tests.conftest import USER_KEY, start_run, wait_final

A, B = fakes.A, fakes.B
HASH = "0x" + "c2c2" + "0" * 60
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


class ScriptAgent(AbstractAgent):
    """Replies with the scripted raw texts in order (the last one repeats) and counts the requests."""

    def __init__(self, *replies):
        super().__init__("", "script")
        self.replies, self.requests = list(replies), 0

    def _send_message(self, user_message, temperature=0):
        reply = self.replies[min(self.requests, len(self.replies) - 1)]
        self.requests += 1
        return reply


class RecordingDownloader:
    CALLS = []

    def __init__(self, chain, addresses, *a, **k):
        RecordingDownloader.CALLS.append(list(addresses))

    def run(self):
        return {}


def make_analyzer(monkeypatch, *replies):
    RecordingDownloader.CALLS = []
    monkeypatch.setattr(fa, "ContractDownloader", RecordingDownloader)
    a = object.__new__(FunctionAnalyzer)
    a.function_prompts = SimpleNamespace(retrieve_additional_info="R:", function_call_task_selection="{task_tree}|{function_call_info_summary}|{current_understanding}")
    a.task_tree = a.understanding_result = a.current_task = ""
    a.function_call_info_summary = {"function": "foo", "calls": [], "high_appreance_count_children_calls": {}}
    a.generation_agent = a.agent = ScriptAgent(*replies)
    a.fundflow_analysis = {"balance_change": {}}
    a.tx_analysis = {"function_call_loc_memo": {}}
    a.contract_info = {}
    a.analysis_result = SimpleNamespace(chain="bsc")
    return a


GOOD_TASK = fakes.GOOD_TASK


# ------------------------------------------------------------------------------------------ the JSON contract

@pytest.mark.parametrize("reply,expect,value", [
    ('{"a": 1}', dict, {"a": 1}),
    ('```json\n{"a": 1}\n```', dict, {"a": 1}),
    ("{'a': (1, 2)}", dict, {"a": (1, 2)}),                    # Python-literal replies stay supported
    ('["x", "y"]', list, ["x", "y"]),
    ('[["0x1", "foo"]]', (list, dict), [["0x1", "foo"]]),
    ("{}", dict, {}),
])
def test_query_json_returns_a_value_of_the_expected_type(reply, expect, value):
    assert ScriptAgent(reply).query_json("q", expect=expect) == value


@pytest.mark.parametrize("reply", ["plain prose, not JSON", "An error occurred.", "", "   ", '{"a": ', '"just a string"', "42", "null",
                                   '["list"]', "line one\nline two"])
def test_query_json_rejects_text_provider_errors_empty_and_the_wrong_type(reply):
    with pytest.raises(ModelResponseError):
        ScriptAgent(reply).query_json("q", expect=dict)


def test_query_json_errors_do_not_quote_the_reply():
    with pytest.raises(ModelResponseError) as err:
        ScriptAgent(f"free text {fakes.LEAKY} api_key={fakes.DECOY_KV}").query_json("q", expect=dict)
    assert fakes.LEAKY not in str(err.value) and fakes.DECOY_KV not in str(err.value) and len(str(err.value)) < 200


def test_query_json_never_evaluates_model_text(tmp_path):
    marker = tmp_path / "pwned"
    with pytest.raises(ModelResponseError):
        ScriptAgent(f"__import__('pathlib').Path({str(marker)!r}).write_text('x')").query_json("q", expect=dict)
    assert not marker.exists()


def test_the_legacy_query_still_returns_text_for_callers_that_check_the_type_themselves():
    """guard: query(format='json') keeps its lenient behaviour (Stage 1 victim detection validates with isinstance)."""
    assert ScriptAgent("An error occurred.").query("q", format="json") in ("An error occurred.", ["An error occurred."])
    assert ScriptAgent("hello").query("q", format="str") == "hello"


# ------------------------------------------------------------------------------------------ 1. task selection

@pytest.mark.parametrize("task", [
    [], ["inspect"], "inspect the function", 7, None,
    {}, {"task_selected": 1}, {"task_description": ""}, {"task_description": "   "},
    {"task_description": 5}, {"task_description": ["a", "b"]},
    {"description": None, "task_description": None}, {"description": 3},
])
def test_normalize_task_rejects_malformed_required_parts(task):
    with pytest.raises(ModelResponseError):
        FunctionAnalyzer._normalize_task(task)


@pytest.mark.parametrize("task,expected_info", [
    ({"task_description": "look"}, ""),
    ({"description": "look"}, ""),
    ({"description": "look", "task_description": "ignored"}, ""),
    ({"task_description": "look", "additional_information": "src"}, "src"),
    ({"task_description": "look", "additional_information": ["a"]}, ["a"]),
    ({"task_description": "look", "additional_information": 12}, ""),
    ({"task_description": "look", "additional_information": None}, ""),
])
def test_normalize_task_accepts_the_supported_forms(task, expected_info):
    out = FunctionAnalyzer._normalize_task(dict(task))
    assert out["task_description"] == "look"
    assert out["additional_information"] == expected_info


def test_select_task_retries_non_object_replies_then_accepts_a_valid_task(monkeypatch):
    a = make_analyzer(monkeypatch, '["not an object"]', "still prose", GOOD_TASK)

    a._select_task()

    assert a.current_task["task_description"] == "inspect the function"
    assert a.generation_agent.requests == 3


@pytest.mark.parametrize("reply", [
    '["inspect the function"]',
    "Inspect the function.",
])
def test_select_task_gives_up_after_four_replies_without_fabricating_a_task(
    monkeypatch, reply
):
    a = make_analyzer(monkeypatch, reply)

    with pytest.raises(fa.CandidateIncomplete) as err:
        a._select_task()

    assert a.generation_agent.requests == 4, (
        "the original request plus three reformat requests; "
        "one structured request per selection attempt"
    )
    assert a.current_task == "", "no task is invented"
    assert err.value.retryable is True
    assert "no usable task after 4 model requests" in str(err.value)
    assert len(str(err.value)) < 300


def test_select_task_uses_one_aggregate_four_request_budget_not_twelve(monkeypatch):
    # Every response is unparseable. query_json_once must prevent the
    # three internal query_json retries from multiplying four selection attempts.
    a = make_analyzer(monkeypatch, "not JSON")

    with pytest.raises(fa.CandidateIncomplete) as err:
        a._select_task()

    assert a.generation_agent.requests == MAX_TASK_SELECTION_ATTEMPTS == 4
    assert err.value.retryable is True
    assert a.current_task == ""


def test_select_task_stops_at_once_on_a_provider_failure_instead_of_asking_to_reformat(
    monkeypatch,
):
    """A provider failure is not a formatting problem: no reformat requests."""
    from faultseeker.utils.agent import ProviderFailure

    a = make_analyzer(monkeypatch, "An error occurred.")

    with pytest.raises(ProviderFailure):
        a._select_task()

    assert a.generation_agent.requests == 1
    assert a.current_task == ""


@pytest.mark.parametrize("reply", [
    '{"task_selected": 1}',
    '{"task_description": ["a"]}',
    '{"task_description": ""}',
])
def test_select_task_retries_valid_objects_with_bad_required_fields(
    monkeypatch, reply
):
    # A syntactically valid object with an invalid required field consumes
    # one selection attempt, just like an unparseable structured response.
    a = make_analyzer(monkeypatch, reply, GOOD_TASK)

    a._select_task()

    assert a.generation_agent.requests == 2
    assert a.current_task["task_description"] == "inspect the function"


@pytest.mark.parametrize("reply", [
    '{"task_selected": 1}',
    '{"task_description": ["a"]}',
    '{"task_description": ""}',
])
def test_select_task_exhausts_budget_on_repeated_invalid_required_fields(
    monkeypatch, reply
):
    a = make_analyzer(monkeypatch, reply)

    with pytest.raises(fa.CandidateIncomplete) as err:
        a._select_task()

    assert a.generation_agent.requests == MAX_TASK_SELECTION_ATTEMPTS == 4
    assert a.current_task == ""
    assert err.value.retryable is True
    assert "task_description" in str(err.value)


def test_perform_task_raises_a_clear_error_not_a_typeerror_for_a_list_task(monkeypatch):
    a = make_analyzer(monkeypatch, "{}")
    a.current_task = ["inspect the function"]

    with pytest.raises(ModelResponseError):
        a._perform_task()


# ------------------------------------------------------------------------------------------ 2./4. additional information

def info(monkeypatch, reply):
    a = make_analyzer(monkeypatch, reply)
    return a, a._retrieve_additional_info("anything")


def test_source_code_as_a_list_of_plain_strings_is_skipped_not_indexed(monkeypatch):
    a, out = info(monkeypatch, '{"source_code": ["0x' + "aa" * 20 + '", "0xa9059cbb"]}')
    assert out == {} and RecordingDownloader.CALLS == [], "no character of a string may become an address"


def test_source_code_keeps_valid_entries_and_skips_malformed_ones(monkeypatch):
    import json
    reply = json.dumps({"source_code": [
        {"function": "foo", "address": A}, "garbage", ["0x1234", "foo"], [B, "bar"], {"function": "baz", "address": "0"},
        {"function_name": "qux", "address": B.upper().replace("0X", "0x")}, 5, None, ["only-one"], {"function": 3, "address": A}]})
    a, out = info(monkeypatch, reply)
    assert sorted(out["source_code"]) == sorted([f"foo_{A}", f"bar_{B}", "qux_" + B.upper().replace("0X", "0x")])
    assert RecordingDownloader.CALLS == [[A], [B], [B]], "only the three well-formed entries were looked up, lower-cased"
    assert all(ADDRESS.match(x) for call in RecordingDownloader.CALLS for x in call)


def test_source_code_as_a_single_object_is_still_supported(monkeypatch):
    a, out = info(monkeypatch, f'{{"source_code": {{"function_name": "foo", "address": "{A}"}}}}')
    assert list(out["source_code"]) == [f"foo_{A}"] and RecordingDownloader.CALLS == [[A]]
    assert out["source_code"][f"foo_{A}"].endswith("for other functions")


@pytest.mark.parametrize("bad", ["0", "5", "", " ", "0x", "0x123", "0x" + "g" * 40, "0x" + "a" * 39, "0x" + "a" * 41,
                                 "aa" * 20, None, 5, ["0x" + "aa" * 20], {"a": 1}])
def test_invalid_addresses_never_reach_the_downloader(monkeypatch, bad):
    a = make_analyzer(monkeypatch, "{}")
    assert a._retrieve_source_code(bad, "foo") == []
    assert RecordingDownloader.CALLS == []
    a2, out = info(monkeypatch, __import__("json").dumps({"source_code": [{"function": "foo", "address": bad}, [bad, "foo"]]}))
    assert out == {} and RecordingDownloader.CALLS == []


def test_a_valid_address_is_looked_up_once_lower_cased(monkeypatch):
    a = make_analyzer(monkeypatch, "{}")
    a._retrieve_source_code(A.upper().replace("0X", "0x"), "foo")
    assert RecordingDownloader.CALLS == [[A]]


def test_other_sections_skip_malformed_entries_instead_of_crashing(monkeypatch):
    import json
    reply = json.dumps({"function_call": [["notalist"], "x", 7, {"function": "foo", "address": A}],
                        "children_calls": ["x", ["foo", A], 7, {"function": 1, "address": A}],
                        "balance_change": [A, 5, None, ["nested"]]})
    a, out = info(monkeypatch, reply)
    assert isinstance(out, dict)                               # no crash; whatever is valid is used
    for text in ('{"function_call": "foo", "children_calls": "foo", "source_code": "foo", "balance_change": 7}',
                 '{"function_call": 5, "children_calls": {"a": 1}, "source_code": {"x": 1}, "balance_change": {"a": 1}}'):
        assert info(monkeypatch, text)[1] == {}


def test_children_calls_accept_both_pair_orders(monkeypatch):
    a = make_analyzer(monkeypatch, '{"children_calls": [["foo", "' + A + '"], ["' + B + '", "bar"]]}')
    out = a._retrieve_additional_info("x")
    assert sorted(out["children_calls (i.e., for {k:v}, v is the children calls of k)"]) == sorted([f"foo::{A}", f"bar::{B}"])


@pytest.mark.parametrize("reply", ['["source_code"]', "Sure! here it is", "An error occurred.", "", "42"])
def test_a_whole_additional_info_reply_of_the_wrong_shape_is_an_error_not_an_empty_success(monkeypatch, reply):
    a = make_analyzer(monkeypatch, reply)
    with pytest.raises(ModelResponseError):
        a._retrieve_additional_info("x")


# ------------------------------------------------------------------------------------------ narrowing / findings consumers

@pytest.mark.parametrize("reply", ["An error occurred.", "some prose", "[]", "[1, 2, 3]", '{"a": 1', "42"])
def test_an_unusable_narrowing_reply_is_ignored_and_never_iterated_as_a_list(monkeypatch, reply):
    a = make_analyzer(monkeypatch, reply)
    assert a._narrowing_reply("p", 9) is None


def test_a_usable_narrowing_reply_narrows(monkeypatch):
    assert make_analyzer(monkeypatch, '["foo_a", "bar_b"]')._narrowing_reply("p", 9) == ["foo_a", "bar_b"]
    assert make_analyzer(monkeypatch, '{"foo_a": 1, "bar_b": 2}')._narrowing_reply("p", 9) == ["foo_a", "bar_b"]


def test_review_keeps_every_candidate_when_narrowing_replies_are_garbage(monkeypatch):
    from tests.test_function_analysis_state import analyzer, entry
    keys = {f"f{i}_{A}": entry() for i in range(7)}
    a = analyzer(inspected=keys)
    a.agent = a.generation_agent = ScriptAgent("An error occurred.")
    a.function_prompts = SimpleNamespace(narrow_down_functions="{function_call_to_be_inspected}|{balance_change}",
                                         narrow_down_functions_with_created_contracts="{function_call_to_be_inspected}")
    a._review_function_calls()
    assert len(a.analyzed) == 7, "a garbled narrowing answer must not drop (or garble) candidates"


def test_update_potentially_vulnerable_function_rejects_text_and_accepts_an_empty_list_or_object(monkeypatch):
    a = make_analyzer(monkeypatch, "{}")
    a.vulnerability_prompts = SimpleNamespace(update_potentially_vulnerable_function="p")
    a.cheatsheet, a.processing_result, a.current_task, a.potentially_vulnerable_functions = "", "", {}, {}
    for good in ("{}", "[]", '{"foo_0xa": ["evidence", 0.9]}'):
        a.organization_agent = ScriptAgent(good)
        a._update_potentially_vulnerable_function()
    assert "foo_0xa" in a.potentially_vulnerable_functions
    for bad in ("An error occurred.", "no findings", '["foo_0xa"]'):
        a.organization_agent = ScriptAgent(bad)
        with pytest.raises(ModelResponseError):
            a._update_potentially_vulnerable_function()


# ------------------------------------------------------------------------------------------ real candidate / pipeline path

def pipeline(tmp_path, monkeypatch, scenario):
    state = fakes.install(scenario, monkeypatch.setattr)
    monkeypatch.setenv("OPENAI_API_KEY", USER_KEY)
    return FaultSeekerPipeline(FaultSeekerConfig(cache_dir=str(tmp_path / "cache"))), state


def analyze(p):
    return p.analyze_transaction(txn_hash=HASH, chain="bsc")


def no_secrets(text):
    for secret in fakes.DECOYS + [USER_KEY]:
        assert secret not in text


@pytest.mark.parametrize("scenario,queries,reason", [
    (
        "tasklist", 8,
        "Four malformed top-level replies per attempt, across two real candidate attempts.",
    ),
    (
        "taskstring", 8,
        "Four unparseable replies per attempt; query_json_once makes one request per selection attempt.",
    ),
    (
        "taskmissing", 8,
        "Four objects missing required task_description per attempt; validation consumes one selection attempt each.",
    ),
    (
        "tasktype", 8,
        "Four objects with the wrong task_description type per attempt; validation consumes one selection attempt each.",
    ),
])
def test_unusable_task_output_fails_the_candidate_through_the_existing_path(
    tmp_path, monkeypatch, scenario, queries, reason
):
    p, state = pipeline(tmp_path, monkeypatch, scenario)

    with pytest.raises(RuntimeError) as err:
        analyze(p)

    message = str(err.value)
    assert "Stage 2 (Function Analysis) incomplete" in message
    assert f"foo@{fakes.A}" in message
    assert "CandidateIncomplete" in message
    assert "TypeError" not in message
    no_secrets(message)

    assert state.task_queries == queries, reason
    a = p.function_analyzer
    assert a.examined_function_memo == []
    assert list(a.unresolved_failures) == [f"foo@{fakes.A}"]
    assert a.failed_function_memo[f"foo@{fakes.A}"] == 2
    assert state.processing_prompts == [], (
        "no valid task was selected, so nothing reached the processing step"
    )


def test_a_provider_outage_at_task_selection_fails_the_candidate_at_once_with_its_real_type(
    tmp_path, monkeypatch
):
    p, state = pipeline(tmp_path, monkeypatch, "taskoutage")

    with pytest.raises(RuntimeError) as err:
        analyze(p)

    assert "ProviderFailure" in str(err.value)
    assert "provider call failed" in str(err.value)
    assert state.task_queries == 1
    assert p.function_analyzer.examined_function_memo == []
    assert p.function_analyzer.failed_function_memo[f"foo@{fakes.A}"] == 1
    no_secrets(str(err.value))


def test_task_output_that_becomes_valid_after_reformat_requests_completes(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "taskretryok")
    assert analyze(p)["transaction_hash"] == HASH
    assert state.task_queries >= 3 and p.function_analyzer.unresolved_failures == {}


def test_list_of_strings_source_code_cannot_reach_the_downloader_and_the_run_completes(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "srcstrings")
    analyze(p)
    addresses = [x for _, call in fakes.FakeDownloader.CALLS for x in call]
    assert addresses and all(ADDRESS.match(x) for x in addresses), addresses
    assert "0" not in addresses and "5" not in addresses


def test_mixed_valid_and_invalid_additional_info_entries_use_only_the_valid_ones(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "srcmixed")
    analyze(p)
    lookups = [call for _, call in fakes.FakeDownloader.CALLS[1:]]          # [0] is the analyzer's own start-up download
    assert lookups and all(len(c) == 1 and ADDRESS.match(c[0]) for c in lookups), lookups
    assert {c[0] for c in lookups} <= {A, B}
    seen = "\n".join(state.processing_prompts)
    for expected in (f"foo_{A}", f"bar_{B}"):
        assert expected in seen
    for rejected in ("baz_0", "garbage", "0x1234"):
        assert rejected not in seen


@pytest.mark.parametrize("scenario", ["infolist", "infotext"])
def test_a_wrong_shaped_additional_info_reply_never_completes_the_candidate(tmp_path, monkeypatch, scenario):
    import faultseeker.utils.agent as agent_module
    monkeypatch.setattr(agent_module, "CONTENT_RETRY_DELAYS", (0, 0))     # fast e2e: delays only, counts unchanged
    p, state = pipeline(tmp_path, monkeypatch, scenario)
    with pytest.raises(RuntimeError) as err:
        analyze(p)
    assert "Stage 2 (Function Analysis) incomplete" in str(err.value) and f"foo@{fakes.A}" in str(err.value)
    no_secrets(str(err.value))
    assert p.function_analyzer.examined_function_memo == []


# ------------------------------------------------------------------------------------------ defect 3: attempt isolation / retry propagation


def _prepare_candidate_runner(a):
    """Supply the complete mutable state and history fields used by _run_candidate."""
    a.task_tree = "baseline task tree"
    a.function_call_info_summary = {
        "function": "foo",
        "calls": [],
        "high_appreance_count_children_calls": {},
    }
    a.current_task = "baseline current task"
    a.processing_result = "baseline processing result"
    a.understanding_result = "baseline understanding"
    a.potentially_vulnerable_functions = {}
    a.children_call_memo_single = {}
    a.children_call_memo = {}
    a.repeated_patterns = []

    a.examined_function_memo = []
    a.failed_function_memo = {}
    a.attempted_function_memo = []
    a.unresolved_failures = {}


def test_candidate_retry_starts_from_clean_state_and_retains_history(monkeypatch):
    from faultseeker.function_analysis.function_analyzer import CandidateIncomplete

    a = make_analyzer(monkeypatch, GOOD_TASK)
    _prepare_candidate_runner(a)
    identity = f"foo@{fakes.A}"

    a.attempted_function_memo.append("prior-attempt")
    a.failed_function_memo["prior-failure"] = 1
    a.unresolved_failures["prior-failure"] = "prior unresolved detail"

    calls = []

    def attempt():
        calls.append({
            "task_tree": a.task_tree,
            "function_call_info_summary": a.function_call_info_summary.copy(),
            "current_task": a.current_task,
            "processing_result": a.processing_result,
            "understanding_result": a.understanding_result,
            "potentially_vulnerable_functions": a.potentially_vulnerable_functions.copy(),
            "children_call_memo_single": a.children_call_memo_single.copy(),
            "children_call_memo": a.children_call_memo.copy(),
            "repeated_patterns": list(a.repeated_patterns),
        })

        assert a.attempted_function_memo == ["prior-attempt", identity]
        assert a.failed_function_memo == {"prior-failure": 1}
        assert a.unresolved_failures == {
            "prior-failure": "prior unresolved detail"
        }

        if len(calls) == 1:
            a.potentially_vulnerable_functions["partial"] = {"finding": "must not leak"}
            a.task_tree = "partial task tree"
            a.processing_result = "partial processing result"
            a.children_call_memo["partial"] = ["partial"]
            raise CandidateIncomplete("retry this candidate", retryable=True)

        assert a.potentially_vulnerable_functions == {}
        assert a.task_tree == "baseline task tree"
        assert a.processing_result == "baseline processing result"
        assert a.children_call_memo == {}
        a.potentially_vulnerable_functions["complete"] = {"finding": "valid"}
        a.task_tree = "successful task tree"

    a._function_analysis_init = attempt

    assert a._run_candidate([identity], "foo") is None
    assert len(calls) == 2

    # Both attempts began from the original baseline.
    assert calls[0]["task_tree"] == calls[1]["task_tree"] == "baseline task tree"
    assert calls[0]["processing_result"] == calls[1]["processing_result"] == "baseline processing result"
    assert calls[0]["potentially_vulnerable_functions"] == calls[1]["potentially_vulnerable_functions"] == {}
    assert calls[0]["children_call_memo"] == calls[1]["children_call_memo"] == {}

    # The successful attempt is retained; history is preserved and updated.
    assert a.task_tree == "successful task tree"
    assert a.potentially_vulnerable_functions == {"complete": {"finding": "valid"}}
    assert a.examined_function_memo == [identity]
    assert a.attempted_function_memo == ["prior-attempt", identity]
    assert a.failed_function_memo == {"prior-failure": 1}
    assert a.unresolved_failures == {"prior-failure": "prior unresolved detail"}


def test_total_candidate_failure_restores_baseline_and_records_both_attempts(monkeypatch):
    from faultseeker.function_analysis.function_analyzer import CandidateIncomplete

    a = make_analyzer(monkeypatch, GOOD_TASK)
    _prepare_candidate_runner(a)
    identity = f"foo@{fakes.A}"
    baseline = a._capture_candidate_attempt_state()
    calls = []

    def attempt():
        calls.append(True)
        a.potentially_vulnerable_functions[f"partial-{len(calls)}"] = {
            "finding": "must not leak"
        }
        a.task_tree = f"partial task tree {len(calls)}"
        a.processing_result = f"partial processing result {len(calls)}"
        raise CandidateIncomplete("still incomplete", retryable=True)

    a._function_analysis_init = attempt

    detail = a._run_candidate([identity], "foo")

    assert len(calls) == 2
    assert a._capture_candidate_attempt_state() == baseline
    assert a.potentially_vulnerable_functions == {}
    assert a.failed_function_memo == {identity: 2}
    assert a.unresolved_failures == {identity: detail}
    assert a.attempted_function_memo == [identity]
    assert a.examined_function_memo == []


def _configure_real_step_loop(a, monkeypatch, select_task):
    """Configure the production _function_analysis_init loop with deterministic step methods."""
    a.function_prompts = SimpleNamespace(
        function_analysis_init_prompt="initial prompt",
        check_analysis_adequacy="adequacy prompt",
    )
    a.reasoning_agent = ScriptAgent("initial task tree")
    a.organization_agent = ScriptAgent("no")
    a._temp_check = lambda: False
    a._update_current_understanding = lambda **kwargs: None
    a._select_task = select_task
    a._perform_task = lambda: None
    a._update_task_tree = lambda: None
    a._update_potentially_vulnerable_function = lambda: None


def test_selection_exhaustion_remains_retryable_through_the_real_step_loop(monkeypatch):
    from faultseeker.function_analysis.function_analyzer import CandidateIncomplete

    a = make_analyzer(monkeypatch, GOOD_TASK)

    def exhausted():
        raise CandidateIncomplete("selection attempts exhausted", retryable=True)

    _configure_real_step_loop(a, monkeypatch, exhausted)

    with pytest.raises(CandidateIncomplete) as err:
        a._function_analysis_init()

    assert err.value.retryable is True
    assert "CandidateIncomplete" in str(err.value)
    assert "selection attempts exhausted" in str(err.value)


def test_plain_iteration_limit_is_not_retryable_through_the_real_step_loop(monkeypatch):
    from faultseeker.function_analysis.function_analyzer import CandidateIncomplete

    a = make_analyzer(monkeypatch, GOOD_TASK)
    _configure_real_step_loop(a, monkeypatch, lambda: None)

    with pytest.raises(CandidateIncomplete) as err:
        a._function_analysis_init()

    assert err.value.retryable is False
    assert "iteration limit (31) reached" in str(err.value)


def test_provider_failure_at_selection_is_terminal_and_not_retried(monkeypatch):
    from faultseeker.function_analysis.function_analyzer import CandidateIncomplete
    from faultseeker.utils.agent import ProviderFailure

    a = make_analyzer(monkeypatch, GOOD_TASK)
    _prepare_candidate_runner(a)
    calls = []

    def provider_failure():
        calls.append(True)
        raise ProviderFailure("call_failed", "provider call failed")

    _configure_real_step_loop(a, monkeypatch, provider_failure)

    identity = f"foo@{fakes.A}"
    a._run_candidate([identity], "foo")

    assert len(calls) == 1
    assert a.failed_function_memo == {identity: 1}
    assert identity in a.unresolved_failures
    assert "CandidateIncomplete" in a.unresolved_failures[identity]
    assert "ProviderFailure" in a.unresolved_failures[identity]
    assert a.examined_function_memo == []


def test_null_content_through_chat_strict_aborts_selection_after_one_provider_call(monkeypatch):
    from faultseeker.utils.agent import ProviderFailure

    class ChatStrictNullAgent(AbstractAgent):
        """Test agent whose strict provider path is the production _chat_strict implementation."""

        def __init__(self):
            super().__init__("", "chat-strict-null-test")
            self.provider_calls = 0

        def _send_message(self, user_message, temperature=0):
            raise AssertionError("_send_message must not bypass the _chat_strict path")

        def _send_message_strict(self, user_message, temperature=0):
            return self._chat_strict(user_message, self._return_null)

        def _return_null(self):
            self.provider_calls += 1
            return None

    a = make_analyzer(monkeypatch, GOOD_TASK)
    agent = ChatStrictNullAgent()
    a.generation_agent = a.agent = agent

    with pytest.raises(ProviderFailure) as err:
        a._select_task()

    assert err.value.kind == "null_content"
    assert agent.provider_calls == 1
    assert agent.memory[-1] == {"role": "assistant", "content": ""}


# ------------------------------------------------------------------------------------------ real worker / API


def run_scenario(make_client, scenario):
    c = make_client(FAULTSEEKER_WORKER_MODULE="tests.pipeline_fake_worker")
    run_id = start_run(c, txn_hash="0x" + fakes.HASH_PREFIX[scenario] + "0" * 60)
    return c, run_id, wait_final(c, run_id, 90)["run"]


def exposed(c, run_id):
    from faultseeker.server import settings
    texts = [c.get(f"/api/runs/{run_id}").text, c.get("/api/runs").text, c.get(f"/api/runs/{run_id}/result").text]
    texts += [p.read_text(errors="replace") for p in (settings.RUNS_DIR / run_id).rglob("*") if p.is_file()]
    return "\n".join(texts)


@pytest.mark.parametrize("scenario", ["tasklist", "taskstring", "taskmissing", "tasktype", "taskoutage", "infolist", "infotext"])   # taskoutage: provider failure
def test_api_malformed_model_output_ends_failed_with_analysis_incomplete_and_no_result(
    make_client, monkeypatch, scenario
):
    # These worker/API scenarios may exercise ordinary query_json content retries.
    # Zeroing the delays keeps the end-to-end test fast without changing retry counts.
    import faultseeker.utils.agent as agent_module
    monkeypatch.setattr(agent_module, "CONTENT_RETRY_DELAYS", (0, 0))

    c, run_id, run = run_scenario(make_client, scenario)
    assert run["state"] == "failed", run
    assert run["error"]["code"] == "analysis_incomplete" and f"foo@{fakes.A}" in run["error"]["message"]
    assert "provider key, quota and availability" in run["error"]["hint"]
    assert c.get(f"/api/runs/{run_id}/result").status_code in (404, 409)
    from faultseeker.server import settings
    assert not (settings.RUNS_DIR / run_id / "result.json").exists()
    no_secrets(exposed(c, run_id))


@pytest.mark.parametrize("scenario", ["taskretryok", "srcstrings", "srcmixed"])
def test_api_recoverable_or_skippable_malformed_output_still_completes(
    make_client, monkeypatch, scenario
):
    # These worker/API scenarios may exercise ordinary query_json content retries.
    # Zeroing the delays keeps the end-to-end test fast without changing retry counts.
    import faultseeker.utils.agent as agent_module
    monkeypatch.setattr(agent_module, "CONTENT_RETRY_DELAYS", (0, 0))

    c, run_id, run = run_scenario(make_client, scenario)
    assert run["state"] == "completed", run
    assert c.get(f"/api/runs/{run_id}/result").status_code == 200
    no_secrets(exposed(c, run_id))
