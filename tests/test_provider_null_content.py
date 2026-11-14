"""Provider null-content (HTTP 200, message.content = null) is a provider failure, never a model answer. OFFLINE tests.

Provenance: a live BSC run crashed with `AttributeError: 'NoneType' object has no attribute 'lower'` at the Stage 2 adequacy
check after 3 completed steps, because Mercury returned content=null, GPTAgent passed it on verbatim and the retry only covered
raised errors. These tests reproduce the mechanism with a fake OpenAI-style client (the REAL GPTAgent on top) and fake model
replies; they are regression tests for that mechanism, not proof about any live provider.

Contract: null / empty / non-text content is re-asked (bounded: 1 + len(CONTENT_RETRY_DELAYS) calls) and then raised as the
typed ProviderFailure (kind + bounded reason). It is never returned, never stored in the agent memory, never read as
"yes" or as "not adequate", and a candidate that meets it stops as a provider failure instead of burning the iteration cap.
"""
import inspect
import pathlib
from types import SimpleNamespace

import pytest

try:
    from faultseeker.core.config import FaultSeekerConfig
    from faultseeker.core.pipeline import FaultSeekerPipeline
    import faultseeker.function_analysis.function_analyzer as fa
    import faultseeker.utils.agent as agent_module
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    from faultseeker.utils.agent import (AbstractAgent, GPTAgent, ModelResponseError, OllmaAgent, PROVIDER_ERROR_TEXT,
                                         ProviderFailure)
    from tests import pipeline_fakes as fakes
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

from tests.conftest import USER_KEY, start_run, wait_final

ID_FOO = f"foo@{fakes.A}"
HASH = "0x" + "c3c3" + "0" * 60


# ------------------------------------------------------------------------------------------ the real agents, fake clients

class FakeClient:
    """Scripted completions: each item is a content value (str / None / list ...) or an Exception to raise."""

    def __init__(self, script):
        self.script, self.calls = list(script), []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, messages, model=None, **kw):
        self.calls.append([dict(m) for m in messages])
        item = self.script[min(len(self.calls) - 1, len(self.script) - 1)]
        if isinstance(item, Exception):
            raise item
        if item == "NO_CHOICES":
            return SimpleNamespace(choices=[])
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=item))])


def gpt(monkeypatch, *script):
    monkeypatch.setattr(agent_module, "CONTENT_RETRY_DELAYS", (0, 0))
    a = object.__new__(GPTAgent)
    AbstractAgent.__init__(a, "system", "fake-model")
    a.resolved = SimpleNamespace(extra_params={}, temperature_mode="omit", temperature_value=0)
    a._client = FakeClient(script)
    return a


def memory_is_text_only(agent):
    return all(isinstance(m["content"], str) for m in agent.memory)


def test_null_content_is_re_asked_and_the_good_answer_is_returned(monkeypatch):
    a = gpt(monkeypatch, None, "yes it is adequate")
    assert a.query_text("q") == "yes it is adequate"
    assert len(a._client.calls) == 2 and memory_is_text_only(a)
    assert [m["role"] for m in a.memory] == ["system", "user", "assistant"], "one user turn, not one per re-ask"


def test_null_content_that_never_recovers_raises_a_typed_bounded_failure(monkeypatch):
    a = gpt(monkeypatch, None)
    with pytest.raises(ProviderFailure) as err:
        a.query_text("q")
    assert err.value.kind == "null_content" and "null content" in str(err.value)
    assert isinstance(err.value, ModelResponseError)
    assert len(a._client.calls) == 3, "1 call + 2 re-asks, then stop"
    assert memory_is_text_only(a), "None must never enter the conversation memory"


@pytest.mark.parametrize("content,kind", [(None, "null_content"), ("", "empty_content"), ("   \n", "empty_content"),
                                          (123, "non_text_content"), (["a"], "non_text_content"), ("NO_CHOICES", "null_content"),
                                          (PROVIDER_ERROR_TEXT, "call_failed")])
def test_every_unusable_content_shape_is_a_provider_failure(monkeypatch, content, kind):
    a = gpt(monkeypatch, content)
    with pytest.raises(ProviderFailure) as err:
        a.query_text("q")
    assert err.value.kind == kind and memory_is_text_only(a)


def test_a_raised_provider_error_is_a_typed_failure_without_quoting_the_error(monkeypatch):
    a = gpt(monkeypatch, RuntimeError(f"401 bad key {fakes.LEAKY}"))
    with pytest.raises(ProviderFailure) as err:
        a.query_text("q")
    assert err.value.kind == "call_failed" and fakes.LEAKY not in str(err.value)
    assert len(a._client.calls) == 1, "raised errors keep the client's own retry policy; no extra agent-level retry"
    assert memory_is_text_only(a)


def test_the_conversation_re_sent_after_a_failed_turn_contains_no_null(monkeypatch):
    a = gpt(monkeypatch, None, None, None, "fine")
    with pytest.raises(ProviderFailure):
        a.query_text("first")
    assert a.query_text("second") == "fine"
    assert all(isinstance(m["content"], str) for call in a._client.calls for m in call)


def test_json_queries_get_the_same_protection(monkeypatch):
    a = gpt(monkeypatch, None, '{"a": 1}')
    assert a.query_json("q", expect=dict) == {"a": 1}
    b = gpt(monkeypatch, None)
    with pytest.raises(ProviderFailure):
        b.query_json("q", expect=dict)


def test_the_legacy_text_query_never_returns_none(monkeypatch):
    """guard: the legacy contract keeps its error sentinel (existing provider tests rely on it), but never None."""
    assert gpt(monkeypatch, None).query("q", format="str") == PROVIDER_ERROR_TEXT
    assert gpt(monkeypatch, None, "ok").query("q", format="str") == "ok"
    assert gpt(monkeypatch, None).query("q", format="json") in (PROVIDER_ERROR_TEXT, [PROVIDER_ERROR_TEXT])


def test_the_default_waits_between_re_asks_are_applied(monkeypatch):
    waits = []
    a = gpt(monkeypatch, None)
    monkeypatch.setattr(agent_module, "CONTENT_RETRY_DELAYS", (1.0, 3.0))
    monkeypatch.setattr(agent_module, "sleep", waits.append)
    with pytest.raises(ProviderFailure):
        a.query_text("q")
    assert waits == [1.0, 3.0]


def test_ollama_null_content_is_handled_the_same_way(monkeypatch):
    monkeypatch.setattr(agent_module, "CONTENT_RETRY_DELAYS", (0, 0))
    replies = [{"message": {"content": None}}, {"message": {"content": "hello"}}]
    calls = []

    def chat(model, messages, options):
        calls.append(1)
        return replies[min(len(calls) - 1, 1)]
    a = object.__new__(OllmaAgent)
    AbstractAgent.__init__(a, "system", "m")
    a._client = SimpleNamespace(chat=chat)
    assert a.query_text("q") == "hello" and memory_is_text_only(a)
    b = object.__new__(OllmaAgent)
    AbstractAgent.__init__(b, "system", "m")
    b._client = SimpleNamespace(chat=lambda model, messages, options: {"message": {"content": None}})
    with pytest.raises(ProviderFailure):
        b.query_text("q")
    assert memory_is_text_only(b)


# ------------------------------------------------------------------------------------------ the eight call sites

class NullAgent(AbstractAgent):
    def __init__(self):
        super().__init__("", "null")
        self.requests = 0

    def _send_message(self, user_message, temperature=0):
        self.requests += 1
        return None


def bare_analyzer():
    a = object.__new__(FunctionAnalyzer)
    a.task_prompts = SimpleNamespace(update_task_tree="{task_tree}|{current_understanding}|{task_completed}")
    a.function_prompts = SimpleNamespace(function_call_organization_function_call="{function_call_info_summary}",
                                         function_call_info_processing="{selected_task}")
    a.reasoning_agent = a.organization_agent = a.processing_agent = NullAgent()
    a.task_tree, a.understanding_result, a.processing_result = "TREE", "UNDERSTANDING", "PROCESSING"
    a.function_call_info_summary, a.current_task = {}, {"task_description": "t", "additional_information": ""}
    a._retrieve_additional_info = lambda info: {}
    return a


@pytest.mark.parametrize("call,attribute,before", [
    (lambda a: a._perform_task(), "processing_result", "PROCESSING"),
    (lambda a: a._update_task_tree(), "task_tree", "TREE"),
    (lambda a: a._update_current_understanding(), "understanding_result", "UNDERSTANDING"),
    (lambda a: a._update_current_understanding(is_init=True), "understanding_result", "UNDERSTANDING"),
])
def test_text_steps_raise_provider_failure_and_never_store_none(call, attribute, before):
    a = bare_analyzer()
    with pytest.raises(ProviderFailure):
        call(a)
    assert getattr(a, attribute) == before, "the previous value stays; None is never assigned"


def test_no_legacy_text_query_is_left_in_stage_2():
    """Class sweep: every text reply goes through query_text (non-empty text or ProviderFailure)."""
    source = pathlib.Path(inspect.getsourcefile(fa)).read_text()
    assert "format='str'" not in source and 'format="str"' not in source


# ------------------------------------------------------------------------------------------ real candidate / pipeline path

def pipeline(tmp_path, monkeypatch, scenario):
    state = fakes.install(scenario, monkeypatch.setattr)
    monkeypatch.setenv("OPENAI_API_KEY", USER_KEY)
    return FaultSeekerPipeline(FaultSeekerConfig(cache_dir=str(tmp_path / "cache"))), state


def analyze(p):
    return p.analyze_transaction(txn_hash=HASH, chain="bsc")


def test_null_at_the_adequacy_check_stops_the_candidate_as_a_provider_failure(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "nullcheckforever")
    with pytest.raises(RuntimeError) as err:
        analyze(p)
    message = str(err.value)
    assert "Stage 2 (Function Analysis) incomplete" in message and ID_FOO in message
    assert "provider failure" in message and "null content" in message
    assert "iteration limit" not in message, "a provider failure must not be reported as an exhausted iteration cap"
    detail = p.function_analyzer.unresolved_failures[ID_FOO]
    assert "after 3 completed step(s)" in detail and "ProviderFailure" in detail
    assert state.adequacy_calls == 3, "asked once, re-asked twice (bounded), then stopped"
    assert p.function_analyzer.examined_function_memo == [], "never a completed candidate"
    assert isinstance(p.function_analyzer.understanding_result, str)


def test_the_provider_failure_stop_does_not_burn_the_iteration_cap(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "nullcheckforever")
    with pytest.raises(RuntimeError):
        analyze(p)
    assert state.attempts["foo"] == 1 and state.adequacy_calls == 3, "one candidate attempt, the check asked 3 times, then stop"


def test_a_null_that_recovers_on_the_reask_lets_the_candidate_complete(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "nullcheckonce")
    assert analyze(p)["transaction_hash"] == HASH
    assert state.adequacy_calls == 2 and p.function_analyzer.unresolved_failures == {}
    assert ID_FOO in p.function_analyzer.examined_function_memo


def test_null_understanding_fails_the_candidate_and_never_stores_none(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "nullunderstand")
    with pytest.raises(RuntimeError) as err:
        analyze(p)
    assert "ProviderFailure" in str(err.value) and "null content" in str(err.value)
    assert isinstance(p.function_analyzer.understanding_result, str)


# ------------------------------------------------------------------------------------------ real worker / API

def run_scenario(make_client, scenario):
    c = make_client(FAULTSEEKER_WORKER_MODULE="tests.pipeline_fake_worker")
    run_id = start_run(c, txn_hash="0x" + fakes.HASH_PREFIX[scenario] + "0" * 60)
    return c, run_id, wait_final(c, run_id, 90)["run"]


def test_api_null_content_outage_ends_failed_with_the_real_reason_and_no_result(make_client):
    c, run_id, run = run_scenario(make_client, "nullcheckforever")
    assert run["state"] == "failed", run
    err = run["error"]
    assert err["code"] == "analysis_incomplete" and ID_FOO in err["message"]
    assert "provider failure" in err["message"] and "null content" in err["message"] and "iteration limit" not in err["message"]
    assert c.get(f"/api/runs/{run_id}/result").status_code in (404, 409)


def test_api_null_content_that_recovers_completes(make_client):
    c, run_id, run = run_scenario(make_client, "nullcheckonce")
    assert run["state"] == "completed", run
    assert c.get(f"/api/runs/{run_id}/result").status_code == 200


def test_query_json_composed_retries_exhausted_on_unparseable_content(monkeypatch):
    a = gpt(
        monkeypatch,
        None, None, "not json",
        None, None, "still not json",
        None, None, "never json",
    )

    with pytest.raises(ModelResponseError):
        a.query_json("return structured data")

    assert len(a._client.calls) == 9
    assert all(
        isinstance(message["content"], str)
        for call in a._client.calls
        for message in call
        if message["role"] in ("user", "assistant")
    )
    assert all(
        isinstance(message["content"], str)
        for message in a.memory
        if message["role"] in ("user", "assistant")
    )
    assert not any(
        not isinstance(message["content"], str)
        for message in a.memory
    )


def test_query_json_null_content_failure_is_terminal_across_outer_reasks(monkeypatch):
    a = gpt(monkeypatch, "not json", "nope", None)

    with pytest.raises(ProviderFailure) as exc_info:
        a.query_json("return structured data")

    assert exc_info.value.kind == "null_content"
    assert len(a._client.calls) == 5
    assert all(
        isinstance(message["content"], str)
        for call in a._client.calls
        for message in call
        if message["role"] in ("user", "assistant")
    )
    assert all(
        isinstance(message["content"], str)
        for message in a.memory
        if message["role"] in ("user", "assistant")
    )
    assert not any(
        not isinstance(message["content"], str)
        for message in a.memory
    )
