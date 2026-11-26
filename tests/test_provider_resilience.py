"""Provider resilience (live-test findings): transient retry with backoff, wall-clock budgets, and honest failure detail. OFFLINE:
fake transports, a fake clock, no provider or RPC request."""
import json
from types import SimpleNamespace

import httpx
import openai
import pytest

try:
    import faultseeker.utils.agent as agent_module
    from faultseeker.function_analysis.function_analyzer import CandidateIncomplete, FunctionAnalyzer
    from faultseeker.providers import load_registry
    from faultseeker.utils.agent import GPTAgent, ProviderFailure, deadline, describe_provider_exception, remaining_seconds
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

REQ = httpx.Request("POST", "https://proxy.example/v1/chat/completions")


def status_error(code, body="upstream said no"):
    response = httpx.Response(code, request=REQ, text=body)
    cls = {400: openai.BadRequestError, 401: openai.AuthenticationError, 404: openai.NotFoundError, 429: openai.RateLimitError,
           422: openai.UnprocessableEntityError}.get(code, openai.InternalServerError)
    return cls(f"Error code: {code}", response=response, body=None)


class Clock:
    """A fake monotonic clock; sleep() advances it and records the pause."""

    def __init__(self):
        self.now, self.sleeps = 1000.0, []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class Transport:
    """Fake OpenAI-style transport: each script item is an exception to raise or a content value to return."""

    def __init__(self, *script, clock=None):
        self.script, self.calls, self.kwargs, self.clock = list(script), 0, [], clock
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, messages, model=None, **kw):
        self.kwargs.append(kw)
        item = self.script[min(self.calls, len(self.script) - 1)]
        self.calls += 1
        if self.clock:
            self.clock.now += 1.0                                   # each request takes a second
        if isinstance(item, BaseException):
            raise item
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=item))])


@pytest.fixture()
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(agent_module, "monotonic", c.monotonic)
    monkeypatch.setattr(agent_module, "sleep", c.sleep)
    monkeypatch.setattr(agent_module, "TRANSIENT_RETRY_DELAYS", (2.0, 6.0, 15.0))
    monkeypatch.setattr(agent_module, "CONTENT_RETRY_DELAYS", (1.0, 3.0, 8.0))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-" + "x" * 30)
    return c


def agent(clock, *script):
    a = GPTAgent("sys", load_registry().resolve("gpt-4o-mini"))
    a._client = Transport(*script, clock=clock)
    return a


# ------------------------------------------------------------------------------------------------ transient errors

@pytest.mark.parametrize("error", [openai.APITimeoutError(request=REQ), openai.APIConnectionError(request=REQ), status_error(503),
                                   status_error(500), status_error(429), httpx.ReadTimeout("The read operation timed out")])
def test_transient_errors_are_retried_with_backoff_then_succeed(clock, error):
    a = agent(clock, error, error, "ok")
    assert a.query_text("hi") == "ok"
    assert a._client.calls == 3 and clock.sleeps == [2.0, 6.0]


@pytest.mark.parametrize("code", [400, 401, 404, 422])
def test_permanent_http_errors_are_never_retried_and_name_their_status(clock, capsys, code):
    a = agent(clock, status_error(code), "ok")
    with pytest.raises(ProviderFailure) as err:
        a.query_text("hi")
    assert a._client.calls == 1 and clock.sleeps == []
    assert err.value.kind == "call_failed" and f"HTTP {code}" in str(err.value)
    assert str(err.value).startswith("the provider call failed (")


def test_exhausted_transient_retries_end_as_a_named_provider_failure(clock, capsys):
    a = agent(clock, openai.APITimeoutError(request=REQ))
    with pytest.raises(ProviderFailure) as err:
        a.query_text("hi")
    assert a._client.calls == 4 and clock.sleeps == [2.0, 6.0, 15.0], "1 request + 3 retries, no more"
    assert "APITimeoutError" in str(err.value)
    out = capsys.readouterr().out
    assert "retrying the provider request in 2s (1/3)" in out and "Provider call failed: APITimeoutError" in out


def test_the_technical_log_names_the_class_status_and_a_body_prefix(clock, capsys):
    a = agent(clock, status_error(503, "upstream   unavailable\n" + "x" * 500))
    with pytest.raises(ProviderFailure):
        a.query_text("hi")
    out = capsys.readouterr().out
    assert "Provider call failed: InternalServerError HTTP 503 body='upstream unavailable xxx" in out
    lines = [l for l in out.splitlines() if l.startswith("Provider call failed")]
    assert lines and all(len(l) < 300 for l in lines), "the body prefix is bounded"


def test_single_request_operations_are_never_retried_here(clock):
    a = agent(clock, openai.APITimeoutError(request=REQ), "{}")
    with pytest.raises(ProviderFailure):
        a.query_json_once("hi")
    assert a._client.calls == 1 and clock.sleeps == []


def test_null_content_now_gets_three_backed_off_retries(clock):
    a = agent(clock, None, None, None, "late")
    assert a.query_text("hi") == "late"
    assert a._client.calls == 4 and clock.sleeps == [1.0, 3.0, 8.0]
    b = agent(clock, None)
    with pytest.raises(ProviderFailure) as err:
        b.query_text("hi")
    assert err.value.kind == "null_content" and b._client.calls == 4


def test_transient_and_content_retries_are_counted_separately(clock):
    a = agent(clock, openai.APITimeoutError(request=REQ), None, openai.APITimeoutError(request=REQ), "fine")
    assert a.query_text("hi") == "fine" and a._client.calls == 4


def test_the_exception_classifier():
    assert describe_provider_exception(status_error(503)) == ("InternalServerError HTTP 503", 503, True)
    assert describe_provider_exception(status_error(401)) == ("AuthenticationError HTTP 401", 401, False)
    assert describe_provider_exception(openai.APITimeoutError(request=REQ))[2] is True
    assert describe_provider_exception(ValueError("bad"))[2] is False
    label, status, transient = describe_provider_exception(httpx.ConnectError("refused"))
    assert (label, status, transient) == ("ConnectError", None, True)


# ------------------------------------------------------------------------------------------------ wall-clock budget

def test_no_request_starts_after_the_deadline_and_the_failure_is_terminal(clock):
    a = agent(clock, "ok")
    with deadline(10):
        clock.now += 11
        with pytest.raises(ProviderFailure) as err:
            a.query_text("hi")
    assert err.value.kind == "deadline" and a._client.calls == 0
    assert "wall-clock budget" in str(err.value)


def test_a_retry_is_not_started_when_its_pause_would_pass_the_deadline(clock):
    a = agent(clock, openai.APITimeoutError(request=REQ))
    with deadline(10):
        with pytest.raises(ProviderFailure) as err:
            a.query_text("hi")
    # 1s request, 2s pause, 1s request, then the 6s pause does not fit in what is left: it stops instead of waiting past the budget
    assert a._client.calls == 2 and clock.sleeps == [2.0], "the 6s pause would pass the deadline, so it was not started"
    assert err.value.kind == "call_failed" and (clock.now - 1000.0) <= 10


def test_the_per_request_timeout_follows_the_deadline_and_is_absent_without_one(clock):
    a = agent(clock, "ok", "ok")
    a.query_text("one")
    assert "timeout" not in a._client.kwargs[0]
    with deadline(40):
        a.query_text("two")
    assert 5.0 <= a._client.kwargs[1]["timeout"] <= 40.0
    assert a._client.kwargs[1]["timeout"] <= a.resolved.provider.timeout_seconds


def test_nested_deadlines_keep_the_earlier_one(clock):
    with deadline(100):
        outer = remaining_seconds()
        with deadline(5):
            assert remaining_seconds() <= 5
        with deadline(1000):
            assert remaining_seconds() <= outer
    assert remaining_seconds() is None


def test_the_candidate_budget_is_configurable_and_bounded(monkeypatch):
    assert FunctionAnalyzer._candidate_seconds() == 900
    monkeypatch.setenv("FAULTSEEKER_CANDIDATE_SECONDS", "120")
    assert FunctionAnalyzer._candidate_seconds() == 120
    for raw, expected in (("5", 30), ("999999", 7200), ("abc", 900), ("", 900)):
        monkeypatch.setenv("FAULTSEEKER_CANDIDATE_SECONDS", raw)
        assert FunctionAnalyzer._candidate_seconds() == expected


def _loop_analyzer(clock):
    a = object.__new__(FunctionAnalyzer)
    a.function_prompts = SimpleNamespace(function_analysis_init_prompt="init", check_analysis_adequacy="adequacy?")
    a.function_call_info_summary, a.understanding_result = {}, "u"
    fit = lambda parts: ("".join(p.text for p in parts), [])        # an agent without a budget does not reduce anything
    a.reasoning_agent = SimpleNamespace(query_text=lambda p: "tree", fit=fit)
    a.organization_agent = SimpleNamespace(query_text=lambda p: "no", fit=fit)
    a.potentially_vulnerable_functions = {}
    a._temp_check = lambda: False
    a._update_current_understanding = lambda **kw: None

    def step():
        clock.now += 100
    a._select_task, a._perform_task = step, lambda: None
    a._update_task_tree = a._update_potentially_vulnerable_function = lambda: None
    return a


def test_a_candidate_stops_when_its_wall_clock_budget_ends_between_steps(clock):
    a = _loop_analyzer(clock)
    with deadline(250):
        with pytest.raises(CandidateIncomplete) as err:
            a._function_analysis_init()
    assert "wall-clock budget" in str(err.value) and err.value.retryable is False
    assert "iteration limit" not in str(err.value)


def test_a_deadline_failure_inside_a_step_is_a_wall_clock_stop_not_a_provider_outage(clock):
    a = _loop_analyzer(clock)

    def step():
        raise ProviderFailure("deadline", "the wall-clock budget for this stage ended before the provider answered")
    a._select_task = step
    with pytest.raises(CandidateIncomplete) as err:
        a._function_analysis_init()
    assert "wall-clock budget" in str(err.value) and "provider outage" not in str(err.value).split("wall-clock")[0]


def test_run_candidate_applies_the_budget_and_a_stuck_candidate_ends_failed_not_silent(clock, monkeypatch):
    from tests.test_function_analysis_state import analyzer as make_analyzer, entry
    a = make_analyzer(inspected={"f_0x" + "aa" * 20: entry()})
    seen = []

    def stuck():
        seen.append(remaining_seconds())
        raise ProviderFailure("deadline", "the wall-clock budget for this stage ended before the provider answered")
    monkeypatch.setenv("FAULTSEEKER_CANDIDATE_SECONDS", "60")
    a._function_analysis_init = stuck
    a._review_function_calls()
    assert seen and 0 < seen[0] <= 60, "the attempt ran inside a 60-second budget"
    assert a.unresolved_failures, "the candidate is recorded as failed, never dropped"


def test_the_forensics_stage_runs_inside_its_own_budget(monkeypatch):
    from faultseeker.forensics.orchestrator import ForensicsOrchestrator
    assert ForensicsOrchestrator._stage_seconds() == 900
    monkeypatch.setenv("FAULTSEEKER_STAGE1_SECONDS", "30")
    assert ForensicsOrchestrator._stage_seconds() == 60
    o = object.__new__(ForensicsOrchestrator)
    seen = []
    o._run = lambda h, c: seen.append(remaining_seconds()) or "done"
    monkeypatch.setenv("FAULTSEEKER_STAGE1_SECONDS", "300")
    assert o.run("0x1", "eth") == "done" and 0 < seen[0] <= 300
    assert remaining_seconds() is None, "the budget does not leak out of the stage"
