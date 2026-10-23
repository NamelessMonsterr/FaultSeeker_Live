"""Transport-only tests. All model HTTP is intercepted by MockTransport."""
import importlib
import json
import types

import httpx
import pytest
from openai import OpenAI


MODEL = "gpt-6.1-sol-low"
OK = {"id": "mock", "object": "chat.completion", "created": 0, "model": MODEL,
      "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"}, "finish_reason": "stop"}]}


class Clock:
    def __init__(self):
        self.now = 0.0
    def monotonic(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


def setup(responses, **options):
    module = importlib.import_module("app.model_endpoint")
    clock = Clock()
    calls, events, clients = [], [], []
    responses = iter(responses)
    def handle(request):
        calls.append(json.loads(request.content))
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response
    def factory():
        # Deliberately retain the SDK's default retries. The session must override it.
        client = OpenAI(api_key="test-secret-never-output", base_url="https://model.invalid/v1",
                        http_client=httpx.Client(transport=httpx.MockTransport(handle)))
        clients.append(client)
        return client
    session = module.ModelEndpointSession(emit=events.append, clock=clock.monotonic,
                                         sleep=clock.sleep, retry_limit=2,
                                         time_budget=60, call_timeout=10, **options)
    return module, session, factory, calls, events, clock


@pytest.mark.parametrize("status,body,kind", [(502, "<html>private error SECRET</html>", "upstream_http"),
                                              (500, {"error": {"message": "SECRET", "type": "server_error"}}, "upstream_http"),
                                              (401, {"error": {"message": "SECRET", "type": "auth_error"}}, "authentication")])
def test_classifies_errors_without_leaking_bodies(status, body, kind):
    response = httpx.Response(status, text=body) if isinstance(body, str) else httpx.Response(status, json=body)
    m, session, factory, calls, events, _ = setup([response] * 3)
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.preflight(factory, MODEL, timeout=20)
    assert failure.value.kind == kind
    assert "SECRET" not in str(failure.value)
    assert "html" not in str(failure.value).lower()
    assert len(calls) == (1 if status == 401 else 3)
    assert "SECRET" not in json.dumps(events)


def test_timeout_is_bounded_and_classified():
    m, session, factory, calls, _, _ = setup([httpx.ReadTimeout("SECRET")] * 3)
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.preflight(factory, MODEL, timeout=20)
    assert failure.value.kind == "timeout"
    assert len(calls) == 3
    assert "SECRET" not in str(failure.value)


def test_recovery_keeps_model_and_does_not_reset_shared_retry_allowance():
    m, session, factory, calls, events, _ = setup([
        httpx.Response(502, text="<html>bad gateway</html>"), httpx.Response(200, json=OK),
        httpx.Response(200, json=OK), httpx.Response(502, text="bad"), httpx.Response(502, text="bad")])
    session.preflight(factory, MODEL, timeout=20)
    assert session.call(factory, {"model": MODEL, "messages": []}, MODEL).choices[0].message.content == "OK"
    with pytest.raises(m.ModelEndpointFailure):
        session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    count = len(calls)
    with pytest.raises(m.ModelEndpointFailure):
        session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    assert len(calls) == count == 5
    assert all(c["model"] == MODEL for c in calls)
    assert any(e["state"] == "waiting_on_model_endpoint" for e in events)
    assert any(e["state"] == "model_endpoint_ready" for e in events)


def test_preflight_failure_never_starts_expensive_analysis():
    m, session, factory, calls, _, _ = setup([httpx.Response(401, json={"error": {"message": "no"}})])
    ran = False
    with pytest.raises(m.ModelEndpointFailure):
        session.preflight(factory, MODEL, timeout=20)
        ran = True
    assert not ran and len(calls) == 1


def test_sdk_retries_are_disabled_for_all_attempts():
    m, session, factory, calls, _, _ = setup([httpx.Response(500, json={"error": "fail"})] * 3)
    with pytest.raises(m.ModelEndpointFailure):
        session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    assert len(calls) == 3  # SDK defaults would multiply this to nine.


def test_time_budget_spans_successful_queries_and_preflight():
    m, session, factory, calls, _, clock = setup([httpx.Response(200, json=OK)] * 4)
    def slow_factory():
        client = factory()
        clock.now += 25
        return client
    session.preflight(factory, MODEL, timeout=20)
    session.call(slow_factory, {"model": MODEL, "messages": []}, MODEL)
    session.call(slow_factory, {"model": MODEL, "messages": []}, MODEL)
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.call(slow_factory, {"model": MODEL, "messages": []}, MODEL)
    assert failure.value.kind == "budget_exhausted"


def test_http_200_html_is_not_a_model_completion():
    m, session, factory, calls, _, _ = setup([httpx.Response(200, text="<html>SECRET</html>")])
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.preflight(factory, MODEL, timeout=20)
    assert failure.value.kind == "invalid_response"
    assert "SECRET" not in str(failure.value)


def test_preflight_deadline_clamps_individual_http_timeouts():
    m, session, factory, calls, _, clock = setup([httpx.Response(502, text="fail")] * 3)
    def slow_factory():
        clock.now += 15
        return factory()
    with pytest.raises(m.ModelEndpointFailure):
        session.preflight(slow_factory, MODEL, timeout=20)
    assert len(calls) <= 1


@pytest.mark.parametrize("status,kind", [(403, "authentication"), (404, "model_unavailable"), (400, "invalid_request")])
def test_permanent_rejection_has_no_retry(status, kind):
    m, session, factory, calls, _, _ = setup([httpx.Response(status, json={"error": {"message": "SECRET"}})])
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.preflight(factory, MODEL)
    assert failure.value.kind == kind and len(calls) == 1


def test_retry_after_cannot_sleep_past_shared_budget():
    m, session, factory, calls, events, clock = setup([httpx.Response(429, headers={"Retry-After": "99999"}, json={"error": "quota"})])
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    assert failure.value.kind == "budget_exhausted"
    assert clock.now == 0 and len(calls) == 1
