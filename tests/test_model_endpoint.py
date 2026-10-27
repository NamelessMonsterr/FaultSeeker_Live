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
    m, session, factory, calls, events, _ = setup([response] * 8)
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.preflight(factory, MODEL, timeout=20)
    assert failure.value.kind == kind
    assert "SECRET" not in str(failure.value)
    assert "html" not in str(failure.value).lower()
    # 401 fails fast; transient 5xx retries until the preflight deadline.
    assert len(calls) == (1 if status == 401 else 7)
    assert "SECRET" not in json.dumps(events)


def test_timeout_is_bounded_and_classified():
    m, session, factory, calls, _, clock = setup([httpx.ReadTimeout("SECRET")] * 8)
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.preflight(factory, MODEL, timeout=20)
    assert failure.value.kind == "timeout"
    assert len(calls) == 7 and clock.now < 20  # deadline-bounded, not count-bounded
    assert "SECRET" not in str(failure.value)


def test_recovery_keeps_model_and_does_not_reset_shared_retry_allowance():
    # Preflight retries are bounded by their deadline, not the shared allowance,
    # so the analysis call below still has all of it (3 attempts, 3 failures).
    m, session, factory, calls, events, _ = setup([
        httpx.Response(502, text="<html>bad gateway</html>"), httpx.Response(200, json=OK),
        httpx.Response(200, json=OK), httpx.Response(502, text="bad"), httpx.Response(502, text="bad"),
        httpx.Response(502, text="bad")])
    session.preflight(factory, MODEL, timeout=20)
    assert session.call(factory, {"model": MODEL, "messages": []}, MODEL).choices[0].message.content == "OK"
    with pytest.raises(m.ModelEndpointFailure):
        session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    count = len(calls)
    with pytest.raises(m.ModelEndpointFailure):
        session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    assert len(calls) == count == 6
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


def test_request_telemetry_reports_elapsed_and_queue_wait_without_payloads():
    m, session, factory, calls, events, clock = setup([httpx.Response(200, json=OK)])
    session.call(factory, {"model": MODEL, "messages": [{"role": "user", "content": "PRIVATE PROMPT"}]}, MODEL)
    started = next(e for e in events if e["state"] == "model_request_started")
    attempt = next(e for e in events if e["state"] == "model_request_attempt")
    assert started["queue_wait_seconds"] == 0
    assert attempt["elapsed_seconds"] >= 0
    assert attempt["outcome"] == "ok"
    assert attempt["error_kind"] is None
    assert "PRIVATE PROMPT" not in json.dumps(events)
    assert "test-secret-never-output" not in json.dumps(events)
    assert "authorization" not in json.dumps(events).lower()


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


@pytest.mark.parametrize("elapsed,accepted", [(59.9, True), (60.0, True), (60.1, False)])
def test_valid_completion_at_shared_time_boundary(elapsed, accepted):
    m, session, factory, calls, events, clock = setup([httpx.Response(200, json=OK)])
    # Charge actual mocked HTTP response time, rather than client creation time.
    def timed_factory():
        client = factory()
        transport = client._client._transport
        original = transport.handler
        def respond(request):
            clock.now += elapsed
            return original(request)
        transport.handler = respond
        return client
    if accepted:
        value = session.call(timed_factory, {"model": MODEL, "messages": []}, MODEL)
        assert value.choices[0].message.content == "OK"
        assert session.failure is None
        assert events[-1]["state"] == "model_endpoint_ready"
        if elapsed == 60:
            with pytest.raises(m.ModelEndpointFailure) as failure:
                session.call(factory, {"model": MODEL, "messages": []}, MODEL)
            assert failure.value.kind == "budget_exhausted"
    else:
        with pytest.raises(m.ModelEndpointFailure) as failure:
            session.call(timed_factory, {"model": MODEL, "messages": []}, MODEL)
        assert failure.value.kind == "budget_exhausted"
    assert len(calls) == 1



def test_preflight_cold_start_retries_past_retry_limit():
    # A waking endpoint that 502s more often than the analysis retry allowance
    # must still get its full preflight window to become ready.
    responses = [httpx.Response(502, text="bad gateway")] * 5 + [httpx.Response(200, json=OK)]
    m, session, factory, calls, events, _ = setup(responses)
    value = session.preflight(factory, MODEL, timeout=30)
    assert value.choices[0].message.content == "OK"
    assert len(calls) == 6  # retry_limit is 2 in this harness
    assert session.retries_left == 2  # preflight consumed no analysis retries
    assert session.failure is None
    waiting = [e for e in events if e["state"] == "waiting_on_model_endpoint" and e.get("phase") == "preflight"]
    assert sum(1 for e in waiting if e.get("retry_in_seconds") == 0) == 6  # every attempt announces itself to the UI


def test_preflight_persistent_failure_reports_last_error_at_deadline():
    m, session, factory, calls, events, clock = setup([httpx.Response(502, text="bad gateway")] * 20)
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.preflight(factory, MODEL, timeout=20)
    # Deadline expiry is attributed to the real cause, not the shared budget.
    assert failure.value.kind == "upstream_http" and failure.value.status_code == 502
    assert failure.value.phase == "preflight"
    assert len(calls) == 7 and clock.now < 20


def test_preflight_does_not_borrow_analysis_retries():
    responses = ([httpx.Response(502, text="bad gateway")] * 4 + [httpx.Response(200, json=OK)]
                 + [httpx.Response(502, text="bad")] * 2 + [httpx.Response(200, json=OK)]
                 + [httpx.Response(502, text="bad")])
    m, session, factory, calls, _, _ = setup(responses)
    session.preflight(factory, MODEL, timeout=30)
    # Analysis still has its full allowance: two retries, then success.
    assert session.call(factory, {"model": MODEL, "messages": []}, MODEL).choices[0].message.content == "OK"
    assert session.retries_left == 0
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    assert failure.value.kind == "upstream_http"
    assert len(calls) == 9


def test_preflight_zero_shared_budget_fails_fast_without_attempts():
    m, session, factory, calls, _, _ = setup([httpx.Response(200, json=OK)])
    session.time_budget = 0.0
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.preflight(factory, MODEL, timeout=20)
    assert failure.value.kind == "budget_exhausted"
    assert len(calls) == 0


def test_preflight_key_rotation_stays_bounded_by_key_count():
    m, session, factory, calls, events, _ = setup(
        [httpx.Response(401, json={"error": {"message": "SECRET"}})] * 4)
    session.register_keys("https://model.invalid/v1", ["key-one", "key-two"])
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.preflight(factory, MODEL, timeout=30)
    assert failure.value.kind == "authentication"
    assert len(calls) == 2  # one attempt per configured key, then fail fast
    assert session.retries_left == 2
    assert "SECRET" not in json.dumps(events)


def test_analysis_rate_limit_stops_without_retry_or_key_rotation():
    m, session, factory, calls, events, clock = setup([
        httpx.Response(429, headers={"Retry-After": "1"}, json={"error": {"message": "quota"}}),
        httpx.Response(200, json=OK),
    ])
    session.register_keys("https://model.invalid/v1", ["first-key", "second-key"], model=MODEL)
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    assert failure.value.kind == "rate_limited"
    assert failure.value.as_dict()["scope"] == "provider_limit"
    assert len(calls) == 1
    assert session.retries_left == 2
    assert not any(e.get("key_rotation") for e in events)
    assert "quota" not in json.dumps(events)
    assert "first-key" not in json.dumps(events)
    assert "second-key" not in json.dumps(events)


def test_preflight_rate_limit_retry_after_beyond_deadline_stays_bounded():
    m, session, factory, calls, _, clock = setup(
        [httpx.Response(429, headers={"Retry-After": "99999"}, json={"error": "quota"})])
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.preflight(factory, MODEL, timeout=20)
    # The deadline cannot fit the hinted wait: report the real cause, no sleep.
    assert failure.value.kind == "rate_limited"
    assert clock.now == 0 and len(calls) == 1


@pytest.mark.parametrize("endpoint", ["https://MODEL.invalid:443/v1", "https://model.invalid/v1/"])
def test_equivalent_endpoint_urls_preserve_rotation(endpoint):
    calls = []
    def reply(request):
        calls.append(request.headers["authorization"])
        return httpx.Response(200, json=OK) if calls[-1] == "Bearer valid-key" else httpx.Response(401, json={"error": {"message": "invalid"}})
    def factory():
        return OpenAI(api_key="invalid-key", base_url=endpoint,
                      http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    from app.model_endpoint import ModelEndpointSession
    session = ModelEndpointSession()
    session.register_keys(endpoint, ["invalid-key", "valid-key"], model=MODEL)
    session.preflight(factory, MODEL)
    assert calls == ["Bearer invalid-key", "Bearer valid-key"]


def test_model_specific_credentials_share_budget_without_crossing_pools():
    from app.model_endpoint import ModelEndpointSession, ModelEndpointFailure
    calls = []
    def reply(request):
        calls.append((json.loads(request.content)["model"], request.headers["authorization"]))
        return httpx.Response(401, json={"error": {"message": "invalid"}}) if calls[-1][1] == "Bearer bad" else httpx.Response(200, json=OK)
    def factory():
        return OpenAI(api_key="upstream-default", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    session = ModelEndpointSession(retry_limit=1)
    session.register_keys("https://model.invalid/v1", ["bad", "stage-one"], model="stage1")
    session.register_keys("https://model.invalid/v1", ["bad", "stage-two"], model="stage2")
    session.call(factory, {"model": "stage1", "messages": []}, "stage1")
    with pytest.raises(ModelEndpointFailure):
        session.call(factory, {"model": "stage2", "messages": []}, "stage2")
    assert calls == [("stage1", "Bearer bad"), ("stage1", "Bearer stage-one"), ("stage2", "Bearer bad")]
    assert session.retries_left == 0



def test_foreign_url_object_compatibility_contract_simulated():
    """Simulates httpx2.URL; this is not an installed OpenAI 3.x integration."""
    from app.model_endpoint import ModelEndpointSession
    class ForeignURL:
        def __str__(self): return "https://MODEL.invalid:443/v1/"
    calls = []
    def reply(request):
        calls.append(request.headers["authorization"])
        return httpx.Response(401, json={"error": {"message": "invalid"}}) if len(calls) == 1 else httpx.Response(200, json=OK)
    class ForeignClient:
        base_url = ForeignURL()
        def __init__(self):
            self.client = OpenAI(api_key="invalid-key", base_url=str(self.base_url),
                http_client=httpx.Client(transport=httpx.MockTransport(reply)))
        def with_options(self, **kwargs): return self.client.with_options(**kwargs)
        def close(self): self.client.close()
    session = ModelEndpointSession()
    session.register_keys(ForeignURL(), ["invalid-key", "valid-key"], model=MODEL)
    assert session.preflight(ForeignClient, MODEL).choices[0].message.content == "OK"
    assert calls == ["Bearer invalid-key", "Bearer valid-key"]
    assert session.failure is None
