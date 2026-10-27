"""Transport-only tests. All model HTTP is intercepted by MockTransport."""
import importlib
import json
import threading
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


def test_expired_absolute_deadline_fails_before_factory_or_network():
    m, session, factory, calls, _, clock = setup([])
    made = []
    def forbidden_factory():
        made.append(True)
        return factory()
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.call(forbidden_factory, {"model": MODEL, "messages": []}, MODEL,
                     deadline=clock.now)
    assert failure.value.kind == "request_deadline_exceeded"
    assert made == [] and calls == []


def test_absolute_deadline_includes_wait_for_state_lock():
    m = importlib.import_module("app.model_endpoint")
    clock = Clock()
    queued = threading.Event()
    made, errors = [], []
    def tracked_clock():
        value = clock.monotonic()
        queued.set()
        return value
    session = m.ModelEndpointSession(clock=tracked_clock, time_budget=30, call_timeout=5)
    def forbidden_factory():
        made.append(True)
        raise AssertionError("expired queued request must not build a client")
    def invoke():
        try:
            session.call(forbidden_factory, {"model": MODEL, "messages": []}, MODEL,
                         deadline=1.0)
        except Exception as exc:
            errors.append(exc)
    session.state_lock.acquire()
    worker = threading.Thread(target=invoke)
    try:
        worker.start()
        assert queued.wait(timeout=2), "worker did not enter call"
        clock.now = 2.0
    finally:
        session.state_lock.release()
        worker.join(timeout=2)
    assert not worker.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], m.ModelEndpointFailure)
    assert errors[0].kind == "request_deadline_exceeded"
    assert made == [] and session.failure is None


def test_shared_budget_deadline_expiring_in_queue_is_sticky():
    m = importlib.import_module("app.model_endpoint")
    clock = Clock()
    queued = threading.Event()
    made = []
    def tracked_clock():
        value = clock.monotonic()
        queued.set()
        return value
    session = m.ModelEndpointSession(time_budget=1, call_timeout=0.5, clock=tracked_clock)
    def forbidden_factory():
        made.append(True)
        raise AssertionError("queued request must not create a client after its shared deadline")
    def invoke():
        with pytest.raises(m.ModelEndpointFailure) as failure:
            session.call(forbidden_factory, {"model": MODEL, "messages": []}, MODEL)
        assert failure.value.kind == "budget_exhausted"
    session.state_lock.acquire()
    worker = threading.Thread(target=invoke)
    try:
        worker.start()
        assert queued.wait(timeout=2)
        clock.now = 2.0
    finally:
        session.state_lock.release()
        worker.join(timeout=2)
    assert not worker.is_alive()
    assert made == []
    assert session.failure is not None and session.failure.kind == "budget_exhausted"


def test_failed_attempt_at_exact_shared_budget_cannot_retry():
    m, session, factory, calls, _, clock = setup([
        httpx.Response(503, text="private upstream failure"),
        httpx.Response(200, json=OK)])
    def timed_factory():
        client = factory()
        transport = client._client._transport
        original = transport.handler
        def respond(request):
            clock.now += 60.0
            return original(request)
        transport.handler = respond
        return client
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.call(timed_factory, {"model": MODEL, "messages": []}, MODEL)
    assert failure.value.kind == "budget_exhausted"
    assert session.summary()["failure"]["kind"] == "budget_exhausted"
    assert len(calls) == 1 and clock.now == 60.0


def test_waiting_worker_is_not_failed_by_a_synthetic_admission_timeout():
    m = importlib.import_module("app.model_endpoint")
    entered, release = threading.Event(), threading.Event()
    requests, outcomes = [], []
    def handle(request):
        body = json.loads(request.content)
        message = body["messages"][0]["content"]
        requests.append(message)
        if message == "slow":
            entered.set()
            if not release.wait(timeout=3):
                raise AssertionError("test did not release mocked transport")
        return httpx.Response(200, json=OK)
    def factory():
        return OpenAI(api_key="test-secret-never-output", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    session = m.ModelEndpointSession(admission_timeout=0, time_budget=30, call_timeout=5)
    def first_call():
        try:
            outcomes.append(("first", session.call(factory, {"model": MODEL, "messages": [
                {"role": "user", "content": "slow"}]}, MODEL)))
        except Exception as exc:
            outcomes.append(("first-error", exc))
    worker = threading.Thread(target=first_call)
    worker.start()
    try:
        assert entered.wait(timeout=2), "first mocked request never reached transport"
        # A second worker is allowed to enter once the short state lock is free;
        # it must not manufacture a terminal failure because the first is in HTTP.
        result = session.call(factory, {"model": MODEL, "messages": [
            {"role": "user", "content": "quick"}]}, MODEL)
        assert result.choices[0].message.content == "OK"
    finally:
        release.set()
        worker.join(timeout=3)
    assert not worker.is_alive()
    assert len(requests) == 2
    assert len(outcomes) == 1 and outcomes[0][0] == "first"
    assert session.failure is None


def test_two_mocked_requests_overlap_without_holding_state_lock():
    m = importlib.import_module("app.model_endpoint")
    rendezvous = threading.Barrier(2)
    seen, outcomes = [], []
    seen_lock = threading.Lock()
    def handle(request):
        with seen_lock:
            seen.append(request)
        rendezvous.wait(timeout=3)
        return httpx.Response(200, json=OK)
    def factory():
        return OpenAI(api_key="test-secret-never-output", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    session = m.ModelEndpointSession(time_budget=10, call_timeout=3)
    def invoke(index):
        try:
            result = session.call(factory, {"model": MODEL, "messages": [
                {"role": "user", "content": f"worker-{index}"}]}, MODEL)
            outcomes.append(("ok", result.choices[0].message.content))
        except Exception as exc:
            outcomes.append(("error", exc))
    workers = [threading.Thread(target=invoke, args=(i,)) for i in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=4)
    assert all(not worker.is_alive() for worker in workers), "requests did not overlap/release"
    assert len(seen) == 2
    assert len(outcomes) == 2 and all(outcome == ("ok", "OK") for outcome in outcomes)
    assert session.failure is None
    assert session.summary()["calls"]["analysis"] == {"ok": 2, "failed": 0}


def test_concurrent_retry_reservations_are_atomic_and_bounded():
    m = importlib.import_module("app.model_endpoint")
    rendezvous = threading.Barrier(2)
    requests, outcomes, reservations = [], [], []
    guard = threading.Lock()
    session = m.ModelEndpointSession(retry_limit=2, time_budget=20, call_timeout=5)
    def handle(request):
        with guard:
            requests.append(request)
            number = len(requests)
            with session.state_lock:
                reservations.append(session.spent + session.reserved)
        if number <= 2:
            rendezvous.wait(timeout=3)
            return httpx.Response(502, text="private upstream failure")
        return httpx.Response(200, json=OK)
    def factory():
        return OpenAI(api_key="test-secret-never-output", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    def invoke(index):
        try:
            result = session.call(factory, {"model": MODEL, "messages": [
                {"role": "user", "content": f"retry-{index}"}]}, MODEL)
            outcomes.append(("ok", result.choices[0].message.content))
        except Exception as exc:
            outcomes.append(("error", exc))
    workers = [threading.Thread(target=invoke, args=(i,)) for i in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=6)
    assert all(not worker.is_alive() for worker in workers), "concurrent retries did not finish"
    assert len(requests) == 4
    assert len(outcomes) == 2 and all(outcome == ("ok", "OK") for outcome in outcomes)
    assert session.retries_left == 0
    assert session.failure is None
    assert reservations and max(reservations) <= session.time_budget


def test_stale_auth_failure_does_not_reject_new_active_key():
    m = importlib.import_module("app.model_endpoint")
    rendezvous = threading.Barrier(2)
    rotated = threading.Event()
    events, requests, outcomes = [], [], []
    requests_lock = threading.Lock()
    def emit(event):
        events.append(event)
        if event.get("key_rotation"):
            rotated.set()
    def handle(request):
        body = json.loads(request.content)
        message = body["messages"][0]["content"]
        auth = request.headers.get("authorization")
        with requests_lock:
            requests.append((message, auth))
        if auth == "Bearer key-a":
            rendezvous.wait(timeout=3)
            if message == "stale":
                assert rotated.wait(timeout=3), "other request did not rotate key"
            return httpx.Response(401, json={"error": {"message": "private"}})
        return httpx.Response(200, json=OK)
    def factory():
        return OpenAI(api_key="key-a", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    session = m.ModelEndpointSession(emit=emit, retry_limit=3, time_budget=10, call_timeout=3)
    session.register_keys("https://model.invalid/v1", ["key-a", "key-b"], model=MODEL)
    def invoke(message):
        try:
            session.call(factory, {"model": MODEL, "messages": [
                {"role": "user", "content": message}]}, MODEL)
            outcomes.append((message, "ok"))
        except Exception as exc:
            outcomes.append((message, exc))
    workers = [threading.Thread(target=invoke, args=(message,)) for message in ("rotate", "stale")]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
    assert all(not worker.is_alive() for worker in workers)
    assert sorted(outcomes) == [("rotate", "ok"), ("stale", "ok")]
    assert session.key_pools[("https://model.invalid/v1", MODEL)]["active"] == "key-b"
    assert "key-b" not in session.key_pools[("https://model.invalid/v1", MODEL)]["rejected"]
    assert sum(1 for _, auth in requests if auth == "Bearer key-a") == 2
    assert sum(1 for _, auth in requests if auth == "Bearer key-b") == 2
    assert "key-a" not in json.dumps(events) and "key-b" not in json.dumps(events)


def test_terminal_429_blocks_an_inflight_success_commit():
    m = importlib.import_module("app.model_endpoint")
    slow_entered, terminal = threading.Event(), threading.Event()
    events, requests, outcomes = [], [], []
    def emit(event):
        events.append(event)
        if event.get("state") == "model_endpoint_failed":
            terminal.set()
    def handle(request):
        body = json.loads(request.content)
        message = body["messages"][0]["content"]
        requests.append(message)
        if message == "slow-success":
            slow_entered.set()
            if not terminal.wait(timeout=3):
                raise AssertionError("429 did not trip terminal circuit")
            return httpx.Response(200, json=OK)
        return httpx.Response(429, json={"error": {"message": "private quota"}})
    def factory():
        return OpenAI(api_key="test-secret-never-output", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    session = m.ModelEndpointSession(emit=emit, time_budget=10, call_timeout=3)
    def slow_call():
        try:
            session.call(factory, {"model": MODEL, "messages": [
                {"role": "user", "content": "slow-success"}]}, MODEL)
            outcomes.append(("slow", "ok"))
        except Exception as exc:
            outcomes.append(("slow", exc))
    worker = threading.Thread(target=slow_call)
    worker.start()
    try:
        assert slow_entered.wait(timeout=2), "slow request never reached transport"
        with pytest.raises(m.ModelEndpointFailure) as limited:
            session.call(factory, {"model": MODEL, "messages": [
                {"role": "user", "content": "rate-limit"}]}, MODEL)
        assert limited.value.kind == "rate_limited"
    finally:
        terminal.set()
        worker.join(timeout=4)
    assert not worker.is_alive()
    assert len(requests) == 2
    assert len(outcomes) == 1 and outcomes[0][0] == "slow"
    assert isinstance(outcomes[0][1], m.ModelEndpointFailure)
    assert outcomes[0][1].kind == "rate_limited"
    assert session.failure.kind == "rate_limited"
    assert not any(event.get("state") == "model_endpoint_ready" for event in events)
    assert "private quota" not in json.dumps(events)


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
    # 503 is retryable; the long Retry-After must still respect the shared budget.
    m, session, factory, calls, events, clock = setup([httpx.Response(503, headers={"Retry-After": "99999"}, json={"error": "temporary"})])
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



def test_explicit_tighter_deadline_does_not_trip_shared_budget_on_retry_after():
    m, session, factory, calls, _, clock = setup([
        httpx.Response(503, headers={"Retry-After": "99999"}, json={"error": "temporary"})])
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.call(factory, {"model": MODEL, "messages": []}, MODEL, deadline=1.0)
    assert failure.value.kind == "request_deadline_exceeded"
    assert len(calls) == 1 and clock.now == 0
    assert session.failure is None


def test_budget_overrun_is_sticky_and_blocks_inflight_success_commit():
    m = importlib.import_module("app.model_endpoint")
    local = threading.local()
    slow_entered, terminal = threading.Event(), threading.Event()
    requests, outcomes = [], []
    def clock():
        return getattr(local, "now", 0.0)
    def emit(event):
        if event.get("state") == "model_endpoint_failed":
            terminal.set()
    def handle(request):
        message = json.loads(request.content)["messages"][0]["content"]
        requests.append(message)
        if message == "inflight-success":
            slow_entered.set()
            if not terminal.wait(timeout=3):
                raise AssertionError("over-budget finalizer did not trip the circuit")
            return httpx.Response(200, json=OK)
        if not slow_entered.wait(timeout=3):
            raise AssertionError("success request did not become in-flight")
        local.now = 75.0
        return httpx.Response(503, text="private upstream failure")
    def factory():
        return OpenAI(api_key="test-secret-never-output", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    session = m.ModelEndpointSession(emit=emit, time_budget=60, call_timeout=20, clock=clock)
    def invoke(message):
        try:
            result = session.call(factory, {"model": MODEL, "messages": [
                {"role": "user", "content": message}]}, MODEL)
            outcomes.append((message, "ok", result.choices[0].message.content))
        except Exception as exc:
            outcomes.append((message, "error", exc))
    slow = threading.Thread(target=invoke, args=("inflight-success",))
    overrun = threading.Thread(target=invoke, args=("overrun",))
    slow.start()
    overrun.start()
    for worker in (slow, overrun):
        worker.join(timeout=5)
    assert not slow.is_alive() and not overrun.is_alive()
    assert len(requests) == 2
    assert session.spent == 75.0
    assert session.summary()["failure"]["kind"] == "budget_exhausted"
    assert not any(item[0] == "inflight-success" and item[1] == "ok" for item in outcomes)
    before = len(requests)
    with pytest.raises(m.ModelEndpointFailure) as failure:
        session.call(factory, {"model": MODEL, "messages": [
            {"role": "user", "content": "must-not-start"}]}, MODEL)
    assert failure.value.kind == "budget_exhausted"
    assert len(requests) == before == 2


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


@pytest.mark.parametrize("phase,retry_after", [
    ("analysis", "1"),
    ("analysis", "99999"),
    ("preflight", "1"),
    ("preflight", "99999"),
])
def test_rate_limit_is_terminal_in_both_phases_with_multiple_keys(phase, retry_after):
    m, session, factory, calls, events, clock = setup([
        httpx.Response(429, headers={"Retry-After": retry_after}, json={"error": {"message": "quota"}}),
        httpx.Response(200, json=OK),
    ])
    session.register_keys("https://model.invalid/v1", ["first-key", "second-key"], model=MODEL)
    with pytest.raises(m.ModelEndpointFailure) as failure:
        if phase == "preflight":
            session.preflight(factory, MODEL, timeout=20)
        else:
            session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    assert failure.value.kind == "rate_limited"
    assert failure.value.phase == phase
    assert failure.value.as_dict()["scope"] == "provider_limit"
    assert len(calls) == 1
    assert session.retries_left == 2
    assert session.spent == 0
    assert clock.now == 0
    assert not any(e.get("key_rotation") for e in events)
    assert not any(e.get("retry_in_seconds", 0) > 0 for e in events)
    assert "quota" not in json.dumps(events)
    assert "first-key" not in json.dumps(events)
    assert "second-key" not in json.dumps(events)


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
