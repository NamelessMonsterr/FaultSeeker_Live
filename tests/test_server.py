"""Offline regressions for public API boundaries; no provider requests are made."""
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest
import asyncio
import httpx

ROOT = Path(__file__).resolve().parents[1]
TX = "0x" + "a" * 64


def test_separate_rpc_key_requires_explicit_placeholder(client):
    response = client.post("/api/analyze", json={"txn_hash": TX, "rpc_key": "private-key"})
    assert response.status_code == 400
    assert "{key}" in response.json()["error"]


def test_worker_preflight_failure_prevents_pipeline_execution(server, monkeypatch):
    import queue
    from app.model_endpoint import ModelEndpointFailure
    called = []
    class Runtime:
        def preflight(self, *args, **kwargs):
            raise ModelEndpointFailure("upstream_http", 502, "preflight")
        def failure_report(self, error):
            return {"transaction_hash": TX, "analysis_status": "failed", "sections": {"function_analysis": "skipped"},
                    "classification": {"rule_verdict": "INCONCLUSIVE"}}
        def close(self):
            pass
    def main(**kwargs):
        called.append(kwargs)
        return {"transaction_hash": TX}
    monkeypatch.setitem(sys.modules, "faultseeker.main", types.SimpleNamespace(main=main))
    monkeypatch.setattr(server, "_prepare_pipeline", lambda *args: Runtime(), raising=False)
    events = queue.Queue()
    server.worker("preflight", {"txn_hash": TX, "chain": "eth", "mode": "gpt-6.1-sol-low", "model_key": "test-only-key"}, events)
    assert not called
    output = []
    while not events.empty():
        output.append(events.get_nowait())
    assert not any(ev == "done" for ev, _ in output)
    assert any(ev == "error" for ev, _ in output)
    report = json.loads((Path(server.RUNS_DIR) / "preflight.json").read_text())
    assert report["analysis_status"] == "failed"
    assert report["sections"]["function_analysis"] == "skipped"


def test_live_configuration_exposes_no_credentials(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "never-expose-this-key")
    response = client.get("/api/config")
    assert response.status_code == 200
    assert response.json()["server_key_available"]["OPENAI_API_KEY"] is True
    assert "never-expose-this-key" not in response.text


@pytest.mark.parametrize("state", ["cancelled", "error", "timeout"])
def test_restarted_server_preserves_unsuccessful_history(client, server, state):
    server._hist_upsert({"run_id": "restart", "status": state})
    path = Path(server.RUNS_DIR) / "restart.json"
    path.write_text(json.dumps({"transaction_hash": TX, "analysis_status": "completed", "scored_functions": [{"function": "candidate"}]}))
    assert "restart" not in server.runs
    response = client.get("/api/result/restart")
    assert response.status_code == 200
    assert response.json()["analysis_status"] == state
    assert response.json()["classification"]["rule_verdict"] == "INCONCLUSIVE"


@pytest.fixture
def server(monkeypatch, tmp_path):
    monkeypatch.delenv("GITHUB_HISTORY_TOKEN", raising=False)
    monkeypatch.delenv("DEMO_GATE_PASSWORD", raising=False)
    spec = importlib.util.spec_from_file_location("regression_server", ROOT / "app/server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "RUNS_DIR", str(tmp_path))
    monkeypatch.setattr(module, "HISTORY_PATH", str(tmp_path / "index.json"))
    return module


@pytest.fixture
def client(server):
    class Client:
        def request(self, method, path, **kwargs):
            async def invoke():
                transport = httpx.ASGITransport(app=server.app, raise_app_exceptions=False, client=("testclient", 50000))
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as value:
                    return await value.request(method, path, **kwargs)
            return asyncio.run(invoke())
        def get(self, path, **kwargs):
            return self.request("GET", path, **kwargs)
        def post(self, path, **kwargs):
            return self.request("POST", path, **kwargs)
    return Client()


@pytest.mark.parametrize("body", [None, [], "text", 1, {"txn_hash": 42}, {"txn_hash": TX, "chain": []}, {"txn_hash": TX, "mode": []}, {"txn_hash": "0x" + "z" * 64}])
def test_invalid_analysis_payload_is_client_error(client, body):
    response = client.post("/api/analyze", json=body)
    assert response.status_code in (400, 422)


def test_malformed_json_is_client_error(client):
    assert client.post("/api/analyze", content="{", headers={"Content-Type": "application/json"}).status_code in (400, 422)


def test_untrusted_model_never_enters_history(client, server):
    response = client.post("/api/analyze", json={"txn_hash": TX, "mode": '<img src=x onerror=alert(1)>'})
    assert response.status_code in (400, 422)
    assert server._hist_load() == []


@pytest.mark.parametrize("replay", [False, True])
def test_history_disk_failure_releases_lock(client, server, monkeypatch, replay):
    def fail(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(server, "_hist_upsert", fail)
    tx = next(iter(server.DEMO_REPLAYS)) if replay else TX
    assert client.post("/api/analyze", json={"txn_hash": tx}).status_code in (500, 503)
    assert not server.run_lock.locked()


def test_thread_start_failure_releases_lock(client, server, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("thread unavailable")
    monkeypatch.setattr(server.threading.Thread, "start", fail)
    # Call the coroutine directly so TestClient's own threads remain functional.
    import asyncio
    request = types.SimpleNamespace(json=lambda: None)
    async def body():
        return {"txn_hash": TX}
    request.json = body
    assert asyncio.run(server.analyze(request)).status_code == 500
    assert not server.run_lock.locked()


def test_provider_import_failure_cannot_change_environment(server, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "server-owned-secret")
    monkeypatch.setitem(sys.modules, "faultseeker.utils.agent", None)
    try:
        server.llm_selftest(model="gpt-4o-mini", keys="visitor-secret")
    except ImportError:
        pass
    import os
    assert os.environ["OPENAI_API_KEY"] == "server-owned-secret"


def test_selftest_caps_real_calls_and_keeps_credentials_local(server, monkeypatch):
    calls = []
    def create(**kwargs):
        import os
        assert os.environ.get("OPENAI_API_KEY") == "server-owned-secret"
        calls.append(kwargs)
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=types.SimpleNamespace(content="ok"))])
    fake = types.SimpleNamespace(__version__="test", OpenAI=lambda **kwargs: types.SimpleNamespace(chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=create))))
    monkeypatch.setenv("OPENAI_API_KEY", "server-owned-secret")
    monkeypatch.setitem(sys.modules, "openai", fake)
    monkeypatch.setitem(sys.modules, "faultseeker.utils.agent", types.SimpleNamespace(PROVIDER_CONFIG={}))
    result = server.llm_selftest(model="gpt-4o-mini", max_keys=10000, keys="one,two,three,four,five")
    assert len(calls) <= 3
    assert calls, result


def test_structured_event_and_persistent_log_redact_nested_secrets(server, tmp_path):
    server._SECRET_VALUES.append("server-owned-secret")
    data = {"nested": [{"error": "server-owned-secret"}]}
    assert "server-owned-secret" not in server.sse("log", data)
    server._hist_log_event("test", "log", data)
    assert "server-owned-secret" not in (tmp_path / "test.events.jsonl").read_text()


def test_two_stream_clients_receive_identical_complete_history(client, server):
    bus = server.RunBus()
    for event in [("log", "first"), ("log", "second"), ("end", None)]:
        bus.put(event)
    server.runs["test"] = {"q": bus, "result": None, "proc": None}
    first = client.get("/api/stream/test").text
    assert first == client.get("/api/stream/test").text
    assert "first" in first and "second" in first and "event: end" in first
    assert "id: " in first
    resumed = client.get("/api/stream/test", headers={"Last-Event-ID": "1"}).text
    assert "first" not in resumed
    assert "second" in resumed


@pytest.mark.parametrize("payload", [{"limitations": ["trace unavailable"]}, {"_debug": {"error": "trace unavailable"}}, {"evidence_cards": [{"evidence": ["possible issue"]}]}])
def test_partial_evidence_cannot_claim_confirmed_or_completed(server, payload):
    result = server._adapt_result_for_view(payload)
    assert result["classification"]["rule_verdict"] not in ("CLEAN", "CONFIRMED")
    assert result["analysis_status"] != "completed"


@pytest.mark.parametrize("payload", [[], None, "bad", {"transaction": None}, {"priority": "HIGH", "reentrancy": []}, {"scored_functions": 42}, {"evidence_cards": [{"function_signature": "bad"}]}])
def test_result_shape_never_causes_http_500(client, server, payload):
    server.runs["test"] = {"q": server.RunBus(), "result": payload, "proc": None}
    response = client.get("/api/result/test")
    assert response.status_code in (200, 404, 422, 502)
    if response.status_code == 200:
        assert isinstance(response.json().get("transaction"), dict)


def test_diagnostic_quota_is_enforced_without_provider_calls(client, server, monkeypatch):
    monkeypatch.setattr(server, "_diag_by_ip", {"testclient": [server.time.time()] * 30})
    assert client.get("/api/llm-selftest").status_code == 429
    assert client.get("/api/rpc-selftest").status_code == 429


def test_pipeline_commit_is_verified_during_image_build():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "rev-parse HEAD" in dockerfile
    assert '"$FAULTSEEKER_SHA"' in dockerfile
    assert "exit 1" in dockerfile or "checkout --detach" in dockerfile


def test_bounded_stream_keeps_end_and_reports_replay_gap(client, server):
    bus = server.RunBus(max_events=3)
    for i in range(12):
        bus.put(("log", str(i)))
    bus.put(("end", None))
    assert len(bus.events) <= 3
    server.runs["bounded"] = {"q": bus, "result": None, "proc": None}
    response = client.get("/api/stream/bounded", headers={"Last-Event-ID": "1"})
    assert "replay-gap" in response.text
    assert "event: end" in response.text


def test_result_redacts_request_secret_and_retains_schema(client, server):
    secret = "visitor-key-sensitive-12345"
    bus = server.RunBus(secrets=(secret,))
    server.runs["secret"] = {"q": bus, "result": {"limitations": [secret], "transaction_hash": TX}, "proc": None}
    response = client.get("/api/result/secret")
    assert response.status_code == 200
    assert secret not in response.text
    assert response.json()["transaction"]["hash"] == TX


def test_nested_redaction_retains_types_and_masks_rpc_url(server):
    secret = "private-endpoint-token-12345"
    url = "https://rpc.example/" + secret
    value = {"nested": [{"message": url, "count": 4, "enabled": True}], "model_key": "other-key"}
    result = server._redact(value, (url, secret))
    assert isinstance(result, dict)
    assert result["nested"][0]["count"] == 4
    assert result["nested"][0]["enabled"] is True
    assert secret not in json.dumps(result)
    assert "other-key" not in json.dumps(result)


def test_process_start_failure_releases_lock_and_terminates_stream(client, server, monkeypatch):
    class InlineThread:
        def __init__(self, target, **kwargs):
            self.target = target
        def start(self):
            self.target()
    class BrokenProcess:
        def __init__(self, **kwargs):
            pass
        def start(self):
            raise OSError("spawn unavailable")
    monkeypatch.setattr(server.threading, "Thread", InlineThread)
    monkeypatch.setattr(server.mp, "Process", BrokenProcess)
    monkeypatch.setattr(server.mp, "Queue", lambda: object())
    response = client.post("/api/analyze", json={"txn_hash": TX})
    assert response.status_code in (200, 500, 503)
    assert not server.run_lock.locked()
    if response.status_code == 200:
        text = client.get("/api/stream/" + response.json()["run_id"]).text
        assert "event: error" in text and "event: end" in text


def test_parallel_diagnostics_do_not_exchange_visitor_keys(server, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import os
    import threading
    barrier = threading.Barrier(2)
    observed = []
    def factory(api_key, **kwargs):
        def create(**kwargs):
            barrier.wait(timeout=5)
            observed.append((api_key, os.environ.get("OPENAI_API_KEY")))
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=types.SimpleNamespace(content="ok"))])
        return types.SimpleNamespace(chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=create)))
    monkeypatch.setenv("OPENAI_API_KEY", "server-owned-secret")
    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(__version__="test", OpenAI=factory))
    monkeypatch.setitem(sys.modules, "faultseeker.utils.agent", types.SimpleNamespace(PROVIDER_CONFIG={}))
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(server.llm_selftest, model="gpt-4o-mini", keys=key) for key in ("visitor-one", "visitor-two")]
        for future in futures:
            assert future.result(timeout=8)["keys"][0]["ok"]
    assert sorted(observed) == [("visitor-one", "server-owned-secret"), ("visitor-two", "server-owned-secret")]


@pytest.mark.parametrize("upstream", [{"transaction_hash": TX, "analysis_status": "inconclusive", "limitations": ["trace unavailable"]}, {"error": "provider returned an error"}])
def test_worker_preserves_incomplete_or_failed_upstream_result(server, monkeypatch, tmp_path, upstream):
    import queue
    import signal
    monkeypatch.setattr(signal, "signal", lambda *args: None)
    # This test isolates worker publication; actual pipeline hooks have their own
    # verified-trace and mocked-HTTP integration tests.
    monkeypatch.setattr(server, "_prepare_pipeline", lambda *args: None)
    paths = []
    def pipeline(**kwargs):
        path = Path(kwargs["output_path"])
        paths.append(path)
        assert path.name == "worker.pipeline.json"
        assert not (tmp_path / "worker.json").exists()
        path.write_text(json.dumps(upstream))
        return dict(upstream)
    monkeypatch.setitem(sys.modules, "faultseeker.main", types.SimpleNamespace(main=pipeline))
    events = queue.Queue()
    server.worker("worker", {"txn_hash": TX, "chain": "eth", "mode": "no-llm"}, events)
    emitted = []
    while not events.empty():
        emitted.append(events.get_nowait())
    assert paths and not paths[0].exists()
    assert emitted[-1][0] == "end"
    if "error" in upstream:
        assert any(event == "error" for event, _ in emitted)
        assert not any(event == "done" for event, _ in emitted)
        assert not (tmp_path / "worker.json").exists()
    else:
        saved = json.loads((tmp_path / "worker.json").read_text())
        assert saved["analysis_status"] == "inconclusive"
        assert saved["stage_completed"] != "stage-3"


@pytest.mark.parametrize("state", ["running", "cancelling"])
def test_results_do_not_read_or_cache_partial_files(client, server, tmp_path, state):
    partial = {"transaction_hash": TX, "analysis_status": "completed"}
    (tmp_path / "active.json").write_text(json.dumps(partial))
    server.runs["active"] = {"q": server.RunBus(), "result": None, "status": state, "proc": None}
    response = client.get("/api/result/active")
    assert response.status_code == 409
    assert server.runs["active"]["result"] is None


@pytest.mark.parametrize("state", ["cancelled", "error", "timeout", "died"])
def test_unsuccessful_run_cannot_present_completed_verdict(client, server, state):
    payload = {"transaction": {"hash": TX}, "analysis_status": "completed", "classification": {"rule_verdict": "CONFIRMED"}}
    server.runs["partial"] = {"q": server.RunBus(), "result": payload, "status": state, "proc": None}
    response = client.get("/api/result/partial")
    assert response.status_code == 200
    assert response.json()["analysis_status"] != "completed"
    assert response.json()["classification"]["rule_verdict"] == "INCONCLUSIVE"


@pytest.mark.parametrize("route", ["result", "stream", "runs", "status", "cancel"])
def test_windows_run_id_traversal_is_rejected(client, route):
    path = "/api/" + route + "/..%5C..%5Cprivate"
    response = client.post(path) if route == "cancel" else client.get(path)
    assert response.status_code == 400


@pytest.mark.parametrize("report_status", ["partial", "failed"])
def test_endpoint_failure_report_keeps_explicit_coverage(client, server, report_status):
    payload = {"transaction": {"hash": TX}, "analysis_status": report_status,
               "classification": {"rule_verdict": "INCONCLUSIVE"},
               "sections": {"function_analysis": "failed", "scoring": "skipped"}}
    server.runs["endpointfailure"] = {"q": server.RunBus(), "result": payload, "status": "error", "proc": None}
    response = client.get("/api/result/endpointfailure")
    assert response.json()["analysis_status"] == report_status
    assert response.json()["sections"] == payload["sections"]


def test_worker_mid_run_model_loss_persists_partial_report(server, monkeypatch):
    import queue
    import httpx
    from openai import OpenAI
    from app.model_endpoint import ModelEndpointSession
    from app.pipeline_guards import PipelineRuntime
    calls = []
    events = queue.Queue()
    def respond(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(200, json={"id": "offline", "object": "chat.completion", "created": 0,
                "model": "gpt-6.1-sol-low", "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "OK"}}]})
        return httpx.Response(502, text="<html>PRIVATE_PROVIDER_BODY</html>")
    def factory():
        return OpenAI(api_key="test-only-key", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(respond)))
    session = ModelEndpointSession(retry_limit=0, emit=lambda value: events.put(("model_status", value)))
    runtime = PipelineRuntime(TX, "eth", session=session)
    runtime.preflight = lambda *args, **kwargs: session.preflight(factory, "gpt-6.1-sol-low")
    def main(**kwargs):
        runtime.partial = {"transaction": {"hash": TX}, "classification": {"rule_verdict": "EXPLOIT"}}
        session.call(factory, {"model": "gpt-6.1-sol-low", "messages": []}, "gpt-6.1-sol-low")
    monkeypatch.setitem(sys.modules, "faultseeker.main", types.SimpleNamespace(main=main))
    monkeypatch.setattr(server, "_prepare_pipeline", lambda *args: runtime)
    server.worker("midrun", {"txn_hash": TX, "chain": "eth", "mode": "gpt-6.1-sol-low", "model_key": "test-only-key"}, events)
    report = json.loads((Path(server.RUNS_DIR) / "midrun.json").read_text())
    assert len(calls) == 2
    assert report["analysis_status"] == "partial"
    assert report["sections"]["function_analysis"] == "failed"
    assert report["sections"]["scoring"] == "skipped"
    assert report["classification"]["rule_verdict"] == "INCONCLUSIVE"
    emitted = list(events.queue)
    assert not any(kind == "done" for kind, _ in emitted)
    assert "PRIVATE_PROVIDER_BODY" not in json.dumps(emitted) + json.dumps(report)


@pytest.mark.parametrize("kind,status", [("authentication", 401), ("rate_limited", 429)])
def test_worker_does_not_restart_pipeline_after_shared_credential_exhaustion(server, monkeypatch, kind, status):
    import queue
    from app.model_endpoint import ModelEndpointFailure
    calls = []
    class Runtime:
        def preflight(self, *args, **kwargs):
            pass
        def failure_report(self, error):
            return {"transaction_hash": TX, "analysis_status": "partial", "classification": {"rule_verdict": "INCONCLUSIVE"}}
        def close(self):
            pass
    def pipeline(**kwargs):
        calls.append(kwargs)
        raise ModelEndpointFailure(kind, status)
    monkeypatch.setattr(server, "_prepare_pipeline", lambda *args: Runtime())
    monkeypatch.setitem(sys.modules, "faultseeker.main", types.SimpleNamespace(main=pipeline))
    events = queue.Queue()
    server.worker("exhausted", {"txn_hash": TX, "chain": "eth", "mode": "gpt-6.1-sol-low", "model_key": "test-first,test-second"}, events)
    assert len(calls) == 1
    report = json.loads((Path(server.RUNS_DIR)/"exhausted.json").read_text())
    assert report["analysis_status"] == "partial"


def test_cancel_before_process_registration_is_honored(client, server, monkeypatch):
    captured = []
    class InlineThread:
        def __init__(self, target, **kwargs):
            self.target = target
        def start(self):
            self.target()
    class Process:
        exitcode = -15
        alive = True
        terminated = False
        def __init__(self, args, **kwargs):
            self.run_id = args[0]
            captured.append(self)
        def start(self):
            # Cancellation arrives while proc is still None in the run table.
            assert server.runs[self.run_id]["proc"] is None
            # This endpoint completes without suspension; drive it directly
            # inside the enclosing ASGI loop to exercise the startup race.
            cancellation = server.cancel(self.run_id)
            with pytest.raises(StopIteration) as completed:
                cancellation.send(None)
            assert completed.value.value["cancelled"] is True
        def terminate(self):
            self.terminated = True
            self.alive = False
        def is_alive(self):
            return self.alive
        def join(self, **kwargs):
            pass
    monkeypatch.setattr(server.threading, "Thread", InlineThread)
    monkeypatch.setattr(server.mp, "Process", Process)
    monkeypatch.setattr(server.mp, "Queue", lambda: object())
    response = client.post("/api/analyze", json={"txn_hash": TX})
    assert response.status_code == 200
    run_id = response.json()["run_id"]
    assert captured[0].terminated
    assert server.runs[run_id]["status"] == "cancelled"
    assert server.runs[run_id]["q"].closed
    assert not server.run_lock.locked()



def test_rpc_diagnostic_never_returns_url_credentials(server, monkeypatch):
    parent = types.ModuleType("faultseeker")
    utils = types.ModuleType("faultseeker.utils")
    rpc = types.ModuleType("faultseeker.utils.rpc_provider")
    parent.utils, utils.rpc_provider = utils, rpc
    rpc._registry = types.SimpleNamespace(_providers=lambda chain: [types.SimpleNamespace(url=url) for url in
        ("https://dummy-user:dummy-password@rpc.invalid/v1", "https://rpc.invalid?token=dummy-query")])
    rpc._http_post = lambda *a, **k: {"result": {"structLogs": []}}
    rpc._check_rpc_error = lambda data: data["result"]
    for name, module in [("faultseeker", parent), ("faultseeker.utils", utils), ("faultseeker.utils.rpc_provider", rpc)]:
        monkeypatch.setitem(sys.modules, name, module)
    result = server.rpc_selftest()
    assert [p["host"] for p in result["providers"]] == ["rpc.invalid", "rpc.invalid"]
    assert "dummy-" not in json.dumps(result)


def test_redaction_preserves_forensic_token_names_but_masks_credentials(server):
    assert server._redact("token: USDC transferred; token = WETH") == "token: USDC transferred; token = WETH"
    assert "dummy-secret" not in server._redact("https://rpc.invalid?token=dummy-secret&x=1")
    assert "dummy-secret" not in server._redact("access_token=dummy-secret")
    assert server._redact({"authorization": "dummy-secret"}) == {"authorization": "***"}
    assert server._redact("token: known-dummy-secret", ["known-dummy-secret"]) == "token: ***"


def test_adapter_keeps_absent_measurements_unknown(server):
    value = server._adapt_result_for_view({"transaction_hash": TX, "analysis_status": "completed",
        "scored_functions": [{"function": "0x12345678", "address": "0xabc"}]})
    assert value["classification"]["rule_verdict"] == "INCONCLUSIVE"
    assert value["classification"]["signals"]["profit_extraction_eth"] is None
    assert value["classification"]["signals"]["large_transfer_to_eoa"] is None
    assert value["classification"]["reentrancy"]["score"] is None


@pytest.mark.parametrize("broken_summary", [False, True])
def test_finalization_always_closes_stream_and_releases_lock(client, server, monkeypatch, broken_summary):
    import queue
    callbacks = []
    class Thread:
        def __init__(self, target, **kwargs): self.target = target
        def start(self): callbacks.append(self.target)
    class Process:
        exitcode = 0
        def __init__(self, target, args, **kwargs): self.args = args
        def start(self):
            run_id, req, q = self.args
            (Path(server.RUNS_DIR) / (run_id + ".json")).write_text(json.dumps({"transaction_hash": TX, "ranked_suspicious_functions": 1}))
            q.put(("end", None))
        def is_alive(self): return False
        def join(self, **kwargs): pass
    monkeypatch.setattr(server.threading, "Thread", Thread)
    monkeypatch.setattr(server.mp, "Process", Process)
    monkeypatch.setattr(server.mp, "Queue", queue.Queue)
    if broken_summary:
        monkeypatch.setattr(server, "_hist_brief", lambda res: (_ for _ in ()).throw(ValueError("summary failed")))
    response = client.post("/api/analyze", json={"txn_hash": TX, "mode": "no-llm"})
    run_id = response.json()["run_id"]
    if broken_summary:
        with pytest.raises(ValueError): callbacks.pop()()
    else:
        callbacks.pop()()
    assert not server.run_lock.locked()
    assert server.runs[run_id]["q"].closed


def test_worker_preserves_explicit_same_provider_stage_keys(server, monkeypatch):
    import queue
    from app.pipeline_guards import PipelineRuntime
    runtime = PipelineRuntime(TX, "eth")
    observed = []
    runtime.preflight = lambda *a, **k: observed.append(dict(runtime.model_keys))
    monkeypatch.setattr(server, "_prepare_pipeline", lambda *a: runtime)
    monkeypatch.setitem(sys.modules, "faultseeker.main", types.SimpleNamespace(main=lambda **k: {"transaction_hash": TX}))
    server.worker("split-keys", {"txn_hash": TX, "chain": "eth", "mode": "gpt-6.1-sol-low", "model_key": "main-dummy",
        "forensics_model": "gpt-6.1-sol-medium", "forensics_model_key": "stage-dummy"}, queue.Queue())
    assert observed == [{"gpt-6.1-sol-low": ["main-dummy"], "gpt-6.1-sol-medium": ["stage-dummy"]}]


def test_missing_capture_returns_not_found(client, server, monkeypatch, tmp_path):
    monkeypatch.setattr(server, "CAPTURE", str(tmp_path / "missing.json"))
    assert client.get("/api/capture").status_code == 404


def test_unicode_gate_input_is_not_a_server_error(client, server, monkeypatch):
    monkeypatch.setattr(server, "GATE", "dummy-access")
    assert client.post("/gate", data={"password": "wrong-\u00e9"}).status_code == 401



def test_adapter_preserves_explicit_classification_without_transaction_object(server):
    classification = {"rule_verdict": "CLEAN", "signals": {"profit_extraction_eth": 7}}
    value = server._adapt_result_for_view({"transaction_hash": TX, "analysis_status": "completed", "classification": classification})
    assert value["classification"] == classification
    value = server._adapt_result_for_view({"transaction_hash": TX, "analysis_status": "partial", "classification": classification})
    assert value["classification"]["rule_verdict"] == "INCONCLUSIVE"
