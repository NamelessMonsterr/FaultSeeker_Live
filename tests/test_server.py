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
