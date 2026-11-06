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


def test_worker_persists_safe_failure_location_and_no_local_values(server, monkeypatch):
    import queue
    from app.pipeline_guards import PipelineRuntime
    runtime = PipelineRuntime(TX, 'eth')
    runtime.partial = {'transaction': {'hash': TX, 'chain': 'eth'}}
    def fail(**kwargs):
        private_value = 'DUMMY_PRIVATE_VALUE'
        raise IndexError(private_value)
    monkeypatch.setattr(server, '_prepare_pipeline', lambda *args: runtime)
    monkeypatch.setitem(sys.modules, 'faultseeker.main', types.SimpleNamespace(main=fail))
    events = queue.Queue()
    server.worker('diagnosticcase', {'txn_hash': TX, 'chain': 'eth', 'mode': 'no-llm',
                                     'model_key': 'DUMMY_PRIVATE_VALUE'}, events)
    report = json.loads((Path(server.RUNS_DIR)/'diagnosticcase.json').read_text())
    diagnostic = report['analysis_integrity']['failure_diagnostics']
    assert diagnostic['frames'][-1]['function'] == 'fail'
    assert diagnostic['frames'][-1]['file'] == 'test_server.py'
    assert 'DUMMY_PRIVATE_VALUE' not in json.dumps(report)
    assert any(event == 'diagnostic' for event, _ in list(events.queue))


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
    monkeypatch.setattr(module, "GATE", "test-only-gate")
    monkeypatch.setenv("OPENAI_DIRECT_BASE_URL", "https://direct.invalid/v1")
    monkeypatch.setattr(module, "RUNS_DIR", str(tmp_path))
    monkeypatch.setattr(module, "HISTORY_PATH", str(tmp_path / "index.json"))
    return module


@pytest.fixture
def client(server):
    class Client:
        def request(self, method, path, **kwargs):
            kwargs.setdefault("headers", {}).setdefault("cookie", "fs_gate=" + server._gate_token())
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
    assert client.get("/api/source-selftest").status_code == 429


class _FakeResp:
    def __init__(self, payload):
        self.payload = payload
    def read(self):
        return self.payload
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


class _FakeEndpoint:
    def __init__(self, base_url, key_env, has_key, circuit=False):
        self.base_url = base_url
        self.api_key_env = key_env
        self.has_configured_key = has_key
        self.is_circuit_open = circuit
        self.api_key = "dummy-secret" if has_key else ""
    def build_url(self, params):
        assert params["action"] == "getsourcecode"
        return f"{self.base_url}?apikey={self.api_key}&chain_id=1"


class _FakeRegistry:
    def __init__(self, endpoints):
        self._endpoints = endpoints
    def sorted_endpoints(self, chain):
        return self._endpoints


def _fake_explorer(monkeypatch, endpoints):
    parent = types.ModuleType("faultseeker")
    utils = types.ModuleType("faultseeker.utils")
    explorer = types.ModuleType("faultseeker.utils.explorer_provider")
    explorer._canonical = lambda chain: chain
    explorer._registry = _FakeRegistry(endpoints)
    explorer._endpoint_label = lambda url: url.split("//", 1)[-1].split("/")[0]
    parent.utils, utils.explorer_provider = utils, explorer
    for name, module in [("faultseeker", parent), ("faultseeker.utils", utils),
                         ("faultseeker.utils.explorer_provider", explorer)]:
        monkeypatch.setitem(sys.modules, name, module)


def test_source_selftest_reports_key_gating_and_never_leaks_secret(client, server, monkeypatch):
    _fake_explorer(monkeypatch, [
        _FakeEndpoint("https://unkeyed.invalid/v2/api", "ETHERSCAN_API_KEY", False),
        _FakeEndpoint("https://keyed.invalid/v2/api", "BLOCKSCOUT_API_KEY", True),
    ])
    seen = {}
    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        return _FakeResp(json.dumps({"status": "1", "message": "OK",
            "result": [{"SourceCode": "contract Dummy {}", "ContractName": "WETH9"}]}).encode())
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    response = client.get("/api/source-selftest")
    assert response.status_code == 200
    body = response.json()
    assert body["endpoints"][0]["key_configured"] is False
    assert body["endpoints"][0]["skipped"] == "no key configured"
    assert body["endpoints"][1]["ok"] is True
    assert body["endpoints"][1]["source_bytes"] == len("contract Dummy {}")
    assert body["endpoints"][1]["contract_name"] == "WETH9"
    assert "dummy-secret" not in response.text
    assert "apikey" not in response.text


def test_source_selftest_surfaces_api_failure_without_source_body(client, server, monkeypatch):
    _fake_explorer(monkeypatch, [
        _FakeEndpoint("https://keyed.invalid/v2/api", "BLOCKSCOUT_API_KEY", True),
    ])
    def fake_urlopen(req, timeout=None):
        return _FakeResp(json.dumps({"status": "0", "message": "NOTOK",
            "result": "Max rate limit reached"}).encode())
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    response = client.get("/api/source-selftest")
    body = response.json()
    assert body["endpoints"][0]["ok"] is False
    assert body["endpoints"][0]["api_status"] == "0"
    assert body["endpoints"][0]["source_bytes"] == 0


def test_source_selftest_rejects_non_account_address(client, server, monkeypatch):
    _fake_explorer(monkeypatch, [_FakeEndpoint("https://keyed.invalid/v2/api", "K", True)])
    assert client.get("/api/source-selftest?address=not-an-address").status_code == 400


def test_container_builds_from_unified_repository_without_cloning():
    dockerfile = (ROOT.parent / "Dockerfile").read_text()
    assert "git clone" not in dockerfile
    assert "COPY faultseeker faultseeker" in dockerfile
    assert "COPY console/app" in dockerfile


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



def test_gate_is_required_even_when_not_configured(client, server, monkeypatch):
    monkeypatch.setattr(server, "GATE", "")
    assert client.get("/api/config").status_code == 503
    assert client.post("/api/analyze", json={"txn_hash": TX}).status_code == 503
    assert client.get("/healthz").status_code == 200


def test_gate_rejects_unauthenticated_and_throttles_guesses(client, server):
    assert client.get("/api/runs", headers={"cookie": ""}).status_code == 401
    for _ in range(10):
        assert client.post("/gate", data={"password": "wrong"}).status_code == 401
    assert client.post("/gate", data={"password": "wrong"}).status_code == 429


def test_quota_tracking_expires_and_never_evicts_live_limits(server, monkeypatch):
    monkeypatch.setattr(server, "LIMIT_MAX_IPS", 2)
    store = {}
    assert server._consume_quota(store, "one", 0, [(10, 1)])
    assert server._consume_quota(store, "two", 0, [(10, 1)])
    assert not server._consume_quota(store, "three", 1, [(10, 1)])
    assert not server._consume_quota(store, "one", 1, [(10, 1)])
    assert len(store) == 2
    assert server._consume_quota(store, "three", 11, [(10, 1)])
    assert list(store) == ["three"]


def test_invalid_requests_still_count_as_requests_by_existing_policy(client):
    for _ in range(10):
        assert client.post("/api/analyze", json={"txn_hash": "invalid"}).status_code == 400
    assert client.post("/api/analyze", json={"txn_hash": TX}).status_code == 429


def test_redaction_preserves_descriptive_keys_and_nested_secrets(server):
    value = {"authorization_checks": "missing", "secret_extraction_evidence": "observed",
             "password_reset_event": "seen", "providerApiKey": "dummy-hidden",
             "headers": {"Authorization": "short-token"}, "client_secret": "dummy-hidden",
             "evidence": "contains known-dummy-key"}
    redacted = server._redact(value, ["known-dummy-key"])
    for key in ("authorization_checks", "secret_extraction_evidence", "password_reset_event"):
        assert redacted[key] == value[key]
    assert redacted["providerApiKey"] == "***"
    assert redacted["headers"]["Authorization"] == "***"
    assert "dummy-hidden" not in json.dumps(redacted)
    assert "known-dummy-key" not in json.dumps(redacted)


def test_dead_worker_cannot_be_changed_to_cancelled(client, server):
    import threading
    server.runs["finished"] = {"status": "running", "proc": types.SimpleNamespace(is_alive=lambda: False),
        "q": server.RunBus(), "cancel": threading.Event()}
    result = client.post("/api/cancel/finished").json()
    assert result["cancelled"] is False
    assert server.runs["finished"]["status"] == "running"
    assert not server.runs["finished"]["cancel"].is_set()


def test_dead_worker_guard_recovers_checkpoint_before_history_and_result(client, server, monkeypatch):
    import queue
    from app.analysis_checkpoint import save_checkpoint
    callbacks = []
    class Thread:
        def __init__(self, target, **kwargs): self.target = target
        def start(self): callbacks.append(self.target)
    class Process:
        exitcode = 23
        def __init__(self, target, args, **kwargs): self.args = args
        def start(self):
            rid, req, events = self.args
            save_checkpoint(server.RUNS_DIR, rid, {'transaction_hash': TX,
                'analysis_status': 'partial', 'sections': {'scoring': 'skipped'},
                'preliminary_findings': [{'target': 'controlled_target', 'status': 'unranked/unverified',
                                         'evidence': ['completed before abrupt exit']}]}, redact=lambda v:v)
        def is_alive(self): return False
        def join(self, **kwargs): pass
    monkeypatch.setattr(server.threading, 'Thread', Thread)
    monkeypatch.setattr(server.mp, 'Process', Process)
    monkeypatch.setattr(server.mp, 'Queue', queue.Queue)
    monkeypatch.setattr(server, '_gh_hist_sync', lambda *args: None)
    response = client.post('/api/analyze', json={'txn_hash': TX})
    assert response.status_code == 200
    rid = response.json()['run_id']
    callbacks.pop(0)()
    assert server.runs[rid]['status'] == 'died'
    assert not server.run_lock.locked()
    recovered = client.get('/api/result/'+rid)
    assert recovered.status_code == 200
    assert recovered.json()['analysis_status'] == 'partial'
    assert recovered.json()['classification']['rule_verdict'] == 'INCONCLUSIVE'
    assert recovered.json()['preliminary_findings'][0]['target'] == 'controlled_target'
    assert server._hist_load()[-1]['status'] == 'died'


def test_completion_event_wins_over_late_cancel(client, server):
    import threading
    server.runs["finishing"] = {"status": "running", "finishing": True,
        "proc": types.SimpleNamespace(is_alive=lambda: True), "q": server.RunBus(), "cancel": threading.Event()}
    assert client.post("/api/cancel/finishing").json()["cancelled"] is False
    assert not server.runs["finishing"]["cancel"].is_set()


def test_history_restart_reconciles_persisted_running_entries(client, server):
    server._hist_save([{"run_id": "old", "status": "running"}])
    server._reconcile_history()
    assert server._hist_load()[0]["status"] == "interrupted"
    assert client.get("/api/runs").json()["runs"][0]["status"] == "interrupted"


def test_import_never_fetches_remote_history(monkeypatch, tmp_path):
    import urllib.request
    calls = []
    def denied(*a, **k):
        calls.append(True)
        raise AssertionError("Unexpected network")
    monkeypatch.setattr(urllib.request, "urlopen", denied)
    monkeypatch.setenv("GITHUB_HISTORY_TOKEN", "dummy-token")
    monkeypatch.setenv("FAULTSEEKER_RUNS_DIR", str(tmp_path / "new"))
    spec = importlib.util.spec_from_file_location("history_import_probe", ROOT / "app/server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert calls == []


def test_startup_schedules_history_without_waiting(server, monkeypatch):
    scheduled = []
    class Thread:
        def __init__(self, target, **kwargs): scheduled.append(target)
        def start(self): pass
    monkeypatch.setattr(server, "GH_HISTORY_TOKEN", "dummy-token")
    monkeypatch.setattr(server, "_history_repo_private", lambda **kwargs: True)
    monkeypatch.setattr(server.threading, "Thread", Thread)
    async def start():
        async with server.lifespan(server.app):
            assert scheduled == [server._gh_hist_seed]
    asyncio.run(start())


def test_history_restore_has_overall_budget(server, monkeypatch):
    clock, calls = [0.0], []
    monkeypatch.setattr(server, "GH_HISTORY_TOKEN", "dummy-token")
    monkeypatch.setattr(server, "_history_repo_private", lambda **kwargs: True)
    monkeypatch.setattr(server.time, "monotonic", lambda: clock[0])
    def fetch(path, timeout):
        calls.append((path, timeout))
        clock[0] += 15
        if path == "index.json":
            return json.dumps([{"run_id": "one"}, {"run_id": "two"}]).encode()
        return b'{"result":{"transaction_hash":"dummy"}}'
    monkeypatch.setattr(server, "_gh_hist_get", fetch)
    server._gh_hist_seed()
    assert len(calls) == 2
    assert calls[1][1] == 15
    assert clock[0] == 30


def test_history_restore_validates_ids_redacts_and_preserves_newer_local_entries(server, monkeypatch):
    monkeypatch.setattr(server, "GH_HISTORY_TOKEN", "dummy-token")
    monkeypatch.setattr(server, "_history_repo_private", lambda **kwargs: True)
    calls = []
    def fetch(path, timeout):
        calls.append(path)
        if path == "index.json":
            server._hist_save([{"run_id": "live", "status": "completed"}])
            return json.dumps([{"run_id": "../escape", "status": "running"}, {"run_id": "restored", "status": "running"}]).encode()
        if path.endswith(".events.jsonl"): return b'{"ev":"log","data":{"api_key":"dummy-hidden"}}'
        return b'{"result":{"api_key":"dummy-hidden"}}'
    monkeypatch.setattr(server, "_gh_hist_get", fetch)
    server._gh_hist_seed()
    assert all(".." not in path for path in calls)
    states = {e["run_id"]:e["status"] for e in server._hist_load()}
    assert states == {"live":"completed", "restored":"interrupted"}
    assert "dummy-hidden" not in (Path(server.RUNS_DIR) / "restored.json").read_text()


def test_unsupported_fallback_is_not_silently_ignored(client):
    assert client.post("/api/analyze", json={"txn_hash": TX, "fallback_model": "another-model"}).status_code == 400
    assert client.post("/api/analyze", json={"txn_hash": TX, "stage2_workers": 5}).status_code == 400


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://169.254.169.254/", "http://[::1]/", "http://10.1.1.1/"])
def test_private_literal_rpc_rejected_before_worker_start(client, url):
    assert client.post("/api/analyze", json={"txn_hash": TX, "rpc_url": url}).status_code == 400


def test_direct_model_diagnostic_requires_separate_endpoint(server, monkeypatch):
    monkeypatch.delenv("OPENAI_DIRECT_BASE_URL", raising=False)
    monkeypatch.setenv("OPENAI_BASE_URL", "https://proxy.invalid/v1")
    monkeypatch.setitem(sys.modules, "faultseeker.utils.agent", types.SimpleNamespace(PROVIDER_CONFIG={}))
    result = server.llm_selftest(model="gpt-4o-mini", keys="dummy-key")
    assert "OPENAI_DIRECT_BASE_URL" in result["error"]



def test_worker_routes_visitor_rpc_through_guarded_relay(server, monkeypatch):
    import os, queue
    from app.pipeline_guards import PipelineRuntime
    observed, closed = [], []
    class Relay:
        def __init__(self, endpoint): observed.append(endpoint)
        def start(self): return "http://127.0.0.1:12345/private-relay-route"
        def close(self): closed.append(True)
    def main(**kwargs):
        observed.append(os.environ["ETH_RPC_URL"])
        return {"transaction_hash": TX}
    monkeypatch.setattr(server, "PublicRPCRelay", Relay)
    monkeypatch.setattr(server, "_prepare_pipeline", lambda *a: PipelineRuntime(TX,"eth"))
    monkeypatch.setitem(sys.modules, "faultseeker.main", types.SimpleNamespace(main=main))
    server.worker("relay", {"txn_hash":TX,"chain":"eth","mode":"no-llm","rpc_url":"https://rpc.invalid/v1"}, queue.Queue())
    assert observed == ["https://rpc.invalid/v1", "http://127.0.0.1:12345/private-relay-route"]
    assert closed == [True]



@pytest.mark.parametrize("visibility", [True, False, None])
def test_history_mirror_requires_verified_private_repository(server, monkeypatch, visibility):
    import io, urllib.request
    monkeypatch.setattr(server, "GH_HISTORY_TOKEN", "dummy-token")
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: io.BytesIO(json.dumps({"private":visibility}).encode()))
    assert server._history_repo_private() is (visibility is True)


def test_history_visibility_check_fails_closed(server, monkeypatch):
    import urllib.request
    monkeypatch.setattr(server, "GH_HISTORY_TOKEN", "dummy-token")
    def unavailable(*args, **kwargs): raise OSError("offline")
    monkeypatch.setattr(urllib.request, "urlopen", unavailable)
    assert server._history_repo_private() is False


@pytest.mark.parametrize("failed_resource", ["runtime", "relay"])
def test_worker_restores_environment_and_ends_when_cleanup_fails(server, monkeypatch, failed_resource):
    import os, queue
    from app.pipeline_guards import PipelineRuntime
    closed = []
    class Runtime(PipelineRuntime):
        def close(self):
            closed.append("runtime")
            if failed_resource == "runtime": raise RuntimeError("dummy cleanup failure")
    class Relay:
        def __init__(self, endpoint): pass
        def start(self): return "http://127.0.0.1:12345/dummy-route"
        def close(self):
            closed.append("relay")
            if failed_resource == "relay": raise RuntimeError("dummy cleanup failure")
    monkeypatch.setenv("ETH_RPC_URL", "https://original.invalid")
    monkeypatch.setattr(server, "PublicRPCRelay", Relay)
    monkeypatch.setattr(server, "_prepare_pipeline", lambda *a: Runtime(TX, "eth"))
    monkeypatch.setitem(sys.modules, "faultseeker.main", types.SimpleNamespace(main=lambda **kw: {"transaction_hash": TX}))
    before = (sys.stdout, sys.stderr)
    events = queue.Queue()
    server.worker("cleanup", {"txn_hash": TX, "chain": "eth", "mode": "no-llm", "rpc_url": "https://rpc.invalid"}, events)
    assert closed == ["runtime", "relay"]
    assert os.environ["ETH_RPC_URL"] == "https://original.invalid"
    assert (sys.stdout, sys.stderr) == before
    emitted = list(events.queue)
    assert ("log", "Worker resource cleanup failed.") in emitted
    assert emitted[-1] == ("end", None)


@pytest.mark.parametrize("field", ["api_keys", "providerApiKeys", "model_keys", "rpc_keys", "secrets", "passwords", "secretKey", "secret_token", "authorization_header", "private_keys", "access_tokens", "refresh_tokens"])
def test_redaction_masks_credential_collections_and_common_forms(server, field):
    assert server._redact({field: ["unknown-dummy-credential"]}) == {field: "***"}


@pytest.mark.parametrize("stubborn", [False, True])
def test_queue_failure_reaps_worker_before_releasing_lock(client, server, monkeypatch, stubborn):
    processes = []
    cleanup = []
    class DeferredThread:
        def __init__(self, target, **kwargs):
            self.target = target
        def start(self):
            with pytest.raises(OSError, match="controlled queue failure"):
                self.target()
    class Process:
        exitcode = None
        alive = True
        def __init__(self, **kwargs):
            processes.append(self)
        def start(self):
            pass
        def is_alive(self):
            return self.alive
        def terminate(self):
            cleanup.append(("terminate", server.run_lock.locked()))
            self.alive = stubborn
        def kill(self):
            cleanup.append(("kill", server.run_lock.locked()))
            self.alive = stubborn
        def join(self, **kwargs):
            cleanup.append(("join", server.run_lock.locked()))
    class BrokenQueue:
        def get(self, **kwargs):
            raise OSError("controlled queue failure")
    monkeypatch.setattr(server, "threading", types.SimpleNamespace(**{**vars(server.threading), "Thread": DeferredThread}))
    monkeypatch.setattr(server.mp, "Process", Process)
    monkeypatch.setattr(server.mp, "Queue", BrokenQueue)
    monkeypatch.setattr(server, "_gh_hist_sync", lambda *args: None)
    response = client.post("/api/analyze", json={"txn_hash": TX})
    assert response.status_code == 200
    assert processes[0].is_alive() is stubborn
    assert any(name == "join" for name, locked in cleanup)
    assert all(locked for name, locked in cleanup)
    assert server.run_lock.locked() is stubborn


@pytest.mark.parametrize("status", ["partial", "failed", "cancelled", "inconclusive"])
def test_nested_partial_report_never_keeps_normal_verdict(server, status):
    report = {"transaction": {"hash": TX}, "classification": {"rule_verdict": "EXPLOIT", "rule_confidence": 0.9}, "analysis_status": status}
    result = server._adapt_result_for_view(report)
    assert result["classification"]["rule_verdict"] == "INCONCLUSIVE"
    assert report["classification"]["rule_verdict"] == "EXPLOIT"
    assert result["analysis_status"] == status


def test_selftest_rejects_query_keys_and_accepts_post_body(client, server, monkeypatch):
    seen = []
    monkeypatch.setattr(server, "llm_selftest", lambda **kwargs: seen.append(kwargs) or {"ok": True})
    response = client.get("/api/llm-selftest?keys=dummy-private")
    assert response.status_code == 400
    assert "dummy-private" not in response.text
    assert not seen
    response = client.post("/api/llm-selftest", json={"model": "gpt-4o-mini", "keys": "dummy-private", "max_keys": 1})
    assert response.status_code == 200
    assert seen == [{"model": "gpt-4o-mini", "keys": "dummy-private", "max_keys": 1, "replay": ""}]


def test_copied_gate_cookie_expires_on_server(client, server, monkeypatch):
    monkeypatch.setattr(server.time, "time", lambda: 1000000)
    token = server._gate_token()
    monkeypatch.setattr(server.time, "time", lambda: 1000000 + 7 * 24 * 3600)
    assert client.get("/api/config", headers={"cookie": "fs_gate=" + token}).status_code == 401


def test_gate_cookie_cannot_be_reissued_with_forged_timestamp(client, server, monkeypatch):
    token = server._gate_token()
    tampered = "9999999999." + token.split(".")[-1]
    assert client.get("/api/config", headers={"cookie": "fs_gate=" + tampered}).status_code == 401


@pytest.mark.parametrize("initial,event_size", [(1999990, 100), (0, 2000000)])
def test_event_log_append_cannot_cross_byte_cap(server, initial, event_size):
    path = Path(server.RUNS_DIR) / "bounded.events.jsonl"
    path.write_bytes(b" " * initial)
    server._hist_log_event("bounded", "log", "x" * event_size)
    assert path.stat().st_size == initial


def test_event_log_under_cap_preserves_complete_json_line(server):
    server._hist_log_event("bounded", "log", "small event")
    path = Path(server.RUNS_DIR) / "bounded.events.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["data"] == "small event"


def test_finished_run_retention_preserves_active_and_latest_twenty(server):
    for index in range(30):
        server.runs[f"done{index}"] = {"status": "completed"}
    server.runs["active"] = {"status": "running"}
    server.runs["cancelling"] = {"status": "cancelling"}
    server._prune_finished_runs()
    assert list(server.runs) == [f"done{i}" for i in range(10, 30)] + ["active", "cancelling"]


def test_successful_replay_requests_apply_stream_retention(client, server, monkeypatch, tmp_path):
    events = tmp_path / "sample.events.jsonl"
    events.write_text(json.dumps({"t": 0, "ev": "log", "data": "recorded"}) + "\n")
    result = tmp_path / "sample.json"
    result.write_text(json.dumps({"transaction_hash": TX, "scored_functions": []}))
    monkeypatch.setattr(server, "DEMO_REPLAYS", {"demo:test": {"txn_hash": TX, "chain": "eth", "events": str(events), "result": str(result)}})
    monkeypatch.setattr(server, "RUN_LIMIT_PER_HOUR", 100)
    monkeypatch.setattr(server, "RUN_LIMIT_PER_DAY", 100)
    class InlineThread:
        def __init__(self, target, **kwargs):
            self.target = target
        def start(self):
            self.target()
    monkeypatch.setattr(server, "threading", types.SimpleNamespace(**{**vars(server.threading), "Thread": InlineThread}))
    ids = []
    for _ in range(25):
        response = client.post("/api/analyze", json={"txn_hash": "demo:test"})
        assert response.status_code == 200
        ids.append(response.json()["run_id"])
    assert list(server.runs) == ids[-20:]
    assert all(state["q"].closed for state in server.runs.values())
    assert not server.run_lock.locked()
    assert (tmp_path / (ids[0] + ".json")).exists()
