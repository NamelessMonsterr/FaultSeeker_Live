import os
import importlib
import json
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/fixtures/hedgey_verified_trace.json").read_text())
TX = FIXTURE["provenance"]["transaction_hash"]


def test_swallowed_model_error_is_rethrown_at_agent_boundary():
    m = importlib.import_module("app.pipeline_guards")
    endpoint = importlib.import_module("app.model_endpoint")
    session = endpoint.ModelEndpointSession()
    class Agent:
        def _send_message(self, *args, **kwargs):
            session.failure = endpoint.ModelEndpointFailure("upstream_http", 502)
            return "An error occurred."
    module = types.SimpleNamespace(GPTAgent=Agent, UniversalAgent=type("OtherAgent", (Agent,), {}))
    runtime = m.PipelineRuntime(TX, "eth", session=session)
    runtime.install_model_hooks(module)
    with pytest.raises(endpoint.ModelEndpointFailure):
        Agent()._send_message("input")


def test_mid_run_failure_produces_explicit_sections_and_no_successful_verdict():
    m = importlib.import_module("app.pipeline_guards")
    endpoint = importlib.import_module("app.model_endpoint")
    session = endpoint.ModelEndpointSession()
    runtime = m.PipelineRuntime(TX, "eth", session=session)
    runtime.partial = {"transaction": {"hash": TX, "chain": "eth"},
                       "classification": {"rule_verdict": "EXPLOIT", "rule_confidence": .85}}
    session.failure = endpoint.ModelEndpointFailure("upstream_http", 502)
    report = runtime.failure_report()
    assert report["analysis_status"] == "partial"
    assert report["sections"]["function_analysis"] == "failed"
    assert report["sections"]["scoring"] == "skipped"
    assert report["classification"]["rule_verdict"] == "INCONCLUSIVE"
    assert report["deterministic_rule_observation"]["rule_verdict"] == "EXPLOIT"


def test_failure_report_always_includes_analysis_integrity_and_wall_cap():
    m = importlib.import_module("app.pipeline_guards")
    endpoint = importlib.import_module("app.model_endpoint")
    runtime = m.PipelineRuntime(TX, "eth", session=endpoint.ModelEndpointSession())
    runtime.partial = {"transaction": {"hash": TX, "chain": "eth"},
                       "classification": {"rule_verdict": "EXPLOIT"}}
    runtime.wall_cap.add({"kind": "function", "function": "transfer@0xabc",
                          "outcome": "likely_forced", "detail": None,
                          "elapsed_wall_secs": 480.1, "elapsed_mono_secs": 480.1,
                          "completed_cycles": 0, "ceiling": 3})
    report = runtime.failure_report(RuntimeError("model failure"))
    assert report["analysis_integrity"]["failure_path"] is True
    assert report["analysis_integrity"]["trace_identity_checked"] is False
    assert report["analysis_integrity"]["unverified_targets"] is None
    assert report["analysis_integrity"]["target_validation"] == "not_assessed"
    assert report["analysis_integrity"]["function_analysis_complete"] is False
    assert report["analysis_integrity"]["function_wall_cap"]["likely_forced"] == 1
    assert report["analysis_integrity"]["model_analysis"]["analysis_calls_ok"] == 0
    assert report["failure"] == {"kind": "RuntimeError"}
    assert "model failure" not in json.dumps(report)


def test_failure_report_preserves_sanitized_model_failure_kind():
    m = importlib.import_module("app.pipeline_guards")
    endpoint = importlib.import_module("app.model_endpoint")
    runtime = m.PipelineRuntime(TX, "eth", session=endpoint.ModelEndpointSession())
    runtime.partial = {"transaction": {"hash": TX, "chain": "eth"}}
    report = runtime.failure_report(endpoint.ModelEndpointFailure("rate_limited", 429))
    assert report["failure"]["kind"] == "rate_limited"
    assert "ModelEndpointFailure" not in json.dumps(report["failure"])


def test_successful_model_run_cannot_validate_an_unobserved_function_label():
    m = importlib.import_module("app.pipeline_guards")
    identity = importlib.import_module("app.trace_identity")
    seq = identity.sequence_from_parity(FIXTURE["responses"]["trace_transaction"], TX, "eth")
    runtime = m.PipelineRuntime(TX, "eth")
    runtime.sequence = seq
    old = json.loads((ROOT / "app/samples/hedgey_e7c04c6fb037.result.json").read_text())
    report = runtime.annotate_result(old)
    assert report["analysis_status"] == "partial"
    assert report["analysis_integrity"]["unverified_targets"]
    assert "updateGhoBorrowRate" in report["analysis_integrity"]["unverified_targets"][0]
    assert report["classification"]["rule_verdict"] == "INCONCLUSIVE"


def test_selector_ranking_stays_on_the_observed_contract():
    m = importlib.import_module("app.pipeline_guards")
    identity = importlib.import_module("app.trace_identity")
    seq = identity.sequence_from_parity(FIXTURE["responses"]["trace_transaction"], TX, "eth")
    runtime = m.PipelineRuntime(TX, "eth")
    runtime.sequence = seq
    root = seq["trace"]
    value = runtime.annotate_result({"transaction_hash": TX, "chain": "eth", "analysis_status": "completed",
                                    "scored_functions": [{"address": root["address"], "function": root["function"]}]})
    assert value["analysis_integrity"]["unverified_targets"] == []
    assert value["analysis_integrity"]["abi_verified"] is False
    assert value["trace_provenance"]["transaction_hash"] == TX


def test_existing_structured_cache_rejects_wrong_chain_before_ranking():
    identity = importlib.import_module("app.trace_identity")
    with pytest.raises(identity.TraceIdentityError):
        identity.check_structured({"transaction_hash": TX, "chain": "bsc", "trace": {}}, TX, "eth")


def rotation_runtime(monkeypatch, statuses, retry_limit=3, budget=60, seconds=1):
    import httpx
    from openai import OpenAI
    from app.model_endpoint import ModelEndpointSession
    from app.pipeline_guards import PipelineRuntime
    now, calls, events = [0.0], [], []
    statuses = iter(statuses)
    def reply(request):
        calls.append(request.headers["authorization"])
        now[0] += seconds
        status = next(statuses)
        if status != 200:
            return httpx.Response(status, text="<html>PRIVATE_PROVIDER_BODY</html>")
        return httpx.Response(200, json={"id": "offline", "object": "chat.completion", "created": 0,
            "model": "gpt-6.1-sol-low", "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "OK"}}]})
    def factory(**kwargs):
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    monkeypatch.setenv("OPENAI_API_KEY", "test-first,test-second")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://model.invalid/v1")
    session = ModelEndpointSession(retry_limit=retry_limit, time_budget=budget,
        clock=lambda: now[0], sleep=lambda delay: now.__setitem__(0, now[0]+delay), emit=events.append)
    runtime = PipelineRuntime(TX, "eth", session=session)
    runtime.source = types.SimpleNamespace(OpenAI=factory, _parse_api_keys=lambda value: value.split(','),
        UniversalAgent=types.SimpleNamespace(_detect_provider=lambda model: ("https://model.invalid/v1", "OPENAI_API_KEY")))
    def query():
        return session.call(lambda: factory(api_key="test-first", base_url="https://model.invalid/v1"),
            {"model": "gpt-6.1-sol-low", "messages": []}, "gpt-6.1-sol-low")
    return runtime, calls, events, query


@pytest.mark.parametrize("first_status", [401, 403])
def test_preflight_rotates_key_specific_failures_and_keeps_valid_key(monkeypatch, first_status):
    runtime, calls, events, query = rotation_runtime(monkeypatch, [first_status, 200, 200])
    runtime.preflight(["gpt-6.1-sol-low"])
    query()  # Upstream factories may still seed the rejected first key.
    assert calls == ["Bearer test-first", "Bearer test-second", "Bearer test-second"]
    # Preflight rotation is bounded by the configured key count and no longer
    # consumes the shared analysis retry allowance.
    assert runtime.session.retries_left == 3
    assert runtime.session.failure is None
    assert "test-first" not in json.dumps(events)
    assert "PRIVATE_PROVIDER_BODY" not in json.dumps(events)


def test_preflight_429_is_terminal_without_rotation_or_backoff(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [429, 200, 200])
    with pytest.raises(ModelEndpointFailure) as failure:
        runtime.preflight(["gpt-6.1-sol-low"])
    assert failure.value.kind == "rate_limited"
    assert failure.value.phase == "preflight"
    assert failure.value.as_dict()["scope"] == "provider_limit"
    assert calls == ["Bearer test-first"]
    assert runtime.session.retries_left == 3
    # rotation_runtime advances its monotonic clock by one second per HTTP call;
    # the sole request is charged, but no retry/backoff sleep is performed.
    assert runtime.session.spent == 1.0
    assert not any(event.get("key_rotation") for event in events)
    assert not any(event.get("retry_in_seconds", 0) > 0 for event in events)
    with pytest.raises(ModelEndpointFailure) as sticky:
        query()
    assert sticky.value.kind == "rate_limited"
    assert calls == ["Bearer test-first"]
    assert "test-first" not in json.dumps(events)
    assert "PRIVATE_PROVIDER_BODY" not in json.dumps(events)


def test_all_keys_invalid_fails_once_without_another_ladder(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [401, 401])
    with pytest.raises(ModelEndpointFailure) as failure:
        runtime.preflight(["gpt-6.1-sol-low"])
    assert len(calls) == 2
    assert failure.value.kind == "authentication"
    assert failure.value.as_dict()["scope"] == "credential"
    with pytest.raises(ModelEndpointFailure):
        query()
    assert len(calls) == 2


def test_endpoint_outage_does_not_rotate_keys_or_reset_budget(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [502]*8, retry_limit=2)
    with pytest.raises(ModelEndpointFailure) as failure:
        runtime.preflight(["gpt-6.1-sol-low"])
    # Preflight retries a cold-starting endpoint until its 20s deadline
    # (attempts at t=0,2,5,10,15 in this 1s-per-call harness), never rotates.
    assert calls == ["Bearer test-first"]*5
    assert failure.value.kind == "upstream_http"
    assert failure.value.as_dict()["scope"] == "endpoint"
    with pytest.raises(ModelEndpointFailure):
        query()
    assert len(calls) == 5


def test_shared_retry_budget_survives_key_rotation_and_success(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [401, 200, 502, 502], retry_limit=1)
    runtime.preflight(["gpt-6.1-sol-low"])
    # Preflight rotation consumed nothing: analysis still has its full allowance.
    assert runtime.session.retries_left == 1
    with pytest.raises(ModelEndpointFailure):
        query()
    assert len(calls) == 4
    assert runtime.session.retries_left == 0
    assert runtime.session.spent == 5  # 4 one-second calls + 1s retry backoff


def test_shared_time_budget_survives_rotation(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [401, 200, 200], budget=5, seconds=2)
    runtime.preflight(["gpt-6.1-sol-low"])
    assert runtime.session.spent == 4
    with pytest.raises(ModelEndpointFailure) as failure:
        query()
    assert failure.value.kind == "budget_exhausted"
    assert len(calls) == 3 and runtime.session.spent == 6


def test_preflight_rotation_is_bounded_by_key_count_not_allowance(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    # Even with a zero analysis retry allowance, preflight may rotate through
    # the configured keys (bounded by key count) to find a working credential.
    runtime, calls, events, query = rotation_runtime(monkeypatch, [401, 200], retry_limit=0)
    runtime.preflight(["gpt-6.1-sol-low"])
    assert calls == ["Bearer test-first", "Bearer test-second"]
    assert runtime.session.retries_left == 0


def test_analysis_rotation_still_requires_shared_retry_allowance(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [200, 401], retry_limit=0)
    runtime.preflight(["gpt-6.1-sol-low"])
    with pytest.raises(ModelEndpointFailure):
        query()
    assert len(calls) == 2 and runtime.session.retries_left == 0


def test_preflight_deadline_is_not_restarted_by_key_rotation(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [401, 200], seconds=11)
    with pytest.raises(ModelEndpointFailure) as failure:
        runtime.preflight(["gpt-6.1-sol-low"], timeout=20)
    assert failure.value.kind == "request_deadline_exceeded"
    assert len(calls) == 2 and runtime.session.spent == 22
    assert runtime.session.failure is None


def test_second_model_cannot_start_after_shared_preflight_deadline(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [200, 200], seconds=20)
    with pytest.raises(ModelEndpointFailure) as failure:
        runtime.preflight(["gpt-6.1-sol-low", "gpt-6.1-sol-medium"], timeout=20)
    assert failure.value.kind == "request_deadline_exceeded"
    assert len(calls) == 1 and runtime.session.spent == 20


def test_rejected_findings_force_partial_even_with_valid_scored():
    m = importlib.import_module("app.pipeline_guards")
    identity = importlib.import_module("app.trace_identity")
    seq = identity.sequence_from_parity(FIXTURE["responses"]["trace_transaction"], TX, "eth")
    runtime = m.PipelineRuntime(TX, "eth")
    runtime.sequence = seq
    root = seq["trace"]
    valid = {"address": root["address"], "function": root["function"]}
    rejected = [{"key": "uniswapV3SwapCallback_0x00000000fdac7708d0d360bddc1bc7d097f47439",
                 "reason": "unbindable_target"},
                {"key": "transfer_0xdead000000000000000000000000000000000000",
                 "reason": "unbindable_target"}]
    report = runtime.annotate_result({
        "transaction_hash": TX, "chain": "eth", "analysis_status": "completed",
        "scored_functions": [valid], "rejected_findings": rejected})
    assert report["analysis_status"] == "partial"
    assert report["classification"]["rule_verdict"] == "INCONCLUSIVE"
    assert report["analysis_integrity"]["unverified_targets"] == []
    joined = " ".join(report["limitations"])
    assert "excluded from scoring" in joined
    assert "uniswapV3SwapCallback_0x0000" in joined
    # the valid finding stays scored; rejected keys never appear in scored output
    assert report["scored_functions"] == [valid]
    scored_text = json.dumps(report["scored_functions"])
    assert "uniswapV3SwapCallback" not in scored_text
    assert "0xdead" not in scored_text


def test_rejected_findings_only_still_partial():
    m = importlib.import_module("app.pipeline_guards")
    identity = importlib.import_module("app.trace_identity")
    seq = identity.sequence_from_parity(FIXTURE["responses"]["trace_transaction"], TX, "eth")
    runtime = m.PipelineRuntime(TX, "eth")
    runtime.sequence = seq
    report = runtime.annotate_result({
        "transaction_hash": TX, "chain": "eth", "analysis_status": "completed",
        "scored_functions": [],
        "rejected_findings": [{"key": "mint_0xbeef000000000000000000000000000000000000",
                               "reason": "unbindable_target"}]})
    assert report["analysis_status"] == "partial"
    assert report["classification"]["rule_verdict"] == "INCONCLUSIVE"
    assert any("excluded from scoring" in lim for lim in report["limitations"])


def test_empty_rejected_findings_changes_nothing():
    m = importlib.import_module("app.pipeline_guards")
    identity = importlib.import_module("app.trace_identity")
    seq = identity.sequence_from_parity(FIXTURE["responses"]["trace_transaction"], TX, "eth")
    runtime = m.PipelineRuntime(TX, "eth")
    runtime.sequence = seq
    root = seq["trace"]
    valid = {"address": root["address"], "function": root["function"]}
    base = {"transaction_hash": TX, "chain": "eth", "analysis_status": "completed",
            "scored_functions": [valid]}
    report = runtime.annotate_result({**base, "rejected_findings": []})
    assert "analysis_status" in report  # unchanged by the propagation path
    assert report["analysis_status"] == "completed"
    assert report["classification"] if "classification" in report else True
    assert not any("excluded from scoring" in lim for lim in report["limitations"])
    # non-dict entries are ignored too
    report2 = runtime.annotate_result({**base, "rejected_findings": ["junk", None, 42]})
    assert report2["analysis_status"] == "completed"


@pytest.mark.parametrize("modern,legacy,expected", [(None, "300", 300), ("90", "300", 90), (None, None, 60)])
def test_timeout_configuration_precedence(monkeypatch, modern, legacy, expected):
    from app.pipeline_guards import PipelineRuntime, make_runtime
    for name, value in [("FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS", modern), ("FAULTSEEKER_LLM_TIMEOUT_SECS", legacy)]:
        monkeypatch.delenv(name, raising=False)
        if value is not None:
            monkeypatch.setenv(name, value)
    monkeypatch.setattr(PipelineRuntime, "install", lambda self: self)
    assert make_runtime(TX, "eth", True, lambda event: None).session.call_timeout == expected


def test_split_stage_keys_reach_actual_mocked_transport(monkeypatch):
    runtime, calls, _, _ = rotation_runtime(monkeypatch, [200, 200])
    runtime.model_keys = {"gpt-6.1-sol-low": ["function-key"], "gpt-6.1-sol-medium": ["forensics-key"]}
    runtime.preflight(list(runtime.model_keys))
    assert calls == ["Bearer function-key", "Bearer forensics-key"]



def test_model_routes_never_send_direct_credentials_to_codex_proxy(monkeypatch):
    import httpx
    from openai import OpenAI
    from app.model_endpoint import ModelEndpointSession
    from app.pipeline_guards import PipelineRuntime
    monkeypatch.setenv("CODEX_PROXY_BASE_URL", "https://proxy.invalid/v1")
    monkeypatch.setenv("OPENAI_DIRECT_BASE_URL", "https://direct.invalid/v1")
    observed = []
    def reply(request):
        observed.append((request.url.host, request.headers["authorization"]))
        return httpx.Response(200, json={"id":"offline","object":"chat.completion","created":0,"model":"test",
            "choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}]})
    def factory(**kwargs):
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    runtime = PipelineRuntime(TX, "eth", session=ModelEndpointSession())
    runtime.source = types.SimpleNamespace(OpenAI=factory, _parse_api_keys=lambda v: v.split(','),
        UniversalAgent=types.SimpleNamespace(_detect_provider=lambda m: (None, "OPENAI_API_KEY")))
    runtime.model_keys = {"gpt-6.1-sol-low": ["proxy-key"], "gpt-4o-mini": ["direct-key"]}
    runtime.preflight(list(runtime.model_keys))
    # Simulate a legacy agent constructing its client with the wrong default route/key.
    runtime.session.call(lambda: factory(api_key="proxy-key", base_url="https://proxy.invalid/v1"),
        {"model":"gpt-4o-mini", "messages":[]}, "gpt-4o-mini")
    assert observed == [("proxy.invalid", "Bearer proxy-key"), ("direct.invalid", "Bearer direct-key"), ("direct.invalid", "Bearer direct-key")]


def test_unconfigured_direct_route_fails_without_using_proxy(monkeypatch):
    from app.model_routes import resolve_route
    monkeypatch.setenv("OPENAI_BASE_URL", "https://proxy.invalid/v1")
    monkeypatch.delenv("OPENAI_DIRECT_BASE_URL", raising=False)
    with pytest.raises(ValueError, match="OPENAI_DIRECT_BASE_URL"):
        resolve_route("gpt-4o-mini")



def test_implicit_openai_model_cannot_escape_routing_policy(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, _, _ = rotation_runtime(monkeypatch, [200])
    runtime.preflight(["gpt-6.1-sol-low"])
    monkeypatch.delenv("OPENAI_DIRECT_BASE_URL", raising=False)
    with pytest.raises(ModelEndpointFailure):
        runtime.session.call(lambda: (_ for _ in ()).throw(AssertionError("Factory must not be used")),
            {"model":"gpt-4o-mini","messages":[]}, "gpt-4o-mini")
    assert len(calls) == 1


@pytest.fixture
def pinned_fork(monkeypatch, tmp_path):
    """Independent pinned-fork sys.path; does not rely on other tests having imported faultseeker."""
    import subprocess
    from pathlib import Path
    location = os.getenv("FAULTSEEKER_TEST_PIPELINE_REPO")
    if not location:
        pytest.skip("Exact pinned pipeline unavailable: set FAULTSEEKER_TEST_PIPELINE_REPO")
    root = Path(__file__).resolve().parents[1]
    pin = next(l.split("=", 1)[1] for l in (root / "Dockerfile").read_text().splitlines() if l.startswith("ARG FAULTSEEKER_SHA="))
    assert subprocess.check_output(["git", "-C", location, "rev-parse", "HEAD"], text=True).strip() == pin
    monkeypatch.syspath_prepend(location)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "true")
    return location


def _annotated(calls, fa_completed=1, **extra):
    from types import SimpleNamespace
    m = importlib.import_module("app.pipeline_guards")
    identity = importlib.import_module("app.trace_identity")
    seq = identity.sequence_from_parity(FIXTURE["responses"]["trace_transaction"], TX, "eth")
    runtime = m.PipelineRuntime(TX, "eth")
    runtime.sequence = seq
    runtime.function_analysis = {"started": fa_completed, "completed": fa_completed}
    runtime.session = SimpleNamespace(summary=lambda: {"calls": calls, "tokens": {}}, assert_healthy=lambda: None)
    base = {"transaction_hash": TX, "chain": "eth", "analysis_status": "completed",
            "priority_score": 0.85, "limitations": []}
    return runtime.annotate_result({**base, **extra})


def test_no_analysis_completion_is_partial_and_score_labelled_heuristic():
    r = _annotated({"preflight": {"ok": 1, "failed": 0}, "analysis": {"ok": 0, "failed": 4}})
    assert r["analysis_status"] == "partial"
    assert r["priority_basis"] == "heuristic_preanalysis_estimate"
    assert r["sections"]["function_analysis"] == "no_model_analysis"
    assert r["stage_completed"] == "deterministic-checks"


def test_model_calls_ok_but_function_analysis_unobserved_is_not_stage3():
    r = _annotated({"preflight": {"ok": 1, "failed": 0}, "analysis": {"ok": 3, "failed": 0}}, fa_completed=0)
    assert r["analysis_status"] == "partial"
    assert r["stage_completed"] == "forensics-only" != "stage-3"
    assert r["sections"]["function_analysis"] == "not_observed"
    assert r["priority_basis"] == "heuristic_preanalysis_estimate"


def test_legitimate_empty_model_result_is_preserved():
    r = _annotated({"preflight": {"ok": 1, "failed": 0}, "analysis": {"ok": 6, "failed": 0}})
    assert r["analysis_status"] == "completed"
    assert r["stage_completed"] == "stage-3"
    assert r["priority_basis"] == "heuristic_preanalysis_estimate"


def test_itera_alias_routes_to_openai_compatible_agent_not_ollama(pinned_fork, monkeypatch):
    monkeypatch.setenv("ITERA_API_KEY", "test-key-not-real")
    import sys
    agent = importlib.import_module("faultseeker.utils.agent")
    m = importlib.import_module("app.pipeline_guards")
    runtime = m.PipelineRuntime(TX, "eth")
    from types import SimpleNamespace
    runtime.session = SimpleNamespace(call=lambda *a, **k: "", route_policy=None, summary=lambda: {})
    runtime.install_model_hooks(agent)
    try:
        assert isinstance(agent.build_provider_agent("t", "itera/qwen3.8-27b"), agent.UniversalAgent)
    finally:
        runtime.close()


def test_provider_config_restored_even_when_run_raises(pinned_fork, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setenv("ITERA_API_KEY", "test-key-not-real")
    agent = importlib.import_module("faultseeker.utils.agent")
    m = importlib.import_module("app.pipeline_guards")
    before = agent.PROVIDER_CONFIG
    runtime = m.PipelineRuntime(TX, "eth")
    runtime.session = SimpleNamespace(call=lambda *a, **k: "", route_policy=None, summary=lambda: {})
    try:
        runtime.install_model_hooks(agent)
        assert "itera/" in agent.PROVIDER_CONFIG
        raise RuntimeError("run failed")
    except RuntimeError:
        pass
    finally:
        runtime.close()
    assert agent.PROVIDER_CONFIG is before and "itera/" not in agent.PROVIDER_CONFIG


@pytest.mark.parametrize("status,expect_status,expect_ok", [(200, "partial", 1), (400, "partial", 0)])
def test_offline_fixture_real_factory_hook_phase_and_status_path(pinned_fork, monkeypatch, status, expect_status, expect_ok):
    """SYNTHETIC OFFLINE FIXTURE: proves routing/hook/phase/status wiring only. Not model quality, not live chain proof."""
    from app.model_endpoint import ModelEndpointSession
    agent = importlib.import_module("faultseeker.utils.agent")
    m = importlib.import_module("app.pipeline_guards")
    identity = importlib.import_module("app.trace_identity")
    import httpx, json as _json
    from openai import OpenAI
    seen = []
    def reply(request):
        seen.append({"auth": request.headers.get("authorization"), "body": _json.loads(request.content)})
        if status != 200:
            return httpx.Response(status, text="x")
        return httpx.Response(200, json={"id": "fx", "object": "chat.completion", "created": 0, "model": "m",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "{}"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
    def factory(**kwargs):
        kwargs.pop("http_client", None)
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    monkeypatch.setattr(agent, "OpenAI", factory)
    if True:
        monkeypatch.setenv("ITERA_BASE_URL", "https://itera-fixture.invalid/v1")
        monkeypatch.setenv("ITERA_API_KEY", "fixture-key-not-real")
        session = ModelEndpointSession(retry_limit=0, time_budget=30, call_timeout=5)
        runtime = m.PipelineRuntime(TX, "eth", session=session)
        runtime.source = agent
        runtime.sequence = identity.sequence_from_parity(FIXTURE["responses"]["trace_transaction"], TX, "eth")
        before = agent.PROVIDER_CONFIG
        try:
            runtime.install_model_hooks(agent)
            ag = agent.build_provider_agent("fixture task", "itera/qwen3.8-27b")
            assert isinstance(ag, agent.UniversalAgent)
            try:
                ag.query("Return JSON.")
            except Exception:
                pass
        finally:
            result = None
            if status == 200 or session.failure is None:
                result = runtime.annotate_result({"transaction_hash": TX, "chain": "eth", "analysis_status": "completed",
                                                  "priority_score": 0.85, "limitations": []})
            runtime.close()
        assert agent.PROVIDER_CONFIG is before
        assert seen and seen[0]["auth"] == "Bearer fixture-key-not-real"
        assert seen[0]["body"]["extra_body"]["reasoning_effort"] == "none" if "extra_body" in seen[0]["body"] else seen[0]["body"].get("reasoning_effort") == "none"
        assert session.summary()["calls"]["analysis"]["ok"] == expect_ok
        if result is not None:
            if expect_ok:
                assert result["analysis_status"] == expect_status
                assert result["priority_basis"] == "heuristic_preanalysis_estimate"  # FunctionAnalyzer never ran in this fixture: stage coverage unobserved
                assert result["stage_completed"] == "forensics-only"
            else:
                assert result["analysis_status"] == expect_status
