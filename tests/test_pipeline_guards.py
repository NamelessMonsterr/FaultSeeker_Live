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


@pytest.mark.parametrize("first_status", [401, 403, 429])
def test_preflight_rotates_key_specific_failures_and_keeps_valid_key(monkeypatch, first_status):
    runtime, calls, events, query = rotation_runtime(monkeypatch, [first_status, 200, 200])
    runtime.preflight(["gpt-6.1-sol-low"])
    query()  # Upstream factories may still seed the rejected first key.
    assert calls == ["Bearer test-first", "Bearer test-second", "Bearer test-second"]
    assert runtime.session.retries_left == 2
    assert runtime.session.failure is None
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
    runtime, calls, events, query = rotation_runtime(monkeypatch, [502]*3, retry_limit=2)
    with pytest.raises(ModelEndpointFailure) as failure:
        runtime.preflight(["gpt-6.1-sol-low"])
    assert calls == ["Bearer test-first"]*3
    assert failure.value.as_dict()["scope"] == "endpoint"
    with pytest.raises(ModelEndpointFailure):
        query()
    assert len(calls) == 3


def test_shared_retry_budget_survives_key_rotation_and_success(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [401, 200, 502], retry_limit=1)
    runtime.preflight(["gpt-6.1-sol-low"])
    assert runtime.session.retries_left == 0
    with pytest.raises(ModelEndpointFailure):
        query()
    assert len(calls) == 3
    assert runtime.session.retries_left == 0
    assert runtime.session.spent == 3


def test_shared_time_budget_survives_rotation(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [401, 200, 200], budget=5, seconds=2)
    runtime.preflight(["gpt-6.1-sol-low"])
    assert runtime.session.spent == 4
    with pytest.raises(ModelEndpointFailure) as failure:
        query()
    assert failure.value.kind == "budget_exhausted"
    assert len(calls) == 3 and runtime.session.spent == 6


def test_rotation_requires_remaining_shared_retry_allowance(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [401], retry_limit=0)
    with pytest.raises(ModelEndpointFailure):
        runtime.preflight(["gpt-6.1-sol-low"])
    assert len(calls) == 1 and runtime.session.retries_left == 0


def test_preflight_deadline_is_not_restarted_by_key_rotation(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [401, 200], seconds=11)
    with pytest.raises(ModelEndpointFailure) as failure:
        runtime.preflight(["gpt-6.1-sol-low"], timeout=20)
    assert failure.value.kind == "budget_exhausted"
    assert len(calls) == 2 and runtime.session.spent == 22


def test_second_model_cannot_start_after_shared_preflight_deadline(monkeypatch):
    from app.model_endpoint import ModelEndpointFailure
    runtime, calls, events, query = rotation_runtime(monkeypatch, [200, 200], seconds=20)
    with pytest.raises(ModelEndpointFailure) as failure:
        runtime.preflight(["gpt-6.1-sol-low", "gpt-6.1-sol"], timeout=20)
    assert failure.value.kind == "budget_exhausted"
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
