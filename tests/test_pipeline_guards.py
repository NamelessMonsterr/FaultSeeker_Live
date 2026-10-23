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
