"""Opt-in offline integration against the exact Docker-pinned external checkout.

Set FAULTSEEKER_TEST_PIPELINE_REPO to a checkout at the pinned SHA. HTTPX model
requests are mocked; RPC responses come only from the verified trace fixture.
"""
import copy
import importlib
import json
import os
from pathlib import Path
import subprocess

import httpx
import pytest
from openai import OpenAI

from app.model_endpoint import ModelEndpointFailure, ModelEndpointSession
from app.pipeline_guards import PipelineRuntime
from app.trace_identity import TraceIdentityError, sequence_from_parity

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/fixtures/hedgey_verified_trace.json").read_text())
TX = FIXTURE["provenance"]["transaction_hash"]
MODEL = "gpt-6.1-sol-low"
PIN = next(line.split("=", 1)[1] for line in (ROOT / "Dockerfile").read_text().splitlines()
           if line.startswith("ARG FAULTSEEKER_SHA="))


@pytest.fixture
def pinned(monkeypatch, tmp_path):
    location = os.getenv("FAULTSEEKER_TEST_PIPELINE_REPO")
    if not location:
        pytest.skip("Set FAULTSEEKER_TEST_PIPELINE_REPO for pinned-pipeline integration")
    assert subprocess.check_output(["git", "-C", location, "rev-parse", "HEAD"], text=True).strip() == PIN
    monkeypatch.syspath_prepend(location)
    monkeypatch.chdir(tmp_path)  # The upstream logger opens ./logs with filemode=w.
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "true")
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://model.invalid/v1")
    monkeypatch.setenv("FAULTSEEKER_LLM_FALLBACK_MODEL", "")
    def blocked(*args, **kwargs):
        raise AssertionError("Unmocked network access is forbidden")
    import urllib.request
    import requests
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(requests.sessions.Session, "request", blocked)
    return location


def test_real_agents_share_one_failure_budget_and_cannot_swallow_502(pinned, monkeypatch):
    agents = importlib.import_module("faultseeker.utils.agent")
    calls = []
    def factory(**kwargs):
        def reply(request):
            calls.append(json.loads(request.content))
            return httpx.Response(502, text="<html>PRIVATE_SERVER_BODY</html>")
        return OpenAI(api_key="test-only-key", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    monkeypatch.setattr(agents, "OpenAI", factory)
    session = ModelEndpointSession(retry_limit=1, sleep=lambda seconds: None)
    runtime = PipelineRuntime(TX, "eth", session=session).install()
    try:
        one = agents.GPTAgent("test", MODEL)
        two = agents.UniversalAgent("test", MODEL)
        for instance in [one, two]:
            with pytest.raises(ModelEndpointFailure) as failure:
                instance._send_message("No real provider is called")
            assert "PRIVATE_SERVER_BODY" not in str(failure.value)
        assert len(calls) == 2  # second agent does NOT start its own seven attempts
        assert all(row["model"] == MODEL for row in calls)
    finally:
        runtime.close()


def test_real_sequence_and_ranker_use_verified_calldata_not_cast_label(pinned, monkeypatch):
    seq_module = importlib.import_module("faultseeker.data_collection.txn_sequencer")
    replay_module = importlib.import_module("faultseeker.data_collection.txn_replayer")
    rpc = importlib.import_module("faultseeker.utils.rpc_provider")
    identity = sequence_from_parity(FIXTURE["responses"]["trace_transaction"], TX, "eth")
    structured = {"transaction_hash": TX, "chain": "eth", "trace": identity["canonical_trace"]}
    monkeypatch.setattr(replay_module.TransactionReplayer, "get_structured_trace", lambda *args: copy.deepcopy(structured))
    monkeypatch.setattr(replay_module.TransactionReplayer, "run", lambda *args: "untrusted decoder boundary")
    old = json.loads((ROOT / "app/samples/hedgey_e7c04c6fb037.result.json").read_text())
    legacy = copy.deepcopy(identity["trace"])
    legacy["function"] = old["scored_functions"][0]["function"]  # actual observed bad label
    monkeypatch.setattr(seq_module.TransactionSequencer, "analyze_trace", lambda *args: copy.deepcopy(legacy))
    monkeypatch.setattr(rpc, "rpc_call", lambda chain, method, params, **kwargs: "0x1" if method == "eth_chainId" else FIXTURE["responses"]["eth_getTransactionByHash"])
    runtime = PipelineRuntime(TX, "eth").install()
    try:
        sequence = seq_module.TransactionSequencer().run(TX, "eth")
        assert sequence["trace"]["function"] == "0xe32a9a37"
        assert "updateGhoBorrowRate" not in json.dumps(sequence)
        trace_module = importlib.import_module("faultseeker.forensics.trace_analyzer")
        monkeypatch.setattr(trace_module, "build_agent", lambda *args: None)  # flattening never queries this agent
        analysis = trace_module.TraceAnalyzer(sequence, {}, model="offline-no-llm").run()
        result_cls = importlib.import_module("faultseeker.forensics.result").ForensicsResult
        forensics = result_cls(transaction_hash=TX, chain="eth", functions_to_be_inspected={"function_name_with_hash": [analysis["flatten_trace"][0]]})
        ranker = importlib.import_module("faultseeker.function_analysis.function_ranker").FunctionRanker()
        ranked = ranker.rank(forensics, analysis)
        assert list(ranked.functions_to_be_inspected) == ["0xe32a9a37_0xc793113f1548b97e37c409f39244ee44241bf2b3"]
    finally:
        runtime.close()


def test_real_cache_identity_guard_rejects_wrong_chain(pinned, monkeypatch):
    replay = importlib.import_module("faultseeker.data_collection.txn_replayer").TransactionReplayer
    monkeypatch.setattr(replay, "get_structured_trace", lambda *args: {"transaction_hash": TX, "chain": "bsc", "trace": {}})
    runtime = PipelineRuntime(TX, "eth").install()
    try:
        with pytest.raises(TraceIdentityError):
            replay().get_structured_trace(TX, "eth")
    finally:
        runtime.close()


@pytest.mark.parametrize("statuses,expected", [
    ([401, 200, 200, 200], ["first", "second", "second", "second"]),
    ([403, 200, 200, 200], ["first", "second", "second", "second"]),
    ([429, 200, 200, 200], ["first", "second", "second", "second"]),
    ([200, 429, 200, 200], ["first", "first", "second", "second"]),
])
def test_real_agents_keep_preflight_rotation_and_rotate_mid_run(pinned, monkeypatch, statuses, expected):
    agents = importlib.import_module("faultseeker.utils.agent")
    monkeypatch.setenv("OPENAI_API_KEY", "test-first,test-second")
    calls, events = [], []
    statuses_initial = statuses
    statuses = iter(statuses)
    def factory(**kwargs):
        def reply(request):
            calls.append(request.headers["authorization"])
            status = next(statuses)
            if status != 200:
                return httpx.Response(status, text="PRIVATE_PROVIDER_BODY")
            return httpx.Response(200, json={"id": "offline", "object": "chat.completion", "created": 0,
                "model": MODEL, "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "OK"}}]})
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    monkeypatch.setattr(agents, "OpenAI", factory)
    session = ModelEndpointSession(retry_limit=2, emit=events.append)
    runtime = PipelineRuntime(TX, "eth", session=session).install()
    try:
        runtime.preflight([MODEL])
        for agent_class in (agents.GPTAgent, agents.UniversalAgent):
            assert agent_class("offline", MODEL)._send_message("Mocked request") == "OK"
        assert calls == ["Bearer test-"+key for key in expected]
        assert session.retries_left == (1 if statuses_initial[0] == 200 else 2)
        assert session.failure is None
        assert "test-first" not in json.dumps(events)
        assert "PRIVATE_PROVIDER_BODY" not in json.dumps(events)
    finally:
        runtime.close()
