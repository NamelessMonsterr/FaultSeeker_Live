"""Opt-in candidate-pipeline contract, separate from immutable Docker-pin tests.

Only controlled HTTP replies are used. Set an explicit local checkout and its
expected SHA; this does not establish real provider or forensic correctness.
"""
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys

import httpx
from openai import OpenAI
import pytest

from app.model_endpoint import ModelEndpointFailure, ModelEndpointSession
from app.pipeline_guards import PipelineRuntime

MODEL = "itera/qwen3.8-27b"
TX = "0x" + "a" * 64


def test_candidate_inception_agents_use_registered_cloud_policy_and_shared_transport(candidate, monkeypatch):
    model = "inception/mercury-3"
    monkeypatch.setenv("INCEPTION_API_KEY", "dummy-inception-key")
    monkeypatch.setenv("INCEPTION_BASE_URL", "https://inception-fixture.invalid/v1")
    requests = []
    def respond(request):
        assert str(request.url) == "https://inception-fixture.invalid/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer dummy-inception-key"
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"id": "mock", "object": "chat.completion", "created": 0,
            "model": "mercury-3", "choices": [{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "OK"}}]})
    def factory(**kwargs):
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(respond)))
    monkeypatch.setattr(candidate, "OpenAI", factory)
    monkeypatch.setattr(candidate, "chat", lambda **kwargs: pytest.fail("Inception was sent to Ollama"))
    runtime = PipelineRuntime(TX, "eth", session=ModelEndpointSession(retry_limit=0)).install()
    runtime.model_keys = {model: ["dummy-inception-key"]}
    try:
        runtime.preflight([model])
        analyzer = importlib.import_module("faultseeker.function_analysis.function_analyzer").FunctionAnalyzer(model=model)
        prompts = importlib.import_module("faultseeker.prompts.local_model_prompts")
        assert not prompts.is_local_model(model)
        assert type(analyzer.function_prompts) is prompts.WorkerPrompts
        for name in ("reasoning_agent", "generation_agent", "processing_agent", "organization_agent",
                     "children_call_filtering_agent", "agent"):
            instance = getattr(analyzer, name)
            assert isinstance(instance, candidate.UniversalAgent)
            assert instance.query("Controlled routing contract", format="str") == "OK"
        assert len(requests) == 7
        assert requests[0]["reasoning_effort"] == "instant"
        assert all(row["model"] == "mercury-3" and row["temperature"] == 0.5 for row in requests)
        assert all(row["reasoning_effort"] == "low" and row["max_completion_tokens"] == 8192 for row in requests[1:])
        assert runtime.session.summary()["calls"]["analysis"] == {"ok": 6, "failed": 0}
    finally:
        runtime.close()


@pytest.fixture
def candidate(monkeypatch, tmp_path):
    location = os.getenv("FAULTSEEKER_TEST_CANDIDATE_REPO")
    expected = os.getenv("FAULTSEEKER_TEST_CANDIDATE_SHA")
    if not location or not expected:
        pytest.skip("Candidate checkout/SHA not supplied; Docker-pin verification is a separate suite")
    actual = subprocess.check_output(["git", "-C", location, "rev-parse", "HEAD"], text=True).strip()
    assert actual == expected, "Candidate pipeline revision does not match the explicitly requested SHA"
    saved = {name: module for name, module in sys.modules.items()
             if name == "faultseeker" or name.startswith("faultseeker.")}
    for name in saved:
        sys.modules.pop(name)
    monkeypatch.syspath_prepend(str(Path(location).resolve()))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "true")
    monkeypatch.setenv("ITERA_API_KEY", "dummy-first,dummy-second")
    monkeypatch.setenv("OPENAI_API_KEY", "dummy-placeholder")
    monkeypatch.setenv("ITERA_BASE_URL", "https://candidate-model.invalid/v1")
    try:
        yield importlib.import_module("faultseeker.utils.agent")
    finally:
        for name in list(sys.modules):
            if name == "faultseeker" or name.startswith("faultseeker."):
                sys.modules.pop(name)
        sys.modules.update(saved)


def configured_runtime(agents, monkeypatch, statuses, *, supplied_keys=True, retry_limit=1, model=MODEL):
    seen, options, events = [], [], []
    statuses = iter(statuses)
    def respond(request):
        seen.append({"auth": request.headers["authorization"], "body": json.loads(request.content)})
        status = next(statuses, 200)
        if status != 200:
            return httpx.Response(status, text="PRIVATE_PROVIDER_BODY")
        return httpx.Response(200, json={"id": "mock", "object": "chat.completion", "created": 0,
            "model": "qwen/qwen3.8-27b" if model == MODEL else model, "choices": [{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "Ready"}}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}})
    def factory(**kwargs):
        options.append(kwargs.copy())
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(respond)))
    monkeypatch.setattr(agents, "OpenAI", factory)
    monkeypatch.setattr(agents, "chat", lambda **kwargs: pytest.fail("Cloud model was sent to Ollama"))
    session = ModelEndpointSession(retry_limit=retry_limit, time_budget=30, call_timeout=5,
                                   sleep=lambda _seconds: None, emit=events.append)
    runtime = PipelineRuntime(TX, "eth", session=session).install()
    if supplied_keys:
        # This is the actual worker path; it bypasses upstream key-list parsing.
        runtime.model_keys = {model: ["dummy-first", "dummy-second"]}
    return runtime, seen, options, events


def test_candidate_real_analyzer_analysis_uses_shared_transport(candidate, monkeypatch):
    runtime, seen, options, _events = configured_runtime(candidate, monkeypatch, [200, 200])
    try:
        runtime.preflight([MODEL], timeout=5)
        analyzer = importlib.import_module("faultseeker.function_analysis.function_analyzer").FunctionAnalyzer(model=MODEL)
        recorded = []
        analyzer.reasoning_agent._record_router_query = lambda *args, **kwargs: recorded.append((args, kwargs))
        assert analyzer.reasoning_agent.query("Controlled analysis", format="str") == "Ready"
        assert runtime.session.summary()["calls"] == {"preflight": {"ok": 1, "failed": 0},
                                                       "analysis": {"ok": 1, "failed": 0}}
        assert runtime.session.summary()["tokens"] == {"prompt": 4, "completion": 6, "reasoning": 0}
        assert len(seen) == 2
        assert all(row["body"]["model"] == "qwen/qwen3.8-27b" and row["body"]["reasoning"] is False for row in seen)
        assert all(row["auth"] == "Bearer dummy-first" for row in seen)
        assert all(option.get("max_retries") == 0 for option in options)
        assert recorded and recorded[0][1] == {"input_tokens": 2, "output_tokens": 3}
        assert analyzer.reasoning_agent.memory[-1] == {"role": "assistant", "content": "Ready"}
    finally:
        runtime.close()


@pytest.mark.parametrize("model,setting,endpoint,json_mode", [
    ("gpt-6.1-sol-low", "CODEX_PROXY_BASE_URL", "https://codex-fixture.invalid/v1", False),
    ("gpt-4o-mini", "OPENAI_DIRECT_BASE_URL", "https://direct-fixture.invalid/v1", True)])
def test_candidate_legacy_gpt_uses_selected_route_and_preserves_json_mode(candidate, monkeypatch, model, setting, endpoint, json_mode):
    monkeypatch.setenv(setting, endpoint)
    runtime, seen, options, _events = configured_runtime(candidate, monkeypatch, [200, 200], model=model)
    try:
        runtime.preflight([model], timeout=5)
        analyzer = importlib.import_module("faultseeker.function_analysis.function_analyzer").FunctionAnalyzer(model=model)
        assert analyzer.reasoning_agent.query("Controlled GPT analysis", format="str") == "Ready"
        assert runtime.session.summary()["calls"]["analysis"]["ok"] == 1
        assert all(option["base_url"] == endpoint and option["max_retries"] == 0 for option in options)
        assert seen[-1]["body"]["model"] == model
        assert seen[-1]["body"].get("response_format") == ({"type": "json_object"} if json_mode else None)
        assert "reasoning" not in seen[-1]["body"]
    finally:
        runtime.close()


@pytest.mark.parametrize("raw", ["dummy-first,dummy-second", "dummy-first\ndummy-second",
    "dummy-first;dummy-second", "ITERA_API_KEY=dummy-first ITERA_API_KEY_2=dummy-second",
    "IGNORED=not-a-key dummy-first dummy-second"])
def test_candidate_missing_upstream_key_parser_preserves_supported_key_lists(candidate, monkeypatch, raw):
    monkeypatch.setenv("ITERA_API_KEY", raw)
    runtime, seen, _options, _events = configured_runtime(candidate, monkeypatch, [401, 200], supplied_keys=False)
    try:
        runtime.preflight([MODEL], timeout=5)
        assert [row["auth"] for row in seen] == ["Bearer dummy-first", "Bearer dummy-second"]
    finally:
        runtime.close()


@pytest.mark.parametrize("supplied_keys", [False, True])
def test_candidate_preflight_rotation_survives_into_analysis(candidate, monkeypatch, supplied_keys):
    runtime, seen, _options, _events = configured_runtime(candidate, monkeypatch, [401, 200, 200], supplied_keys=supplied_keys)
    try:
        runtime.preflight([MODEL], timeout=5)
        analyzer = importlib.import_module("faultseeker.function_analysis.function_analyzer").FunctionAnalyzer(model=MODEL)
        assert analyzer.reasoning_agent.query("Controlled analysis", format="str") == "Ready"
        assert [row["auth"] for row in seen] == ["Bearer dummy-first", "Bearer dummy-second", "Bearer dummy-second"]
        assert runtime.session.summary()["calls"]["analysis"]["ok"] == 1
    finally:
        runtime.close()


@pytest.mark.parametrize("status,kind,analysis_attempts", [(502, "upstream_http", 2), (429, "rate_limited", 1)])
@pytest.mark.parametrize("output_format", ["str", "json"])
def test_candidate_mid_run_failure_is_latched_not_swallowed(candidate, monkeypatch, status, kind, analysis_attempts, output_format):
    runtime, seen, _options, events = configured_runtime(candidate, monkeypatch, [200, status, status])
    try:
        runtime.preflight([MODEL], timeout=5)
        analyzer = importlib.import_module("faultseeker.function_analysis.function_analyzer").FunctionAnalyzer(model=MODEL)
        with pytest.raises(ModelEndpointFailure) as failure:
            analyzer.reasoning_agent.query("Controlled analysis", format=output_format)
        assert failure.value.kind == kind
        assert runtime.session.summary()["calls"]["analysis"] == {"ok": 0, "failed": analysis_attempts}
        count = len(seen)
        with pytest.raises(ModelEndpointFailure):
            analyzer.generation_agent.query("No fresh retry ladder", format="str")
        assert len(seen) == count == 1 + analysis_attempts
        assert "PRIVATE_PROVIDER_BODY" not in str(failure.value)
        assert "dummy-first" not in json.dumps(events)
    finally:
        runtime.close()
