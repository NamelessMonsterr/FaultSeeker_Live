"""Inception protocol tests: dummy credentials and intercepted HTTP only."""
import copy
import json

import httpx
from openai import OpenAI
import pytest

from app.model_endpoint import ModelEndpointSession
from app.model_routes import adapt_request, resolve_route

MODEL = "inception/mercury-3"
BASE = "https://api.inceptionlabs.ai/v1"


def test_inception_route_uses_its_own_endpoint_and_credentials(monkeypatch):
    monkeypatch.delenv("INCEPTION_BASE_URL", raising=False)
    monkeypatch.setenv("OPENAI_DIRECT_BASE_URL", "https://other.invalid/v1")
    monkeypatch.setenv("ITERA_BASE_URL", "https://itera.invalid/v1")
    assert resolve_route(MODEL, "https://ignored.invalid/v1", "OPENAI_API_KEY") == (BASE, "INCEPTION_API_KEY")
    monkeypatch.setenv("INCEPTION_BASE_URL", "https://inception-fixture.invalid/v1")
    assert resolve_route(MODEL) == ("https://inception-fixture.invalid/v1", "INCEPTION_API_KEY")


@pytest.mark.parametrize("endpoint", ["https://user:password@model.invalid/v1", "file:///tmp/model", "https:///v1"])
def test_inception_rejects_invalid_operator_endpoints(monkeypatch, endpoint):
    monkeypatch.setenv("INCEPTION_BASE_URL", endpoint)
    with pytest.raises(ValueError):
        resolve_route(MODEL)


def test_inception_preserves_valid_explicit_options_without_mutating_request():
    request = {"model": MODEL, "temperature": 0.8, "max_completion_tokens": 1024,
               "reasoning_effort": "high", "messages": [{"role": "user", "content": "controlled"}]}
    original = copy.deepcopy(request)
    result = adapt_request(MODEL, request)
    assert result["model"] == "mercury-3"
    assert result["temperature"] == 0.8 and result["max_completion_tokens"] == 1024
    assert result["reasoning_effort"] == "high" and request == original


def test_inception_supports_documented_8192_reasoning_and_answer_budget():
    result = adapt_request(MODEL, {"model": MODEL, "max_completion_tokens": 8192})
    assert result["max_completion_tokens"] == 8192
    assert result["reasoning_effort"] == "low"


@pytest.mark.parametrize("options", [{"temperature": float("nan")}, {"temperature": 2},
    {"max_completion_tokens": 0}, {"max_completion_tokens": 999999},
    {"max_tokens": 10, "max_completion_tokens": 20}, {"reasoning_effort": "unsupported"}])
def test_inception_rejects_invalid_or_conflicting_options(options):
    with pytest.raises(ValueError):
        adapt_request(MODEL, {"model": MODEL, **options})


def test_unregistered_inception_model_is_not_silently_substituted():
    with pytest.raises(ValueError):
        adapt_request("inception/not-a-configured-model", {"temperature": 0})


def test_inception_preflight_and_analysis_use_documented_request_contract():
    requests, sdk_attempts = [], []
    def respond(request):
        requests.append(json.loads(request.content))
        sdk_attempts.append(request.headers.get("x-stainless-retry-count"))
        assert request.headers["authorization"] == "Bearer dummy-inception-key"
        return httpx.Response(200, json={"id": "mock", "object": "chat.completion", "created": 0,
            "model": "mercury-3", "choices": [{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "OK"}}]})
    def factory():
        client = OpenAI(api_key="dummy-inception-key", base_url=BASE,
                        http_client=httpx.Client(transport=httpx.MockTransport(respond)))
        return client
    session = ModelEndpointSession(retry_limit=0)
    session.preflight(factory, MODEL, timeout=20)
    session.call(factory, {"model": MODEL, "temperature": 0,
                          "messages": [{"role": "user", "content": "controlled analysis"}]}, MODEL)
    assert len(requests) == 2 and sdk_attempts == ["0", "0"]
    preflight, analysis = requests
    assert preflight["model"] == analysis["model"] == "mercury-3"
    assert preflight["temperature"] == analysis["temperature"] == 1
    assert preflight["reasoning_effort"] == "instant" and preflight["max_completion_tokens"] == 8
    assert analysis["reasoning_effort"] == "low" and analysis["max_completion_tokens"] == 24576
    assert all("max_tokens" not in row and "reasoning" not in row for row in requests)
    assert session.summary()["calls"] == {"preflight": {"ok": 1, "failed": 0}, "analysis": {"ok": 1, "failed": 0}}


def test_other_provider_parameters_remain_unchanged():
    request = {"model": "gpt-4o-mini", "temperature": 0, "max_tokens": 12}
    assert adapt_request("gpt-4o-mini", request) == request


def test_inception_normal_profile_and_timeout_isolation(monkeypatch):
    from app.model_routes import model_call_timeout
    for name in ("FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS", "FAULTSEEKER_LLM_TIMEOUT_SECS"):
        monkeypatch.delenv(name, raising=False)
    result = adapt_request(MODEL, {"temperature": 0})
    assert result["max_completion_tokens"] == 24576
    assert result["temperature"] == 1
    assert adapt_request(MODEL, {"temperature": 0.5})["temperature"] == 0.5
    assert model_call_timeout([MODEL]) == 120
    assert model_call_timeout(["gpt-6.1-sol-low"]) == 60
    assert model_call_timeout([MODEL, "itera/qwen3.8-27b"]) == 180
    monkeypatch.setenv("FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS", "45")
    assert model_call_timeout([MODEL]) == 45
