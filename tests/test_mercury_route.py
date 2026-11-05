"""Mercury 3 (Inception) route isolation, request adaptation and credential ownership. No network."""
import importlib
import json

import httpx
from openai import OpenAI

MERCURY = "mercury-3"


def routes():
    return importlib.import_module("app.model_routes")


def test_mercury_route_is_isolated_from_groq_itera_sol_and_direct(monkeypatch):
    m = routes()
    for var in ("INCEPTION_BASE_URL", "ITERA_BASE_URL", "GROQ_BASE_URL",
                "CODEX_PROXY_BASE_URL", "OPENAI_DIRECT_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("CODEX_PROXY_BASE_URL", "https://codex.example/v1")
    # Even a detected Groq/OpenAI provider URL cannot redirect the Mercury model.
    endpoint, key_env = m.resolve_route(MERCURY, "https://api.groq.com/openai/v1", "GROQ_API_KEY")
    assert endpoint == "https://api.inceptionlabs.ai/v1" and key_env == "INCEPTION_API_KEY"
    endpoint, key_env = m.resolve_route(MERCURY, "https://evil.example/v1", "OPENAI_API_KEY")
    assert endpoint == "https://api.inceptionlabs.ai/v1" and key_env == "INCEPTION_API_KEY"
    # Other routes keep their own endpoint and credential.
    assert m.resolve_route("itera/qwen3.8-27b", None, "ITERA_API_KEY") == \
        ("https://api.iteracompute.com/v1", "ITERA_API_KEY")
    assert m.resolve_route("gpt-6.1-sol-low", "https://api.openai.com/v1", "OPENAI_API_KEY") == \
        ("https://codex.example/v1", "OPENAI_API_KEY")


def test_mercury_endpoint_override_is_operator_env_only_and_validated(monkeypatch):
    m = routes()
    monkeypatch.setenv("INCEPTION_BASE_URL", "https://api.example.test/v1")
    assert m.resolve_route(MERCURY)[0] == "https://api.example.test/v1"
    monkeypatch.setenv("INCEPTION_BASE_URL", "https://user:pw@api.example.test/v1")
    import pytest
    with pytest.raises(ValueError):
        m.resolve_route(MERCURY)


def test_adapt_request_adds_reasoning_effort_only_for_mercury(monkeypatch):
    m = routes()
    monkeypatch.delenv("FAULTSEEKER_MERCURY_REASONING_EFFORT", raising=False)
    base = {"model": MERCURY, "messages": [{"role": "user", "content": "x"}], "max_tokens": 500}
    out = m.adapt_request(MERCURY, base)
    assert out["model"] == MERCURY  # exact model id is preserved
    assert out["extra_body"] == {"reasoning_effort": "medium"}
    assert "extra_body" not in base  # input is not mutated
    monkeypatch.setenv("FAULTSEEKER_MERCURY_REASONING_EFFORT", "low")
    out = m.adapt_request(MERCURY, base)
    assert out["extra_body"] == {"reasoning_effort": "low"}
    keep = m.adapt_request(MERCURY, {**base, "extra_body": {"x": 1}})
    assert keep["extra_body"] == {"x": 1, "reasoning_effort": "low"}
    # Tiny probes (the transport's preflight cap) skip reasoning and get a floor:
    # reasoning would spend the whole cap before any visible answer.
    tiny = m.adapt_request(MERCURY, {**base, "max_tokens": 8})
    assert tiny["max_tokens"] == 64
    assert tiny["extra_body"] == {"reasoning_effort": "instant"}
    # Mercury clamps temperature into its documented [0.5, 1.0] range instead of
    # letting the provider silently reset out-of-range values to 1.0.
    assert m.adapt_request(MERCURY, {**base, "temperature": 0})["temperature"] == 0.5
    assert m.adapt_request(MERCURY, {**base, "temperature": 0.7})["temperature"] == 0.7
    assert m.adapt_request(MERCURY, {**base, "temperature": 2})["temperature"] == 1.0
    assert "temperature" not in m.adapt_request(MERCURY, base)
    other = {"model": "qwen/qwen3.8-27b", "messages": []}
    assert m.adapt_request("qwen/qwen3.8-27b", other) is other


def session(responses, seen):
    mod = importlib.import_module("app.model_endpoint")
    queue = iter(responses)

    def handle(request):
        seen.append({"host": request.url.host, "auth": request.headers.get("authorization"),
                     "body": json.loads(request.content)})
        return next(queue)

    def factory():
        return OpenAI(api_key="client-default", base_url="https://api.inceptionlabs.ai/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    s = mod.ModelEndpointSession(retry_limit=1, time_budget=30, call_timeout=5,
                                 sleep=lambda _x: None)
    s.model_routes[MERCURY] = "https://api.inceptionlabs.ai/v1"
    s.register_keys("https://api.inceptionlabs.ai/v1", ["inception-key-1"], model=MERCURY)
    return mod, s, factory


def ok(content):
    return httpx.Response(200, json={"id": "m", "object": "chat.completion", "created": 0, "model": "mercury-3",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 9, "total_tokens": 21,
                  "completion_tokens_details": {"reasoning_tokens": 4}}})


def test_request_payload_credential_and_token_accounting(monkeypatch):
    monkeypatch.delenv("FAULTSEEKER_MERCURY_REASONING_EFFORT", raising=False)
    seen = []
    _m, s, factory = session([ok('["token"]')], seen)
    s.call(factory, {"model": MERCURY, "messages": [{"role": "user", "content": "x"}], "max_tokens": 500}, MERCURY)
    assert len(seen) == 1
    assert seen[0]["host"] == "api.inceptionlabs.ai"
    assert seen[0]["auth"] == "Bearer inception-key-1"  # only the Inception key, never the SDK default
    assert seen[0]["body"]["model"] == "mercury-3"
    assert seen[0]["body"]["reasoning_effort"] == "medium"
    assert s.summary()["tokens"] == {"prompt": 12, "completion": 9, "reasoning": 4}
    assert "inception-key-1" not in json.dumps(s.summary())


def test_mercury_model_is_listed_with_its_own_credential_env():
    server_src = open("app/server.py", encoding="utf-8").read()
    assert '"id": "mercury-3"' in server_src and '"keyEnv": "INCEPTION_API_KEY"' in server_src
