"""Itera route isolation, request adaptation, empty-answer failure and credential ownership. No network."""
import importlib
import json

import httpx
import pytest
from openai import OpenAI

ITERA = "itera/qwen3.8-27b"


def routes():
    return importlib.import_module("app.model_routes")


def test_itera_route_is_isolated_from_groq_sol_and_direct(monkeypatch):
    m = routes()
    for var in ("ITERA_BASE_URL", "GROQ_BASE_URL", "CODEX_PROXY_BASE_URL", "OPENAI_DIRECT_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("CODEX_PROXY_BASE_URL", "https://codex.example/v1")
    # Even a detected Groq/OpenAI provider URL cannot redirect the Itera model.
    endpoint, key_env = m.resolve_route(ITERA, "https://api.groq.com/openai/v1", "GROQ_API_KEY")
    assert endpoint == "https://api.iteracompute.com/v1" and key_env == "ITERA_API_KEY"
    endpoint, key_env = m.resolve_route(ITERA, "https://evil.example/v1", "OPENAI_API_KEY")
    assert endpoint == "https://api.iteracompute.com/v1" and key_env == "ITERA_API_KEY"
    # Groq qwen/ and Sol routes keep their own endpoint and credential.
    assert m.resolve_route("qwen/qwen3.8-27b", "https://api.groq.com/openai/v1", "GROQ_API_KEY") == \
        ("https://api.groq.com/openai/v1", "GROQ_API_KEY")
    assert m.resolve_route("gpt-6.1-sol-low", "https://api.openai.com/v1", "OPENAI_API_KEY") == \
        ("https://codex.example/v1", "OPENAI_API_KEY")


def test_itera_endpoint_override_is_operator_env_only_and_validated(monkeypatch):
    m = routes()
    monkeypatch.setenv("ITERA_BASE_URL", "https://api.example.test/v1")
    assert m.resolve_route(ITERA)[0] == "https://api.example.test/v1"
    monkeypatch.setenv("ITERA_BASE_URL", "https://user:pw@api.example.test/v1")
    with pytest.raises(ValueError):
        m.resolve_route(ITERA)


def test_adapt_request_rewrites_only_itera_and_disables_reasoning():
    m = routes()
    base = {"model": ITERA, "messages": [{"role": "user", "content": "x"}], "max_tokens": 5}
    out = m.adapt_request(ITERA, base)
    assert out["model"] == "qwen/qwen3.8-27b"
    assert out["extra_body"] == {"reasoning_effort": "none"}
    assert base["model"] == ITERA and "extra_body" not in base  # input is not mutated
    other = {"model": "qwen/qwen3.8-27b", "messages": []}
    assert m.adapt_request("qwen/qwen3.8-27b", other) is other
    sol = {"model": "gpt-6.1-sol-low", "messages": []}
    assert m.adapt_request("gpt-6.1-sol-low", sol) is sol
    keep = m.adapt_request(ITERA, {**base, "extra_body": {"x": 1}})
    assert keep["extra_body"] == {"x": 1, "reasoning_effort": "none"}


def session(responses, seen):
    mod = importlib.import_module("app.model_endpoint")
    queue = iter(responses)

    def handle(request):
        seen.append({"host": request.url.host, "auth": request.headers.get("authorization"),
                     "body": json.loads(request.content)})
        return next(queue)

    def factory():
        return OpenAI(api_key="client-default", base_url="https://api.iteracompute.com/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    s = mod.ModelEndpointSession(retry_limit=1, time_budget=30, call_timeout=5,
                                 sleep=lambda _x: None)
    s.model_routes[ITERA] = "https://api.iteracompute.com/v1"
    s.register_keys("https://api.iteracompute.com/v1", ["itera-key-1"], model=ITERA)
    return mod, s, factory


def ok(content, reasoning=0):
    return httpx.Response(200, json={"id": "m", "object": "chat.completion", "created": 0, "model": "qwen/qwen3.8-27b",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 7, "total_tokens": 17,
                  "completion_tokens_details": {"reasoning_tokens": reasoning}}})


def test_request_payload_credential_and_token_accounting():
    seen = []
    _m, s, factory = session([ok('["token"]')], seen)
    s.call(factory, {"model": ITERA, "messages": [{"role": "user", "content": "x"}], "max_tokens": 50}, ITERA)
    assert len(seen) == 1
    assert seen[0]["host"] == "api.iteracompute.com"
    assert seen[0]["auth"] == "Bearer itera-key-1"          # only the Itera key, never the SDK default
    assert seen[0]["body"]["model"] == "qwen/qwen3.8-27b"
    assert seen[0]["body"]["reasoning_effort"] == "none"
    assert s.summary()["tokens"] == {"prompt": 10, "completion": 7, "reasoning": 0}
    assert "itera-key-1" not in json.dumps(s.summary())


def test_empty_answer_is_a_failure_not_a_result():
    seen = []
    mod, s, factory = session([ok(""), ok("  ")], seen)
    with pytest.raises(mod.ModelEndpointFailure) as failure:
        s.call(factory, {"model": ITERA, "messages": [], "max_tokens": 50}, ITERA)
    assert failure.value.kind == "invalid_response"
    assert "itera-key-1" not in str(failure.value)


def test_itera_model_is_listed_with_its_own_credential_env():
    server_src = open("app/server.py", encoding="utf-8").read()
    assert '"id": "itera/qwen3.8-27b"' in server_src and '"keyEnv": "ITERA_API_KEY"' in server_src


def test_itera_budget_is_route_specific_and_bounded(monkeypatch):
    from app.pipeline_guards import model_time_budget
    for n in ("FAULTSEEKER_MODEL_TIME_BUDGET_SECS", "FAULTSEEKER_ITERA_TIME_BUDGET_SECS", "DEMO_RUN_TIMEOUT_SECS"):
        monkeypatch.delenv(n, raising=False)
    assert model_time_budget(("gpt-6.1-sol-low", None)) == 600
    assert model_time_budget(()) == 600
    assert model_time_budget(("itera/qwen3.8-27b",)) == 6000
    monkeypatch.setenv("FAULTSEEKER_ITERA_TIME_BUDGET_SECS", "999999")
    assert model_time_budget(("itera/qwen3.8-27b",)) == 6600
    monkeypatch.setenv("DEMO_RUN_TIMEOUT_SECS", "3000")
    assert model_time_budget(("itera/qwen3.8-27b",)) == 6000
    assert model_time_budget(("gpt-6.1-sol-low",)) == 600


def test_selftest_uses_adapted_payload(monkeypatch):
    import app.server as srv
    seen = {}
    class C:
        def __init__(self, **k): pass
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    seen.update(kw)
                    class M: content = "ok"
                    class Ch: message = M
                    class R: choices = [Ch]
                    return R
        def close(self): pass
    import sys, types
    stub = types.ModuleType("faultseeker.utils.agent")
    stub.PROVIDER_CONFIG = {}
    for name in ("faultseeker", "faultseeker.utils"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "faultseeker.utils.agent", stub)
    import openai
    monkeypatch.setattr(openai, "OpenAI", C)
    monkeypatch.setenv("ITERA_API_KEY", "k")
    out = srv.llm_selftest(model="itera/qwen3.8-27b")
    assert seen["model"] == "qwen/qwen3.8-27b"
    assert seen["extra_body"] == {"reasoning_effort": "none"}
    assert out["keys"][0]["ok"] is True
