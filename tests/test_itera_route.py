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
    assert out["extra_body"] == {"reasoning": False}
    assert base["model"] == ITERA and "extra_body" not in base  # input is not mutated
    other = {"model": "qwen/qwen3.8-27b", "messages": []}
    assert m.adapt_request("qwen/qwen3.8-27b", other) is other
    sol = {"model": "gpt-6.1-sol-low", "messages": []}
    assert m.adapt_request("gpt-6.1-sol-low", sol) is sol
    keep = m.adapt_request(ITERA, {**base, "extra_body": {"x": 1}})
    assert keep["extra_body"] == {"x": 1, "reasoning": False}


def session(responses, seen):
    mod = importlib.import_module("app.model_endpoint")
    queue = iter(responses)

    def handle(request):
        seen.append({"host": request.url.host, "auth": request.headers.get("authorization"),
                     "body": json.loads(request.content), "timeout": request.extensions["timeout"]})
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
    assert seen[0]["body"]["reasoning"] is False
    assert s.summary()["tokens"] == {"prompt": 10, "completion": 7, "reasoning": 0}
    assert "itera-key-1" not in json.dumps(s.summary())


def test_empty_answer_is_a_failure_not_a_result():
    seen = []
    mod, s, factory = session([ok(""), ok("  ")], seen)
    with pytest.raises(mod.ModelEndpointFailure) as failure:
        s.call(factory, {"model": ITERA, "messages": [], "max_tokens": 50}, ITERA)
    assert failure.value.kind == "invalid_response"
    assert "itera-key-1" not in str(failure.value)


def test_itera_http_payload_uses_documented_thinking_control():
    """Contract: https://iteracompute.com/docs.html, first free Qwen call.

    This checks serialized SDK HTTP, not provider availability or inference.
    """
    seen = []
    _m, s, factory = session([ok("Ready")], seen)
    s.preflight(factory, ITERA, timeout=5)
    assert seen[0]["body"].get("reasoning") is False
    assert "reasoning_effort" not in seen[0]["body"]


def test_per_model_timeout_reaches_sdk_http_without_extending_session():
    seen = []
    _m, s, factory = session([ok("Ready")], seen)
    s.model_timeouts[ITERA] = 3
    s.preflight(factory, ITERA, timeout=5)
    assert 0 < seen[0]["timeout"]["read"] <= 3
    assert s.call_timeout == 5


def test_itera_defaults_allow_documented_queue_and_generation(monkeypatch):
    from app.model_routes import model_call_timeout, model_preflight_timeout
    for name in ("FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS", "FAULTSEEKER_LLM_TIMEOUT_SECS",
                 "FAULTSEEKER_MODEL_PREFLIGHT_SECS"):
        monkeypatch.delenv(name, raising=False)
    assert model_call_timeout([ITERA]) == 180
    assert model_preflight_timeout([ITERA]) == 180
    assert model_call_timeout(["gpt-6.1-sol-low"]) == 60
    assert model_preflight_timeout(["gpt-6.1-sol-low"]) == 120
    monkeypatch.setenv("FAULTSEEKER_LLM_TIMEOUT_SECS", "90")
    assert model_call_timeout([ITERA]) == 90
    monkeypatch.setenv("FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS", "75")
    monkeypatch.setenv("FAULTSEEKER_MODEL_PREFLIGHT_SECS", "45")
    assert model_call_timeout([ITERA]) == 75
    assert model_preflight_timeout([ITERA]) == 45


def test_itera_runtime_uses_documented_timeout_without_resetting_shared_budget(monkeypatch):
    from app.pipeline_guards import PipelineRuntime, make_runtime
    for name in ("FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS", "FAULTSEEKER_LLM_TIMEOUT_SECS",
                 "FAULTSEEKER_MODEL_TIME_BUDGET_SECS", "FAULTSEEKER_ITERA_TIME_BUDGET_SECS",
                 "DEMO_RUN_TIMEOUT_SECS", "FAULTSEEKER_MODEL_RETRY_LIMIT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(PipelineRuntime, "install", lambda self: self)
    runtime = make_runtime("0x" + "0" * 64, "eth", True, lambda event: None, models=[ITERA])
    assert runtime.session.call_timeout == 180
    assert runtime.session.time_budget == 6000
    assert runtime.session.retries_left == 3


def test_mixed_runtime_preserves_each_models_attempt_allowance(monkeypatch):
    from app.pipeline_guards import PipelineRuntime, make_runtime
    for name in ("FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS", "FAULTSEEKER_LLM_TIMEOUT_SECS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(PipelineRuntime, "install", lambda self: self)
    runtime = make_runtime("0x" + "0" * 64, "eth", True, lambda event: None,
                           models=[ITERA, "gpt-6.1-sol-low"])
    assert runtime.session.model_timeouts == {ITERA: 180, "gpt-6.1-sol-low": 60}


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
    assert model_time_budget(("itera/qwen3.8-27b",)) == 2400
    assert model_time_budget(("gpt-6.1-sol-low",)) == 600


def test_selftest_uses_adapted_payload(monkeypatch):
    import app.server as srv
    seen = {}
    class C:
        def __init__(self, **k): seen['timeout'] = k.get('timeout')
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
    assert seen["extra_body"] == {"reasoning": False}
    assert out["keys"][0]["ok"] is True
    assert seen["timeout"] == 180
