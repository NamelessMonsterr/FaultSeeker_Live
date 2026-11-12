"""Provider registry and agent routing.

OFFLINE: every endpoint is either a value that is only parsed, or a local fake server (tests/fake_provider.py) bound to
127.0.0.1. No real provider is contacted and no real key is used.
"""
import json

import pytest

pytest.importorskip("openai")

from faultseeker import providers  # noqa: E402
from faultseeker.utils import utils  # noqa: E402
from tests.conftest import CLEARED_ENV  # noqa: E402
from tests.fake_provider import FakeProvider  # noqa: E402

CODEX_KEY, MERCURY_KEY, OPENAI_KEY = "codex-secret-" + "c" * 20, "mercury-secret-" + "m" * 20, "sk-openai-" + "o" * 24


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in CLEARED_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FAULTSEEKER_ISOLATED_RUN", "1")      # no .env loading, like a server-started worker


def write_registry(tmp_path, data):
    path = tmp_path / "models.json"
    path.write_text(json.dumps(data))
    return path


def agent_for(monkeypatch, model_id, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return utils.build_agent("system prompt", model_id)


# ---- registry file ------------------------------------------------------------------------------------
def test_shipped_registry_has_no_secrets_and_no_invented_endpoints():
    text = (providers.DEFAULT_MODELS_FILE).read_text()
    data = json.loads(text)
    assert set(data["providers"]) == {"openai", "ollama", "codex_proxy", "mercury"}
    assert "sk-" not in text and "Bearer" not in text
    for pid in ("codex_proxy", "mercury"):
        p = data["providers"][pid]
        assert "base_url" not in p and p["base_url_env"] and p["api_key_env"], "endpoints come from the environment"
    for mid in ("codex-proxy", "mercury"):
        m = next(m for m in data["models"] if m["id"] == mid)
        assert "model" not in m and m["model_env"], "exact model IDs come from the environment"
    assert data["providers"]["openai"]["base_url"] == "https://api.openai.com/v1"


def test_each_model_names_its_provider_and_nothing_is_guessed_from_the_name(tmp_path):
    reg = providers.Registry.load(write_registry(tmp_path, {
        "providers": {"acme": {"type": "openai_compatible", "base_url": "http://127.0.0.1:1/v1", "api_key_env": "ACME_KEY"},
                      "ollama": {"type": "ollama"}},
        "models": [{"id": "gpt-lookalike", "provider": "acme", "model": "gpt-lookalike"},
                   {"id": "llama-lookalike", "provider": "acme", "model": "Llama/Case-Sensitive:1"}]}))
    assert reg.resolve("gpt-lookalike", {}).provider.id == "acme"          # a gpt* name does not mean OpenAI
    assert reg.resolve("llama-lookalike", {}).provider.id == "acme"        # a non-gpt name does not mean Ollama
    assert reg.resolve("llama-lookalike", {}).model_id == "Llama/Case-Sensitive:1"   # exact ID, case preserved
    with pytest.raises(providers.ProviderConfigError, match="not in the provider registry"):
        reg.resolve("gpt-something-else", {})
    with pytest.raises(providers.ProviderConfigError, match="not in the provider registry"):
        reg.resolve("llama3", {})                                           # no implicit Ollama fallback
    assert reg.resolve("ollama:llama3", {}).provider.id == "ollama"        # explicit provider syntax works


@pytest.mark.parametrize("data,match", [
    ({"providers": {"p": {"type": "weird"}}, "models": []}, "type must be one of"),
    ({"providers": {"p": {"type": "openai_compatible"}}, "models": []}, "needs base_url"),
    ({"providers": {"p": {"type": "openai_compatible", "base_url": "http://x/v1", "key_validation": "magic"}}, "models": []}, "key_validation"),
    ({"providers": {"p": {"type": "ollama"}}, "models": [{"id": "m", "provider": "nope", "model": "x"}]}, "unknown provider"),
    ({"providers": {"p": {"type": "ollama"}}, "models": [{"id": "m", "provider": "p"}]}, "model_env"),
    ({"providers": {"p": {"type": "ollama"}}, "models": [{"id": "m", "provider": "p", "model": "x", "params": {"stream": True}}]}, "unsupported params"),
    ({"providers": {"p": {"type": "ollama"}}, "models": [{"id": "m", "provider": "p", "model": "x"}, {"id": "M", "provider": "p", "model": "y"}]}, "Duplicate"),
])
def test_bad_registry_files_fail_loudly(tmp_path, data, match):
    with pytest.raises(providers.ProviderConfigError, match=match):
        providers.Registry.load(write_registry(tmp_path, data))


def test_invalid_json_and_missing_file_are_reported(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    with pytest.raises(providers.ProviderConfigError, match="not valid JSON"):
        providers.Registry.load(bad)
    with pytest.raises(providers.ProviderConfigError, match="Cannot read"):
        providers.Registry.load(tmp_path / "missing.json")


def test_unconfigured_models_say_which_variable_is_missing_never_a_value(monkeypatch):
    reg = providers.load_registry()
    reasons = {s.id: r for s, r in reg.availability({})}
    assert reasons["gpt-4o"] is None
    assert "CODEX_PROXY_MODEL" in reasons["codex-proxy"] and "MERCURY_MODEL" in reasons["mercury"]
    env = {"CODEX_PROXY_MODEL": "exact-id"}
    assert "CODEX_PROXY_BASE_URL" in dict((s.id, r) for s, r in reg.availability(env))["codex-proxy"]
    env["CODEX_PROXY_BASE_URL"] = "ftp://nope"
    assert "http" in dict((s.id, r) for s, r in reg.availability(env))["codex-proxy"]


def test_enabled_models_come_from_one_source_and_can_be_filtered(monkeypatch):
    reg = providers.load_registry()
    env = {"CODEX_PROXY_BASE_URL": "http://127.0.0.1:1/v1", "CODEX_PROXY_MODEL": "m1", "MERCURY_BASE_URL": "https://x/v1", "MERCURY_MODEL": "m2"}
    assert [m.id for m in reg.enabled(env)] == ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "gpt-4.1", "codex-proxy", "mercury"]
    assert [m.id for m in reg.enabled({**env, "FAULTSEEKER_ENABLED_MODELS": "mercury, gpt-4o"})] == ["mercury", "gpt-4o"]
    assert [m.id for m in reg.enabled({"FAULTSEEKER_ENABLED_MODELS": "mercury"})] == [], "enabled but unconfigured stays hidden"
    with pytest.raises(providers.ProviderConfigError, match="unknown models"):
        reg.enabled({"FAULTSEEKER_ENABLED_MODELS": "typo-model"})


def test_parameter_policies_are_explicit():
    reg = providers.load_registry()
    base = {"CODEX_PROXY_BASE_URL": "http://h/v1", "CODEX_PROXY_MODEL": "m"}
    assert reg.resolve("gpt-4o", {}).temperature_mode == "pass"                          # OpenAI: caller's value
    assert reg.resolve("codex-proxy", base).temperature_mode == "omit"                    # unset env: never sent
    fixed = reg.resolve("codex-proxy", {**base, "CODEX_PROXY_TEMPERATURE": "0.25"})
    assert (fixed.temperature_mode, fixed.temperature_value) == ("fixed", 0.25)
    with pytest.raises(providers.ProviderConfigError, match="not a valid float"):
        reg.resolve("codex-proxy", {**base, "CODEX_PROXY_TEMPERATURE": "hot"})


# ---- routing through the real agent classes, against local fake servers ----------------------------------
def test_each_model_talks_only_to_its_own_provider_with_its_own_key(monkeypatch):
    with FakeProvider() as codex, FakeProvider() as mercury, FakeProvider() as openai:
        env = {"CODEX_PROXY_BASE_URL": codex.base_url, "CODEX_PROXY_MODEL": "Codex-Exact_ID", "CODEX_PROXY_API_KEY": CODEX_KEY,
               "MERCURY_BASE_URL": mercury.base_url, "MERCURY_MODEL": "mercury-exact", "MERCURY_API_KEY": MERCURY_KEY}
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setenv("OPENAI_API_KEY", OPENAI_KEY)
        monkeypatch.setattr(providers.Registry, "_provider", staticmethod(_redirect_openai(openai.base_url)))
        utils.build_agent("t", "codex-proxy").query("hello", format="str")
        utils.build_agent("t", "mercury").query("hello", format="str")
        utils.build_agent("t", "gpt-4o-mini").query("hello", format="str")
        assert [(r["path"], r["key"]) for r in codex.chat_requests()] == [("/v1/chat/completions", CODEX_KEY)]
        assert [(r["path"], r["key"]) for r in mercury.chat_requests()] == [("/v1/chat/completions", MERCURY_KEY)]
        assert [(r["path"], r["key"]) for r in openai.chat_requests()] == [("/v1/chat/completions", OPENAI_KEY)]
        assert codex.chat_requests()[0]["body"]["model"] == "Codex-Exact_ID"     # exact configured ID, case preserved
        assert mercury.chat_requests()[0]["body"]["model"] == "mercury-exact"
        for fake, own in ((codex, CODEX_KEY), (mercury, MERCURY_KEY), (openai, OPENAI_KEY)):
            sent = json.dumps([r["headers"] for r in fake.requests]) + json.dumps([r["body"] for r in fake.requests])
            for other in {CODEX_KEY, MERCURY_KEY, OPENAI_KEY} - {own}:
                assert other not in sent, "one provider's key reached another provider"


def _redirect_openai(url):
    original = providers.Registry._provider    # accessed on the class, a staticmethod is the plain function

    def patched(pid, raw):
        if pid == "openai":
            raw = dict(raw, base_url=url)
        return original(pid, raw)
    return patched


def test_a_missing_provider_key_is_a_clear_error_not_a_call_to_somewhere_else(monkeypatch):
    with FakeProvider() as codex:
        monkeypatch.setenv("OPENAI_API_KEY", OPENAI_KEY)                    # present, but must never be borrowed
        for k, v in {"CODEX_PROXY_BASE_URL": codex.base_url, "CODEX_PROXY_MODEL": "m"}.items():
            monkeypatch.setenv(k, v)
        with pytest.raises(providers.ProviderConfigError, match="CODEX_PROXY_API_KEY"):
            utils.build_agent("t", "codex-proxy")
        assert codex.requests == []


def test_temperature_is_sent_omitted_or_fixed_exactly_as_configured(monkeypatch):
    with FakeProvider() as codex:
        base = {"CODEX_PROXY_BASE_URL": codex.base_url, "CODEX_PROXY_MODEL": "m", "CODEX_PROXY_API_KEY": CODEX_KEY}
        agent_for(monkeypatch, "codex-proxy", **base).query("hi", temperature=0, format="str")
        assert "temperature" not in codex.chat_requests()[-1]["body"]
        agent_for(monkeypatch, "codex-proxy", **base, CODEX_PROXY_TEMPERATURE="0.4").query("hi", temperature=0, format="str")
        assert codex.chat_requests()[-1]["body"]["temperature"] == 0.4
    with FakeProvider() as openai:
        monkeypatch.setenv("OPENAI_API_KEY", OPENAI_KEY)
        monkeypatch.setattr(providers.Registry, "_provider", staticmethod(_redirect_openai(openai.base_url)))
        utils.build_agent("t", "gpt-4o").query("hi", temperature=0, format="str")
        assert openai.chat_requests()[-1]["body"]["temperature"] == 0


def test_registry_params_are_passed_through_verbatim(tmp_path, monkeypatch):
    with FakeProvider() as p:
        path = write_registry(tmp_path, {
            "providers": {"acme": {"type": "openai_compatible", "base_url": p.base_url, "api_key_env": "ACME_KEY"}},
            "models": [{"id": "acme-1", "provider": "acme", "model": "acme-model",
                        "params": {"temperature": "omit", "max_completion_tokens": 321, "reasoning_effort": "low"}}]})
        monkeypatch.setenv("FAULTSEEKER_MODELS_FILE", str(path))
        monkeypatch.setenv("ACME_KEY", "acme-key-" + "a" * 20)
        utils.build_agent("t", "acme-1").query("hi", temperature=0.9, format="str")
        body = p.chat_requests()[0]["body"]
        assert body["max_completion_tokens"] == 321 and body["reasoning_effort"] == "low"
        assert "temperature" not in body and "max_tokens" not in body


@pytest.mark.parametrize("status,error", [
    (500, {"error": {"message": "boom"}}),
    (503, {"error": {"message": "overloaded"}}),
    (429, {"error": {"message": "slow down", "type": "rate_limit_error"}}),
    (400, {"error": {"message": "Unsupported parameter: 'temperature'", "param": "temperature", "code": "unsupported_parameter"}}),
])
def test_failed_calls_are_made_once_and_never_retried_or_rewritten(monkeypatch, status, error, capsys):
    with FakeProvider(chat_status=status, chat_error=error) as codex:
        agent = agent_for(monkeypatch, "codex-proxy", CODEX_PROXY_BASE_URL=codex.base_url, CODEX_PROXY_MODEL="m",
                          CODEX_PROXY_API_KEY=CODEX_KEY, CODEX_PROXY_TEMPERATURE="0.3")
        assert agent.query("hello", temperature=0, format="str") == "An error occurred."
        assert agent.query("hello", format="json") in ("An error occurred.", ["An error occurred."])   # list shape: see results.py
        assert len(codex.chat_requests()) == 2, "exactly one HTTP call per query: no SDK retries, no second attempt"
        assert {r["body"].get("temperature") for r in codex.chat_requests()} == {0.3}, "parameters are not silently changed"
    assert "Error code" in capsys.readouterr().err        # the failure is printed (and later classified), not swallowed


def test_unreachable_provider_fails_once_without_retrying(monkeypatch):
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()      # a port nothing listens on
    agent = agent_for(monkeypatch, "codex-proxy", CODEX_PROXY_BASE_URL=f"http://127.0.0.1:{port}/v1", CODEX_PROXY_MODEL="m",
                      CODEX_PROXY_API_KEY=CODEX_KEY)
    assert agent.query("hello", format="str") == "An error occurred."


def test_explicit_ollama_model_uses_the_ollama_agent_and_host(monkeypatch):
    from faultseeker.utils.agent import OllmaAgent
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:9")
    a = utils.build_agent("t", "ollama:llama3")
    assert isinstance(a, OllmaAgent) and a.model == "llama3"


def test_an_unknown_model_is_an_error_not_a_silent_ollama_call():
    with pytest.raises(providers.ProviderConfigError, match="not in the provider registry"):
        utils.build_agent("t", "llama3")
    with pytest.raises(providers.ProviderConfigError, match="not in the provider registry"):
        utils.build_agent("t", "gpt-5-whatever")


def test_function_hash_check_is_anchored():
    assert utils.is_function_hash("2fbebd38") and utils.is_function_hash("0x2fbebd38") and utils.is_function_hash("A9059CBB")
    assert not utils.is_function_hash("deadbeefToken") and not utils.is_function_hash("transfer") and not utils.is_function_hash("2fbebd3")
