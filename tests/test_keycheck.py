"""Key validation: valid / invalid / unavailable, per provider, without contacting any real API.

OFFLINE / MOCKED: unit tests use httpx.MockTransport (no sockets). Server-level tests inject a mock transport into the
app. Nothing here reaches OpenAI, a Codex proxy, Mercury or any other real endpoint.
"""
import asyncio
import json

import httpx
import pytest

from faultseeker import providers
from tests.conftest import payload, start_run, wait_final

CODEX_KEY, MERCURY_KEY, OPENAI_KEY = "codex-user-" + "c" * 24, "mercury-user-" + "m" * 24, "sk-user-" + "o" * 28


def provider(**kw):
    base = dict(id="acme", label="Acme", type="openai_compatible", key_validation="models_list")
    base.update(kw)
    return providers.Provider(**base)


def check(handler, prov=None, base="https://acme.example.invalid/v1", key="k-" + "z" * 20):
    from faultseeker.server import keycheck
    calls = []

    def wrapped(request):
        calls.append(request)
        return handler(request)
    result = asyncio.run(keycheck.check_key(prov or provider(), base, key, transport=httpx.MockTransport(wrapped)))
    return result, calls


def refuse(request):
    raise httpx.ConnectError("refused")


def slow(request):
    raise httpx.ReadTimeout("too slow")


@pytest.mark.parametrize("handler,status", [
    (lambda r: httpx.Response(200, json={"data": []}), "valid"),
    (lambda r: httpx.Response(401, json={"error": {"message": "nope"}}), "invalid"),
])
def test_definite_answers(handler, status):
    result, calls = check(handler)
    assert result.status == status and len(calls) == 1


@pytest.mark.parametrize("name,handler", [
    ("connection refused", refuse), ("timeout", slow),
    ("500", lambda r: httpx.Response(500)), ("502", lambda r: httpx.Response(502)), ("503", lambda r: httpx.Response(503)),
    ("429 rate limited", lambda r: httpx.Response(429)), ("403", lambda r: httpx.Response(403)),
    ("404 no /models", lambda r: httpx.Response(404)), ("405", lambda r: httpx.Response(405)),
    ("400", lambda r: httpx.Response(400)), ("418", lambda r: httpx.Response(418)),
    ("307 redirect", lambda r: httpx.Response(307, headers={"Location": "https://elsewhere.example.invalid/v1/models"})),
])
def test_an_outage_or_odd_answer_is_never_reported_as_valid(name, handler):
    result, calls = check(handler)
    assert result.status == "unavailable", name
    assert result.status != "valid"
    assert len(calls) == 1, "redirects are not followed, so the key cannot be bounced to another host"


def test_key_check_uses_the_providers_own_url_and_only_its_own_key():
    result, calls = check(lambda r: httpx.Response(200, json={}), base="https://api.codex.example.invalid/v1/", key=CODEX_KEY)
    assert str(calls[0].url) == "https://api.codex.example.invalid/v1/models"
    assert calls[0].headers["authorization"] == f"Bearer {CODEX_KEY}" and calls[0].method == "GET"


def test_providers_without_validation_report_not_supported_and_make_no_call():
    for prov in (provider(key_validation="none"), provider(type="ollama")):
        result, calls = check(lambda r: httpx.Response(200), prov)
        assert result.status == "not_supported" and calls == []


def test_details_never_contain_the_key():
    for handler in (refuse, slow, lambda r: httpx.Response(401), lambda r: httpx.Response(500), lambda r: httpx.Response(404)):
        result, _ = check(handler, key="super-secret-key-12345")
        assert "super-secret-key-12345" not in result.detail


# ---- through the HTTP API -----------------------------------------------------------------------------------
ENV = {"CODEX_PROXY_BASE_URL": "https://codex.example.invalid/v1", "CODEX_PROXY_MODEL": "codex-exact",
       "MERCURY_BASE_URL": "https://mercury.example.invalid/v1", "MERCURY_MODEL": "mercury-exact"}


@pytest.fixture()
def multi(make_client):
    return make_client(**ENV)


def test_each_selected_provider_is_validated_at_its_own_endpoint_with_its_own_key(multi):
    for model, key, host in (("codex-proxy", CODEX_KEY, "codex.example.invalid"), ("mercury", MERCURY_KEY, "mercury.example.invalid"),
                             ("gpt-4o", OPENAI_KEY, "api.openai.com")):
        multi.keycheck.calls.clear()
        rid = start_run(multi, mode=model, model_key=key)
        wait_final(multi, rid)
        assert multi.keycheck.calls == [{"url": f"https://{host}/v1/models", "host": host, "key": key}]
    seen = [c for c in multi.keycheck.calls]
    assert len(seen) == 1     # (cleared per model above; the assertion above is the per-provider proof)


def test_no_key_is_ever_sent_to_a_different_provider(multi):
    keys = {"codex-proxy": CODEX_KEY, "mercury": MERCURY_KEY, "gpt-4o": OPENAI_KEY}
    allowed = {"codex-proxy": "codex.example.invalid", "mercury": "mercury.example.invalid", "gpt-4o": "api.openai.com"}
    for model, key in keys.items():
        rid = start_run(multi, mode=model, model_key=key)
        wait_final(multi, rid)
    for call in multi.keycheck.calls:
        owner = next(m for m, k in keys.items() if k == call["key"])
        assert call["host"] == allowed[owner], f"{owner}'s key was sent to {call['host']}"
    assert len(multi.keycheck.calls) == 3


def test_invalid_key_is_rejected_and_nothing_starts(multi):
    multi.keycheck.handler = lambda r: httpx.Response(401, json={"error": {}})
    r = multi.post("/api/runs", json=payload(mode="codex-proxy", model_key=CODEX_KEY))
    err = r.json()["error"]
    assert r.status_code == 400 and err["code"] == "model_key_rejected" and err["field"] == "model_key"
    assert "Codex proxy" in err["message"] and CODEX_KEY not in r.text
    assert multi.get("/api/runs").json()["runs"] == []


@pytest.mark.parametrize("handler", [refuse, slow, lambda r: httpx.Response(503), lambda r: httpx.Response(429),
                                     lambda r: httpx.Response(404), lambda r: httpx.Response(307, headers={"Location": "https://x.invalid/"})])
def test_unavailable_check_blocks_the_run_instead_of_assuming_valid(multi, handler):
    multi.keycheck.handler = handler
    r = multi.post("/api/runs", json=payload(mode="mercury", model_key=MERCURY_KEY))
    assert r.status_code == 503 and r.json()["error"]["code"] == "key_validation_unavailable"
    assert r.json()["error"]["field"] == "model_key" and MERCURY_KEY not in r.text
    assert multi.get("/api/runs").json()["runs"] == [], "an outage must not count as a valid key"
    assert multi.get("/api/config").json()["active_run"] is None


def test_valid_key_starts_and_records_the_check(multi):
    rid = start_run(multi, mode="mercury", model_key=MERCURY_KEY)
    data = wait_final(multi, rid)
    assert data["run"]["state"] == "completed" and data["run"]["key_check"] == "valid" and data["run"]["provider"] == "mercury"


def test_server_held_key_is_checked_too_and_failures_do_not_blame_the_user(make_client):
    c = make_client(**ENV, CODEX_PROXY_API_KEY="server-codex-" + "s" * 24)
    assert next(m for m in c.get("/api/config").json()["models"] if m["id"] == "codex-proxy")["key_optional"] is True
    c.keycheck.handler = lambda r: httpx.Response(401)
    r = c.post("/api/runs", json=payload(mode="codex-proxy", model_key=""))
    assert r.status_code == 503 and r.json()["error"]["code"] == "server_key_rejected" and "operator" in r.json()["error"]["message"]
    assert "server-codex" not in r.text
    c.keycheck.handler = refuse
    assert c.post("/api/runs", json=payload(mode="codex-proxy", model_key="")).json()["error"]["code"] == "key_validation_unavailable"
    c.keycheck.handler = lambda r: httpx.Response(200, json={})
    c.keycheck.calls.clear()
    rid = start_run(c, mode="codex-proxy", model_key="")
    assert c.keycheck.calls[0]["key"] == "server-codex-" + "s" * 24 and wait_final(c, rid)["run"]["key_source"] == "server"
    c.keycheck.calls.clear()
    wait_final(c, start_run(c, mode="codex-proxy", model_key=CODEX_KEY))
    assert c.keycheck.calls[0]["key"] == CODEX_KEY, "a user's own key takes precedence and is the one validated"


def test_a_provider_with_validation_none_is_used_unchecked_and_labelled(make_client, tmp_path):
    reg = tmp_path / "models.json"
    reg.write_text(json.dumps({"providers": {"quiet": {"type": "openai_compatible", "base_url": "https://quiet.example.invalid/v1",
                                                        "api_key_env": "QUIET_KEY", "key_validation": "none"}},
                               "models": [{"id": "quiet-1", "label": "Quiet", "provider": "quiet", "model": "q"}]}))
    c = make_client(FAULTSEEKER_MODELS_FILE=reg)
    rid = start_run(c, mode="quiet-1", model_key="quiet-key-" + "q" * 20)
    data = wait_final(c, rid)
    assert c.keycheck.calls == [] and data["run"]["key_check"] == "not_supported" and data["run"]["state"] == "completed"


def test_missing_key_for_a_provider_that_needs_one_is_a_field_error(multi):
    r = multi.post("/api/runs", json=payload(mode="mercury", model_key=""))
    assert r.status_code == 400 and r.json()["error"]["field"] == "model_key" and "Inception Mercury" in r.json()["error"]["message"]
    assert multi.keycheck.calls == []


def test_models_missing_their_endpoint_or_id_are_not_offered(make_client):
    c = make_client(CODEX_PROXY_BASE_URL="https://codex.example.invalid/v1")           # no MODEL id configured
    ids = [m["id"] for m in c.get("/api/config").json()["models"]]
    assert "codex-proxy" not in ids and "mercury" not in ids
    reasons = {u["id"]: u["reason"] for u in c.get("/api/config").json()["unavailable_models"]}
    assert "CODEX_PROXY_MODEL" in reasons["codex-proxy"] and "MERCURY_MODEL" in reasons["mercury"]
    r = c.post("/api/runs", json=payload(mode="codex-proxy", model_key=CODEX_KEY))
    assert r.json()["error"]["field"] == "mode"


def test_registry_problems_stop_the_server_from_starting(make_client, tmp_path):
    bad = tmp_path / "models.json"
    bad.write_text("{not json")
    with pytest.raises(RuntimeError, match="Model registry"):
        make_client(FAULTSEEKER_MODELS_FILE=bad)
    with pytest.raises(RuntimeError, match="unknown models"):
        make_client(FAULTSEEKER_ENABLED_MODELS="typo-model")


def test_enabled_models_filter_drives_what_the_console_receives(make_client):
    c = make_client(**ENV, FAULTSEEKER_ENABLED_MODELS="mercury,gpt-4o", FAULTSEEKER_DEFAULT_MODEL="gpt-4o")
    models = c.get("/api/config").json()["models"]
    assert [m["id"] for m in models] == ["mercury", "gpt-4o"] and [m["default"] for m in models] == [False, True]
    assert models[0]["provider_label"] == "Inception Mercury"
    blob = json.dumps(c.get("/api/config").json())
    for secret_like in ("codex.example.invalid", "mercury.example.invalid", "codex-exact", "mercury-exact"):
        assert secret_like not in blob, "endpoints and exact model IDs are not sent to the browser"
