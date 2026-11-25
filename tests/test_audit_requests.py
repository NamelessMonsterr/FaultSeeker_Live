"""Audit F02 (streamed body cap) and F06 (non-string JSON fields). OFFLINE: the real FastAPI app, fake worker, local fake key validation."""
import json

import pytest

from tests.conftest import payload

LIMIT = 16 * 1024


def padded(size, **kw):
    """A syntactically valid JSON body of exactly `size` bytes (padding is trailing whitespace)."""
    base = json.dumps(payload(**kw))
    assert size >= len(base)
    return (base + " " * (size - len(base))).encode()


def chunks(data, step=1000):
    for i in range(0, len(data), step):
        yield data[i:i + step]


def post_chunked(client, data, path="/api/runs"):
    return client.post(path, content=chunks(data), headers={"content-type": "application/json"})      # no Content-Length


def test_a_chunked_body_over_the_cap_is_rejected_without_a_content_length(make_client):
    c = make_client()
    r = post_chunked(c, padded(LIMIT + 1))
    assert r.status_code == 413 and r.json()["error"]["code"] == "too_large"
    assert c.get("/api/runs").json()["runs"] == [], "no run was started"


def test_the_cap_boundary_is_exact(make_client):
    c = make_client()
    at = post_chunked(c, padded(LIMIT))
    assert at.status_code != 413, "exactly the limit is accepted by the size check"
    over = post_chunked(c, padded(LIMIT + 1))
    assert over.status_code == 413


def test_a_declared_length_that_understates_the_body_is_not_trusted(make_client):
    c = make_client()
    r = c.post("/api/runs", content=padded(LIMIT * 3), headers={"content-type": "application/json", "content-length": "100"})
    assert r.status_code in (400, 413), r.text
    assert r.status_code == 413 or r.json()["error"]["code"] in ("invalid_json", "too_large")


def test_a_malformed_length_header_does_not_bypass_the_cap(make_client):
    c = make_client()
    r = c.post("/api/runs", content=padded(LIMIT * 2), headers={"content-type": "application/json", "content-length": "12abc"})
    assert r.status_code in (400, 413)


def test_the_public_login_route_enforces_the_same_cap(make_client):
    c = make_client(FAULTSEEKER_ACCESS_CODE="correct horse battery staple")
    body = json.dumps({"code": "x"}).encode()
    body = body + b" " * (LIMIT + 200 - len(body))
    r = post_chunked(c, body, "/auth/login")
    assert r.status_code == 413, "the app-level cap applies to unauthenticated auth routes too"
    small = post_chunked(c, json.dumps({"code": "wrong"}).encode(), "/auth/login")
    assert small.status_code == 401


def test_a_normal_request_is_unaffected(make_client):
    c = make_client()
    r = c.post("/api/runs", json=payload())
    assert r.status_code == 201


# ------------------------------------------------------------------------------------------------ F06

FIELDS = ["txn_hash", "model_key", "rpc_key", "rpc_url", "chain", "mode"]
BAD = [123, 1.5, True, False, ["a"], {"a": 1}]


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("value", BAD)
def test_a_non_string_field_is_a_field_error_not_a_server_error(make_client, field, value):
    c = make_client()
    r = c.post("/api/runs", json=payload(**{field: value}))
    assert r.status_code == 400, f"{field}={value!r} gave {r.status_code}: {r.text[:200]}"
    assert r.json()["error"]["field"] == field
    assert c.get("/api/runs").json()["runs"] == [], "no worker was started"


@pytest.mark.parametrize("field", ["rpc_key", "rpc_url", "model_key"])
def test_null_and_missing_optional_fields_still_mean_empty(make_client, field):
    c = make_client()
    body = payload(model_key="sk-test-" + "x" * 30)
    body[field] = None
    r = c.post("/api/runs", json=body)
    assert r.status_code in (201, 400) and r.status_code != 500
    if r.status_code == 400:
        assert r.json()["error"]["field"] == field and field == "model_key", "only a required key may be rejected for being empty"


def test_a_bad_rpc_url_type_is_reported_before_any_key_validation(make_client, monkeypatch):
    import faultseeker.server.app as app_module
    calls = []
    real = app_module.keycheck.check_key

    async def spy(*a, **k):
        calls.append(1)
        return await real(*a, **k)
    monkeypatch.setattr(app_module.keycheck, "check_key", spy)
    c = make_client()
    r = c.post("/api/runs", json=payload(rpc_url=123))
    assert r.status_code == 400 and r.json()["error"]["field"] == "rpc_url"
    assert calls == [], "a malformed request makes no external key-validation call"


def test_the_body_must_still_be_an_object(make_client):
    c = make_client()
    for body in ("[1]", "123", '"x"', "null", "{bad"):
        r = c.post("/api/runs", content=body, headers={"content-type": "application/json"})
        assert r.status_code == 400
