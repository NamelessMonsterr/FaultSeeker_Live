"""Access protection: access code, sessions, rate limiting, coverage of every route, startup safety.

OFFLINE: in-process only. The clock is injected for the unit tests; the HTTP tests use the real app with the stand-in worker.
"""
import hmac
import re

import pytest

from tests.conftest import payload, start_run, wait_final

CODE = "correct horse battery staple"
PUBLIC = {"/api/health", "/login", "/auth/login", "/auth/logout", "/auth/session", "/favicon.ico"}


# ---- AccessControl unit tests ------------------------------------------------------------------------
class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def control(clock=None, **kw):
    from faultseeker.server import auth
    args = dict(session_seconds=3600, max_failures_per_ip=3, window_seconds=600, max_failures_global=10)
    args.update(kw)
    return auth.AccessControl(CODE, now=clock or Clock(), **args)


def test_code_is_compared_in_constant_time(monkeypatch):
    calls = []
    real = hmac.compare_digest
    monkeypatch.setattr(hmac, "compare_digest", lambda a, b: calls.append((len(a), len(b))) or real(a, b))
    ac = control()
    assert ac.check_code(CODE) is True
    assert ac.check_code("x") is False and ac.check_code("x" * 5000) is False and ac.check_code("") is False
    assert len(calls) == 4 and {c for c in calls} == {(32, 32)}, "digests of equal length, so neither content nor length leaks"
    assert control().check_code(None) is False


def test_no_code_configured_means_nothing_matches():
    from faultseeker.server import auth
    ac = auth.AccessControl("", session_seconds=1, max_failures_per_ip=1, window_seconds=1, max_failures_global=1)
    assert ac.enabled is False and ac.check_code("") is False and ac.check_code("anything") is False


def test_sessions_expire_and_can_be_revoked():
    clock = Clock()
    ac = control(clock, session_seconds=100)
    token = ac.create_session()
    assert len(token) >= 43 and ac.valid_session(token) and not ac.valid_session("") and not ac.valid_session("guess")
    clock.t += 99
    assert ac.valid_session(token)
    clock.t += 2
    assert not ac.valid_session(token), "expired"
    t2 = ac.create_session()
    ac.revoke(t2)
    assert not ac.valid_session(t2), "revoked by logout"
    assert ac.create_session() != ac.create_session()


def test_the_token_is_not_stored_in_the_clear():
    ac = control()
    token = ac.create_session()
    assert token not in repr(ac.__dict__) and token.encode() not in b"".join(ac._sessions)


def test_login_rate_limit_per_address_and_globally():
    clock = Clock()
    ac = control(clock)
    assert ac.retry_after("1.1.1.1") == 0
    for _ in range(3):
        ac.record_failure("1.1.1.1")
    wait = ac.retry_after("1.1.1.1")
    assert 590 <= wait <= 601 and ac.retry_after("2.2.2.2") == 0, "limit is per address"
    clock.t += 601
    assert ac.retry_after("1.1.1.1") == 0, "window slides"
    for i in range(10):
        ac.record_failure(f"10.0.0.{i}")
    assert ac.retry_after("fresh-address") > 0, "a spread-out guessing attack hits the global limit"
    ac2 = control(clock)
    ac2.record_failure("a"); ac2.record_failure("a")
    ac2.record_success("a")
    assert ac2.retry_after("a") == 0 and len(ac2._failures) == 0


# ---- HTTP-level tests ---------------------------------------------------------------------------------
@pytest.fixture()
def protected(make_client):
    return make_client(FAULTSEEKER_ACCESS_CODE=CODE)


def login(c, code=CODE, **kw):
    return c.post("/auth/login", json={"code": code}, **kw)


def test_every_route_requires_a_session_except_the_public_ones(protected):
    app = protected.app_module.app
    paths = []
    for route in app.routes:
        path = getattr(route, "path", "")
        if hasattr(route, "methods"):
            paths.append((path, sorted(route.methods - {"HEAD", "OPTIONS"})))
        else:                                   # mounted static directories
            paths.append((path + "/console.js", ["GET"]))
    paths += [("/assets/console.css", ["GET"]), ("/assets/../settings.py", ["GET"]), ("/nonexistent", ["GET"]), ("/api/runs/0123456789abcdef", ["GET"])]
    protected_seen = 0
    for path, methods in paths:
        concrete = re.sub(r"\{[^}]+\}", "0123456789abcdef", path)
        if concrete in PUBLIC or concrete.startswith("/login-assets"):
            continue
        for method in methods:
            r = protected.request(method, concrete, follow_redirects=False)
            assert r.status_code in (401, 303), f"{method} {concrete} reachable without a session ({r.status_code})"
            if concrete != "/":
                assert r.status_code == 401 and r.json()["error"]["code"] == "auth_required"
            protected_seen += 1
    assert protected_seen == 13, "the enumeration covers every API route, the console pages and the static mount"
    assert {c for c, _ in paths} >= {"/", "/api/config", "/api/runs", "/api/runs/{run_id}", "/api/runs/{run_id}/cancel",
                                      "/api/runs/{run_id}/result", "/api/capture", "/assets/console.js"}


def test_home_page_redirects_to_login_and_leaks_nothing(protected):
    r = protected.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login" and "FAULTSEEKER" not in r.text
    assert protected.get("/api/config").json() == {"error": {"code": "auth_required", "message": "Sign in to continue.", "field": None}}


def test_runs_results_downloads_and_cancel_need_a_session(protected, make_client):
    r = protected.post("/api/runs", json=payload())
    assert r.status_code == 401 and protected.get("/api/runs").status_code == 401
    assert protected.keycheck.calls == [], "an unauthenticated request must not even trigger a provider key check"
    assert login(protected).status_code == 200
    rid = start_run(protected)
    wait_final(protected, rid)
    fresh = make_client(FAULTSEEKER_ACCESS_CODE=CODE)      # same data directory, no cookie
    for path in (f"/api/runs/{rid}", f"/api/runs/{rid}/result", f"/api/runs/{rid}/result?download=raw", "/api/capture", "/api/runs"):
        assert fresh.get(path).status_code == 401, path
    assert fresh.post(f"/api/runs/{rid}/cancel").status_code == 401


def test_public_surface_is_minimal(protected):
    assert protected.get("/api/health").json() == {"status": "ok"}
    assert protected.get("/auth/session").json() == {"required": True, "authenticated": False}
    page = protected.get("/login")
    assert page.status_code == 200 and "Access code" in page.text and "FAULTSEEKER" in page.text
    assert protected.get("/login-assets/login.js").status_code == 200 and protected.get("/login-assets/login.css").status_code == 200
    for hidden in ("/assets/console.js", "/assets/console.css"):
        assert protected.get(hidden).status_code == 401, "console code is behind the login"
    assert protected.get("/favicon.ico").status_code == 204


def test_login_page_follows_the_csp_no_inline_script_or_style(protected):
    page = protected.get("/login")
    html = page.text
    assert "<script>" not in html and "style=" not in html and "onclick=" not in html and "<style" not in html
    assert re.findall(r'<script[^>]*src="([^"]+)"', html) == ["/login-assets/login.js"]
    csp = page.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp and "frame-ancestors 'none'" in csp
    js = protected.get("/login-assets/login.js").text
    assert "innerHTML" not in js and "eval(" not in js


def test_wrong_code_is_rejected_without_hints(make_client):
    protected = make_client(FAULTSEEKER_ACCESS_CODE=CODE, FAULTSEEKER_LOGIN_MAX_FAILURES=100)    # keep the limiter out of this test
    for bad in ("", "wrong", CODE.upper(), CODE + " ", "x" * 300):
        r = login(protected, bad)
        assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_access_code"
        assert CODE not in r.text and "set-cookie" not in r.headers
    assert protected.post("/auth/login", content=b"nope").status_code == 401
    assert protected.post("/auth/login", json={"code": 12345}).status_code == 401
    assert protected.post("/auth/login", json=["list"]).status_code == 401


def test_login_sets_a_hardened_session_cookie_and_unlocks_everything(protected):
    r = login(protected)
    assert r.status_code == 200 and r.json() == {"ok": True}
    cookie = r.headers["set-cookie"]
    assert cookie.startswith("fs_session=") and "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie
    assert "Max-Age=43200" in cookie and CODE not in cookie
    assert "Secure" not in cookie, "plain-http local use works"
    assert protected.get("/auth/session").json() == {"required": True, "authenticated": True}
    assert protected.get("/api/config").status_code == 200 and protected.get("/assets/console.js").status_code == 200
    assert protected.get("/").status_code == 200 and "FAULTSEEKER" in protected.get("/").text
    assert protected.get("/login", follow_redirects=False).status_code == 303


def test_cookie_is_secure_over_https_and_always_in_public_mode(make_client):
    c = make_client(FAULTSEEKER_ACCESS_CODE=CODE)
    secure = c.post("/auth/login", json={"code": CODE}, headers={"x-forwarded-proto": "https"})
    assert "Secure" in secure.headers["set-cookie"]
    public = make_client(FAULTSEEKER_ACCESS_CODE=CODE, FAULTSEEKER_PUBLIC="1")
    assert "Secure" in public.post("/auth/login", json={"code": CODE}).headers["set-cookie"]


def test_logout_revokes_the_session_even_if_the_cookie_is_replayed(protected):
    login(protected)
    token = protected.cookies.get("fs_session")
    assert protected.get("/api/runs").status_code == 200
    out = protected.post("/auth/logout")
    assert out.status_code == 200 and "fs_session=" in out.headers["set-cookie"] and "Max-Age=0" in out.headers["set-cookie"]
    assert protected.get("/api/runs").status_code == 401
    assert protected.get("/api/runs", headers={"cookie": f"fs_session={token}"}).status_code == 401, "token revoked server side"
    assert protected.get("/", follow_redirects=False).status_code == 303


def test_forged_and_malformed_cookies_are_rejected(protected):
    for value in ("", "guess", "A" * 43, "../../etc/passwd", "x" * 5000):
        r = protected.get("/api/runs", headers={"cookie": f"fs_session={value}"})
        assert r.status_code == 401


def test_failed_logins_are_rate_limited_then_recover(make_client):
    c = make_client(FAULTSEEKER_ACCESS_CODE=CODE, FAULTSEEKER_LOGIN_MAX_FAILURES=3)
    for _ in range(3):
        assert login(c, "nope").status_code == 401
    blocked = login(c, "nope")
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) > 0
    assert blocked.json()["error"]["code"] == "too_many_attempts"
    assert login(c, CODE).status_code == 429, "even the right code is refused while locked out"
    assert c.get("/api/runs").status_code == 401
    clock = c.app_module.access
    shift = 10_000
    original = clock._now
    clock._now = lambda: original() + shift
    assert login(c, CODE).status_code == 200


def test_cross_site_posts_are_refused(protected):
    login(protected)
    for path, body in (("/auth/logout", None), ("/api/runs", payload()), ("/auth/login", {"code": CODE})):
        r = protected.post(path, json=body or {}, headers={"origin": "https://evil.example"})
        assert r.status_code == 403 and r.json()["error"]["code"] == "bad_origin"
    assert protected.post("/api/runs", json=payload(), headers={"origin": "null"}).status_code == 403
    ok = protected.post("/api/runs", json=payload(), headers={"origin": "http://testserver"})
    assert ok.status_code == 201
    wait_final(protected, ok.json()["id"])


def test_without_an_access_code_the_console_is_open_as_before(client):
    assert client.get("/api/runs").status_code == 200 and client.get("/assets/console.js").status_code == 200
    assert client.get("/auth/session").json() == {"required": False, "authenticated": True}
    assert client.post("/auth/login", json={"code": "x"}).status_code == 404
    assert client.get("/login", follow_redirects=False).status_code == 303
    assert client.get("/api/config").json()["auth"] == {"required": False}


def test_config_tells_the_console_to_show_sign_out_only_when_protected(protected):
    login(protected)
    assert protected.get("/api/config").json()["auth"] == {"required": True}


# ---- startup safety ---------------------------------------------------------------------------------
def test_no_default_password_ships_in_any_file():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    files = [root / "render.yaml", root / "Dockerfile", root / ".env.example", root / "docker-entrypoint.sh", root / "config" / "models.json"]
    assert all(f.exists() for f in files)
    assignment = re.compile(r"FAULTSEEKER_ACCESS_CODE\s*[=:]\s*(?P<value>\S+)")
    for f in files:
        for line in f.read_text().splitlines():
            if line.lstrip().startswith("#"):
                continue
            m = assignment.search(line)
            assert not m, f"{f.name} assigns an access code: {line.strip()}"
    yaml_text = (root / "render.yaml").read_text()
    block = yaml_text[yaml_text.index("key: FAULTSEEKER_ACCESS_CODE"):].split("- key:")[0]
    assert "sync: false" in block and "value:" not in block, "the code is entered in the host's dashboard, never in the repository"
    env_example = (root / ".env.example").read_text()
    assert re.search(r"^FAULTSEEKER_ACCESS_CODE=$", env_example, re.M), "the example leaves the code empty"


def test_short_access_codes_are_refused(make_client):
    with pytest.raises(RuntimeError, match="at least 12 characters"):
        make_client(FAULTSEEKER_ACCESS_CODE="short")


def test_public_start_with_a_server_model_key_and_no_protection_is_refused(make_client):
    for flags in ({"FAULTSEEKER_PUBLIC": "1"}, {"RENDER": "true"}):
        with pytest.raises(RuntimeError, match="access protection is not") as exc:
            make_client(OPENAI_API_KEY="sk-server-" + "s" * 24, **flags)
        assert "FAULTSEEKER_ACCESS_CODE" in str(exc.value) and "sk-server" not in str(exc.value), "names the fix, never the key"
    with pytest.raises(RuntimeError, match="CODEX_PROXY_API_KEY"):
        make_client(CODEX_PROXY_API_KEY="k" * 24, FAULTSEEKER_PUBLIC="1")


def test_public_start_is_allowed_with_protection_with_no_server_key_or_with_the_explicit_override(make_client):
    make_client(OPENAI_API_KEY="sk-server-" + "s" * 24, FAULTSEEKER_PUBLIC="1", FAULTSEEKER_ACCESS_CODE=CODE)
    make_client(FAULTSEEKER_PUBLIC="1")                                    # users bring their own keys: nothing to protect
    make_client(OPENAI_API_KEY="sk-server-" + "s" * 24, FAULTSEEKER_PUBLIC="1", FAULTSEEKER_ALLOW_UNSAFE_PUBLIC="1")
    make_client(OPENAI_API_KEY="sk-server-" + "s" * 24)                    # local development is not "public"
