"""FastAPI application: JSON API under /api, access control under /auth, plus the static console."""
import asyncio
import os
import logging
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from . import keycheck, presets, results, settings
from .auth import COOKIE_NAME, AccessControl
from .runs import BusyError, RunManager
from .security import ValidationError, resolve_rpc, validate_hash, validate_secret

log = logging.getLogger("faultseeker.server")
manager: RunManager = None        # created in lifespan; tests may replace it
access: AccessControl = None
KEYCHECK_TRANSPORT = None         # test seam: an httpx transport for key checks (never set in production)

# The only things reachable without a session when access protection is on.
PUBLIC_PATHS = {"/api/health", "/login", "/auth/login", "/auth/logout", "/auth/session", "/favicon.ico"}
PUBLIC_PREFIXES = ("/login-assets/",)


def build_access_control() -> AccessControl:
    return AccessControl(settings.ACCESS_CODE, session_seconds=settings.SESSION_HOURS * 3600,
                         max_failures_per_ip=settings.LOGIN_MAX_FAILURES_PER_IP,
                         window_seconds=settings.LOGIN_WINDOW_SECONDS,
                         max_failures_global=settings.LOGIN_MAX_FAILURES_GLOBAL)


@asynccontextmanager
async def lifespan(_: FastAPI):
    global manager, access
    problems = settings.startup_problems()
    if problems:
        raise RuntimeError("FaultSeeker refuses to start:\n  - " + "\n  - ".join(problems))
    if settings.PUBLIC_MODE and not settings.ACCESS_CODE:
        log.warning("Running publicly WITHOUT access protection: set FAULTSEEKER_ACCESS_CODE before sharing the URL.")
    access = build_access_control()
    manager = RunManager()
    yield
    await manager.shutdown()


app = FastAPI(title="FaultSeeker++", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


def _error(status: int, code: str, message: str, field: str = None, headers: dict = None, **extra):
    body = {"error": {"code": code, "message": message, "field": field, **extra}}
    return JSONResponse(body, status_code=status, headers=headers)


def _is_public(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _secure_cookie(request: Request) -> bool:
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return settings.PUBLIC_MODE or request.url.scheme == "https" or forwarded == "https"


def _origin_ok(request: Request) -> bool:
    """CSRF defence in depth (the cookie is also SameSite=Strict): a browser-sent Origin must match this host."""
    origin = request.headers.get("origin")
    if not origin or origin == "null":
        return origin is None
    return urlsplit(origin).netloc.lower() == request.headers.get("host", "").lower()


@app.middleware("http")
async def gate(request: Request, call_next):
    path = request.url.path
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not _origin_ok(request):
            return _error(403, "bad_origin", "Cross-site requests are not allowed.")
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.MAX_BODY_BYTES:
            return _error(413, "too_large", "Request body is too large.")
    if access is not None and access.enabled and not _is_public(path):
        if not access.valid_session(request.cookies.get(COOKIE_NAME, "")):
            if request.method == "GET" and path == "/":
                response = RedirectResponse("/login", status_code=303)
            else:
                response = _error(401, "auth_required", "Sign in to continue.")
            response.headers["Cache-Control"] = "no-store"
            _security_headers(response, path)
            return response
    response = await call_next(request)
    _security_headers(response, path)
    return response


def _security_headers(response, path: str):
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    if path.startswith(("/api/", "/auth/")) or path == "/login":
        response.headers["Cache-Control"] = "no-store"


@app.exception_handler(ValidationError)
async def validation_handler(_: Request, exc: ValidationError):
    return _error(400, exc.code, exc.message, exc.field)


# ---- access control --------------------------------------------------------------------------------
@app.get("/auth/session")
async def auth_session(request: Request):
    return {"required": access.enabled,
            "authenticated": (not access.enabled) or access.valid_session(request.cookies.get(COOKIE_NAME, ""))}


@app.post("/auth/login")
async def auth_login(request: Request):
    if not access.enabled:
        return _error(404, "auth_disabled", "Access protection is not enabled on this server.")
    ip = _client_ip(request)
    wait = access.retry_after(ip)
    if wait:
        return _error(429, "too_many_attempts", f"Too many failed attempts. Try again in {max(1, round(wait / 60))} minute(s).",
                      headers={"Retry-After": str(wait)})
    try:
        body = await request.json()
    except ValueError:
        body = None
    code = body.get("code") if isinstance(body, dict) else None
    if not isinstance(code, str) or not code or len(code) > 256 or not access.check_code(code):
        access.record_failure(ip)
        return _error(401, "invalid_access_code", "Incorrect access code.")
    access.record_success(ip)
    token = access.create_session()
    response = JSONResponse({"ok": True})
    response.set_cookie(COOKIE_NAME, token, max_age=int(access.session_seconds), httponly=True, samesite="strict",
                        secure=_secure_cookie(request), path="/")
    return response


@app.post("/auth/logout")
async def auth_logout(request: Request):
    access.revoke(request.cookies.get(COOKIE_NAME, ""))
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, samesite="strict", secure=_secure_cookie(request))
    return response


@app.get("/login", include_in_schema=False)
async def login_page(request: Request):
    if not access.enabled or access.valid_session(request.cookies.get(COOKIE_NAME, "")):
        return RedirectResponse("/", status_code=303)
    return FileResponse(settings.WEB_DIR / "login" / "login.html", headers={"Cache-Control": "no-store"})


# ---- API -------------------------------------------------------------------------------------------
@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/config")
async def config():
    return {
        "environment": settings.environment_report(),
        "auth": {"required": access.enabled},
        "chains": settings.CHAINS,
        "models": settings.models(),
        "unavailable_models": settings.unavailable_models(),
        "presets": presets.presets_by_chain(),
        "recent": manager.known_hashes(),
        "limits": {"concurrent_runs": settings.MAX_CONCURRENT_RUNS, "timeout_seconds": settings.RUN_TIMEOUT_SECONDS},
        "active_run": next(iter(manager.active), None),
    }


@app.post("/api/runs", status_code=201)
async def create_run(request: Request):
    try:
        body = await request.json()
    except ValueError:
        return _error(400, "invalid_json", "Request body must be JSON.")
    if not isinstance(body, dict):
        return _error(400, "invalid_json", "Request body must be a JSON object.")

    txn_hash = validate_hash(body.get("txn_hash"))
    chain = str(body.get("chain") or "").strip().lower()
    if chain not in settings.CHAIN_IDS:
        known = next((c for c in settings.CHAINS if c["id"] == chain), None)
        raise ValidationError("chain", (known and known["note"]) or "Choose a supported network.")
    model_id = str(body.get("mode") or "").strip().lower()
    model = next((m for m in settings.models() if m["id"] == model_id), None)
    if not model:
        raise ValidationError("mode", "Choose an available analysis model.")
    user_key = validate_secret("model_key", body.get("model_key"), "The model API key")

    reg = settings.registry()
    resolved = reg.resolve(model["id"])
    provider = resolved.provider
    key_status = ""
    if provider.api_key_env:
        key = user_key or os.environ.get(provider.api_key_env, "").strip()
        if not key:
            raise ValidationError("model_key", f"{provider.label} needs an API key for this model.")
        check = await keycheck.check_key(provider, resolved.base_url, key, transport=KEYCHECK_TRANSPORT)
        key_status = check.status
        if check.status == keycheck.INVALID:
            if user_key:
                raise ValidationError("model_key", check.detail or f"{provider.label} rejected this API key.", "model_key_rejected")
            return _error(503, "server_key_rejected", f"The server's {provider.label} key was rejected. Tell the operator.")
        if check.status == keycheck.UNAVAILABLE:
            return _error(503, "key_validation_unavailable", check.detail or f"Could not verify the {provider.label} key right now.",
                          field="model_key" if user_key else None)
    else:
        user_key = ""

    rpc_key = validate_secret("rpc_key", body.get("rpc_key"), "The RPC key")
    rpc_url = await asyncio.to_thread(resolve_rpc, body.get("rpc_url"), rpc_key)

    report = settings.environment_report()
    if not report["ready"]:
        return _error(503, "environment_not_ready", "The analysis environment is not ready.", issues=report["issues"])
    try:
        run = manager.start(txn_hash=txn_hash, chain=chain, model=model["id"], model_key=user_key, rpc_url=rpc_url,
                            key_check=key_status)
    except BusyError as busy:
        return _error(409, "busy", "Another analysis is already running. Wait for it to finish or open it.",
                      active_run=busy.active_id)
    return {"id": run.id, "run": run.meta()}


@app.get("/api/runs")
async def list_runs():
    return {"runs": manager.history()}


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str, e: int = 0, l: int = 0):
    run = manager.get(run_id)
    if not run:
        return _error(404, "not_found", "This run does not exist or has been removed.")
    return manager.view(run, e, l)


@app.post("/api/runs/{run_id}/cancel")
async def cancel_run(run_id: str):
    run = manager.get(run_id)
    if not run:
        return _error(404, "not_found", "This run does not exist or has been removed.")
    cancelled = await manager.cancel(run)
    if not cancelled:
        return _error(409, "not_running", "This run has already finished.")
    return {"ok": True}


@app.get("/api/runs/{run_id}/result")
async def get_result(run_id: str, download: str = ""):
    run = manager.get(run_id)
    if not run:
        return _error(404, "not_found", "This run does not exist or has been removed.")
    data = manager.result(run_id, raw=(download == "raw"))
    if data is None:
        return _error(404, "no_result", "This run has no report.")
    if download:
        return JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="faultseeker-{run.txn_hash[:10]}.json"'})
    meta = run.meta()
    data["run"] = {"id": run.id, "model": run.model, "provider": run.provider, "chain": run.chain,
                   "created_at": meta["created_at"], "finished_at": meta["finished_at"], "rpc_mode": run.rpc_mode}
    return data


@app.get("/api/capture")
async def capture():
    data = results.reference_capture()
    if not data:
        return _error(404, "no_capture", "No saved capture is available in this deployment.")
    return data


# ---- static console --------------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(settings.WEB_DIR / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


class NoCacheStatic(StaticFiles):
    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


app.mount("/assets", NoCacheStatic(directory=settings.WEB_DIR / "assets"), name="assets")
app.mount("/login-assets", NoCacheStatic(directory=settings.WEB_DIR / "login"), name="login-assets")
