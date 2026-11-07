"""FastAPI application: JSON API under /api plus the static console."""
import asyncio
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import presets, results, settings
from .runs import BusyError, RunManager
from .security import ValidationError, resolve_rpc, validate_hash, validate_secret

log = logging.getLogger("faultseeker.server")
manager: RunManager = None  # created in lifespan; tests may replace it


@asynccontextmanager
async def lifespan(_: FastAPI):
    global manager
    manager = RunManager()
    yield
    await manager.shutdown()


app = FastAPI(title="FaultSeeker++", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.MAX_BODY_BYTES:
            return _error(413, "too_large", "Request body is too large.")
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def _error(status: int, code: str, message: str, field: str = None, **extra):
    body = {"error": {"code": code, "message": message, "field": field, **extra}}
    return JSONResponse(body, status_code=status)


@app.exception_handler(ValidationError)
async def validation_handler(_: Request, exc: ValidationError):
    return _error(400, exc.code, exc.message, exc.field)


# ---- API -----------------------------------------------------------------------------------------
@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/config")
async def config():
    env = settings.environment_report()
    return {
        "environment": env,
        "chains": settings.CHAINS,
        "models": settings.models(),
        "presets": presets.presets_by_chain(),
        "recent": manager.known_hashes(),
        "limits": {"concurrent_runs": settings.MAX_CONCURRENT_RUNS, "timeout_seconds": settings.RUN_TIMEOUT_SECONDS},
        "active_run": next(iter(manager.active), None),
    }


async def _openai_key_ok(key: str) -> bool:
    """Reject a key the provider says is invalid. Network trouble never blocks a run."""
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {key}"})
        return resp.status_code != 401
    except httpx.HTTPError:
        return True


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
    model_key = validate_secret("model_key", body.get("model_key"), "The model API key")
    if model["provider"] == "openai":
        if not model_key and not settings.server_has_openai_key():
            raise ValidationError("model_key", "This model needs an API key.")
        if model_key and not await _openai_key_ok(model_key):
            raise ValidationError("model_key", "The provider rejected this API key.", "model_key_rejected")
    else:
        model_key = ""
    rpc_key = validate_secret("rpc_key", body.get("rpc_key"), "The RPC key")
    rpc_url = await asyncio.to_thread(resolve_rpc, body.get("rpc_url"), rpc_key)

    report = settings.environment_report()
    if not report["ready"]:
        return _error(503, "environment_not_ready", "The analysis environment is not ready.",
                      issues=report["issues"])
    try:
        run = manager.start(txn_hash=txn_hash, chain=chain, model=model["id"], model_key=model_key, rpc_url=rpc_url)
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
    data["run"] = {"id": run.id, "model": run.model, "chain": run.chain, "created_at": meta["created_at"],
                   "finished_at": meta["finished_at"], "rpc_mode": run.rpc_mode}
    return data


@app.get("/api/capture")
async def capture():
    data = results.reference_capture()
    if not data:
        return _error(404, "no_capture", "No saved capture is available in this deployment.")
    return data


# ---- static console ------------------------------------------------------------------------------
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
