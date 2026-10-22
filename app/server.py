"""FaultSeeker demo server: serves the built UI and runs the real pipeline
(main-1) with per-stage SSE progress. Keys arrive per-request in the POST
body, are set into os.environ only for the duration of that run, and are
removed afterwards. They are never logged or written to disk."""
import io
import json
import os
import queue
import re
import sys
import threading
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.environ.get("FAULTSEEKER_REPO", os.path.normpath(os.path.join(HERE, "..", "FaultSeeker-")))
CAPTURE = os.environ.get("FAULTSEEKER_CAPTURE", os.path.join(REPO, "demo_outputs", "eth_0x0788ba22.json"))
RUNS_DIR = os.path.join(HERE, "runs")
os.makedirs(RUNS_DIR, exist_ok=True)
if os.path.isdir(REPO):
    sys.path.insert(0, REPO)

CHAINS = ["eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche", "base",
          "fantom", "zksync", "linea", "scroll", "gnosis", "celo", "cronos", "moonbeam", "aurora"]
MODELS = [
    {"id": "no-llm", "label": "No LLM - deterministic Stage 1 (free RPC)", "keyEnv": None},
    {"id": "gpt-4o-mini", "label": "GPT-4o Mini (OpenAI)", "keyEnv": "OPENAI_API_KEY"},
    {"id": "gemini-2.0-flash", "label": "Gemini 2.0 Flash (Google)", "keyEnv": "GOOGLE_API_KEY"},
    {"id": "grok-3-mini", "label": "Grok 3 Mini (xAI)", "keyEnv": "XAI_API_KEY"},
    {"id": "claude-3-haiku-20240307", "label": "Claude 3 Haiku (Anthropic)", "keyEnv": "ANTHROPIC_API_KEY"},
    {"id": "qwen-turbo", "label": "Qwen Turbo (Alibaba DashScope)", "keyEnv": "DASHSCOPE_API_KEY"},
]


def _key_list(env_name):
    """Parse an env var holding one or many API keys.

    Tolerates newline/comma/space separators and .env-style VAR= prefixes,
    so a pasted multi-line .env chunk works as-is. Returns bare keys.
    """
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return []
    keys = []
    for tok in re.split(r"[\s,;]+", raw):
        tok = tok.strip().strip('"').strip("'")
        if not tok:
            continue
        if "=" in tok:
            name, _, tok = tok.partition("=")
            # .env dumps often carry sibling config lines (XAI_MODEL=,
            # XAI_BASE_URL=, ...); only *_API_KEY* assignments are keys.
            if "API_KEY" not in name:
                continue
        tok = tok.strip()
        if tok:
            keys.append(tok)
    return keys


# stdout fragments from the real pipeline -> UI stage index (0..4)
STAGE_LINES = [
    ("Collecting transaction sequence", 0), ("Collecting transaction info", 0),
    ("Fetching transaction data from blockchain", 0),
    ("Analyzing execution trace", 1),
    ("Extracting deterministic signals", 2), ("Forensics analysis completed", 2),
    ("Rule verdict", 3),
    ("Classifying addresses", 4), ("Identifying vulnerable functions", 4),
    ("Stage 2", 4), ("Ranking suspicious functions", 4), ("Analyzing vulnerable functions", 4),
    ("Stage 3", 4), ("Calibrated", 4),
]

runs = {}
run_lock = threading.Lock()

app = FastAPI()


# --- hosted-demo protection: access gate + per-IP run limits ----------------
import hashlib
import hmac
import time

from fastapi.responses import HTMLResponse, RedirectResponse

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8420"))
GATE = os.environ.get("DEMO_GATE_PASSWORD", "").strip()
RUN_LIMIT_PER_HOUR = int(os.environ.get("DEMO_RUN_LIMIT_PER_HOUR", "10"))
RUN_LIMIT_PER_DAY = int(os.environ.get("DEMO_RUN_LIMIT_PER_DAY", "40"))
_runs_by_ip = {}


def _gate_token():
    return hmac.new(GATE.encode(), b"faultseeker-demo-gate", hashlib.sha256).hexdigest()


GATE_PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>FaultSeeker demo - access</title><style>
body{background:#0a0f0a;color:#c8e6c9;font-family:monospace;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
form{border:1px solid #2e4d2e;padding:2rem;display:flex;flex-direction:column;gap:1rem;min-width:280px}
input,button{background:#0f1a0f;border:1px solid #2e4d2e;color:#c8e6c9;font-family:monospace;padding:.6rem;font-size:1rem}
button{cursor:pointer;background:#16301a}.err{color:#ff7070;font-size:.85rem}</style></head>
<body><form method=post action="/gate">
<div><b>FaultSeeker // Forensic Console</b></div>
<div>Enter the demo access code</div>
<input type=password name=password autofocus autocomplete=current-password>
<button type=submit>Enter</button>__ERR__</form></body></html>"""


@app.middleware("http")
async def gate_and_limit(request: Request, call_next):
    path = request.url.path
    if path in ("/healthz", "/gate"):
        return await call_next(request)
    if GATE:
        cookie = request.cookies.get("fs_gate", "")
        if not hmac.compare_digest(cookie, _gate_token()):
            return RedirectResponse(url="/gate", status_code=303)
    if path == "/api/analyze" and request.method == "POST":
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        stamps = [t for t in _runs_by_ip.get(ip, []) if now - t < 86400]
        if len([t for t in stamps if now - t < 3600]) >= RUN_LIMIT_PER_HOUR or len(stamps) >= RUN_LIMIT_PER_DAY:
            return JSONResponse({"error": "run limit reached for this network, try later"}, status_code=429)
        stamps.append(now)
        _runs_by_ip[ip] = stamps
    return await call_next(request)


@app.get("/gate", response_class=HTMLResponse)
async def gate_form():
    return GATE_PAGE.replace("__ERR__", "")


@app.post("/gate")
async def gate_submit(request: Request):
    form = await request.form()
    if GATE and hmac.compare_digest(str(form.get("password", "")), GATE):
        resp = RedirectResponse(url="/", status_code=303)
        resp.set_cookie("fs_gate", _gate_token(), max_age=7 * 24 * 3600,
                        httponly=True, samesite="lax", secure=True)
        return resp
    return HTMLResponse(GATE_PAGE.replace("__ERR__", '<div class=err>wrong code</div>'), status_code=401)


@app.get("/healthz")
async def healthz():
    return {"ok": True}



def sse(ev, data):
    return f"event: {ev}\ndata: {json.dumps(data)}\n\n"


def worker(run_id, req):
    q = runs[run_id]["q"]
    env_set = []
    env_prior = {}

    class Tap(io.TextIOBase):
        def write(self, s):
            if s and s.strip():
                # Never stream credentials to the browser: the fork echoes
                # full RPC URLs (keys embedded) in its diagnostics.
                line = re.sub(r"(https?://[^/\s'\"]+)[^\s)'\"]*", r"\1/•••", s.strip())
                for pat, idx in STAGE_LINES:
                    if pat in line:
                        q.put(("stage", {"index": idx}))
                        break
                q.put(("log", line[:220]))
            return len(s) if s else 0

    old_out = sys.stdout
    sys.stdout = Tap()
    try:
        rpc_url = (req.get("rpc_url") or "").strip()
        rpc_key = (req.get("rpc_key") or "").strip()
        model_key = (req.get("model_key") or "").strip()
        if rpc_url:
            # The pipeline reads {CHAIN}_RPC_URL (key embedded in the URL for
            # dRPC/BlockPI style endpoints). Request value wins over server env.
            var = f"{req['chain'].upper()}_RPC_URL"
            env_prior[var] = os.environ.get(var)
            os.environ[var] = rpc_url
            env_set.append(var)

        mode = req.get("mode", "no-llm")
        from faultseeker.main import main as fs_main

        out_path = os.path.join(RUNS_DIR, run_id + ".json")
        if mode == "no-llm":
            q.put(("log", "mode: no-llm (deterministic Stage 1, free RPC)"))
            result = fs_main(txn_hash=req["txn_hash"], chain=req["chain"],
                             no_llm=True, output_path=out_path)
        else:
            entry = next((m for m in MODELS if m["id"] == mode), None)
            if not entry:
                raise ValueError(f"unknown model {mode}")
            keys = [model_key] if model_key else _key_list(entry["keyEnv"])
            if not keys:
                raise ValueError(f"model {mode} needs an API key (Settings, or server env {entry['keyEnv']})")
            if entry["keyEnv"] not in env_set:
                env_prior[entry["keyEnv"]] = os.environ.get(entry["keyEnv"])
                env_set.append(entry["keyEnv"])
            for ki, one_key in enumerate(keys):
                os.environ[entry["keyEnv"]] = one_key
                which = f" (key {ki + 1}/{len(keys)})" if len(keys) > 1 else ""
                q.put(("log", f"mode: full pipeline Stage 1-3 with {mode}{which} (cost tracking on)"))
                try:
                    result = fs_main(txn_hash=req["txn_hash"], chain=req["chain"],
                                     forensics_model=mode, function_analysis_model=mode,
                                     track_cost=True, output_path=out_path)
                    break
                except Exception as key_err:  # noqa: BLE001 - rotate fallback keys on auth/quota failures
                    low = f"{type(key_err).__name__} {key_err}".lower()
                    retryable = any(t in low for t in (
                        "rate limit", "ratelimit", "429", "quota", "resource exhausted",
                        "resource_exhausted", "401", "403", "unauthorized",
                        "unauthenticated", "invalid api key", "api key not valid",
                        "permission denied"))
                    if ki < len(keys) - 1 and retryable:
                        q.put(("log", f"{entry['keyEnv']} key {ki + 1} failed ({type(key_err).__name__}); rotating to fallback key {ki + 2}"))
                        continue
                    raise
        result["_demo_model_requested"] = mode
        runs[run_id]["result"] = result
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f)
        q.put(("done", {"ok": True}))
    except Exception as e:  # noqa: BLE001 - surface any pipeline failure as fallback trigger
        q.put(("error", f"{type(e).__name__}: {str(e)[:400]}"))
    finally:
        sys.stdout = old_out
        for k in env_set:
            if env_prior.get(k) is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = env_prior[k]
        q.put(("end", None))


@app.post("/api/analyze")
async def analyze(request: Request):
    req = await request.json()
    tx = (req.get("txn_hash") or "").strip()
    chain = (req.get("chain") or "eth").strip().lower()
    if not (tx.startswith("0x") and len(tx) == 66):
        return JSONResponse({"error": "transaction hash must be 0x + 64 hex chars"}, status_code=400)
    if chain not in CHAINS:
        return JSONResponse({"error": f"unsupported chain {chain}"}, status_code=400)
    if not run_lock.acquire(blocking=False):
        return JSONResponse({"error": "a run is already in progress"}, status_code=409)
    run_id = uuid.uuid4().hex[:12]
    runs[run_id] = {"q": queue.Queue(), "result": None}
    req["chain"] = chain
    req["txn_hash"] = tx

    def guarded():
        try:
            worker(run_id, req)
        finally:
            run_lock.release()

    threading.Thread(target=guarded, daemon=True).start()
    return {"run_id": run_id}


@app.get("/api/stream/{run_id}")
async def stream(run_id: str):
    if run_id not in runs:
        return JSONResponse({"error": "unknown run"}, status_code=404)
    q = runs[run_id]["q"]

    def gen():
        while True:
            ev, data = q.get()
            if ev == "end":
                yield sse("end", {})
                break
            yield sse(ev, data)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/result/{run_id}")
async def result(run_id: str):
    r = runs.get(run_id)
    if not r or r["result"] is None:
        return JSONResponse({"error": "no result yet"}, status_code=404)
    # strip internal helper fields before sending to the page
    out = {k: v for k, v in r["result"].items() if not k.startswith("_demo_")}
    return JSONResponse(out)


@app.get("/api/capture")
async def capture():
    return FileResponse(CAPTURE, media_type="application/json")


@app.get("/api/config")
async def config():
    return {"chains": CHAINS, "models": MODELS, "repo_present": os.path.isdir(REPO)}


web = os.path.normpath(os.path.join(HERE, "web"))
if os.path.isdir(web):
    app.mount("/", StaticFiles(directory=web, html=True), name="web")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
