"""FaultSeeker demo server: serves the built UI and runs the real pipeline
(main-1) with per-stage SSE progress. Keys arrive per-request in the POST
body, are set into os.environ only for the duration of that run, and are
removed afterwards. They are never logged or written to disk."""
import io
import json
import os
import multiprocessing as mp
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
    {"id": "gemini-3.8-flash", "label": "Gemini 3.8 Flash (Google)", "keyEnv": "GOOGLE_API_KEY"},
    {"id": "grok-3-mini", "label": "Grok 3 Mini (xAI)", "keyEnv": "XAI_API_KEY"},
    {"id": "claude-3-haiku-20240307", "label": "Claude 3 Haiku (Anthropic)", "keyEnv": "ANTHROPIC_API_KEY"},
    {"id": "qwen-turbo", "label": "Qwen Turbo (Alibaba DashScope)", "keyEnv": "DASHSCOPE_API_KEY"},
    {"id": "nemotron-3.5-lightning-free", "label": "Nemotron 3.5 Lightning free (NaraRouter)", "keyEnv": "NARAROUTER_API_KEY"},
    {"id": "minimax-m3.1-flash:free", "label": "MiniMax M3.1 Flash free (NaraRouter)", "keyEnv": "NARAROUTER_API_KEY"},
    {"id": "agnes-2.5-flash", "label": "agnes 2.5 flash (NaraRouter free)", "keyEnv": "NARAROUTER_API_KEY"},
    {"id": "laguna-s-2.1", "label": "Laguna S 2.1 (NaraRouter free)", "keyEnv": "NARAROUTER_API_KEY"},
    {"id": "qwen/qwen3.8-27b", "label": "Qwen 3.8 27B (Groq)", "keyEnv": "GROQ_API_KEY"},
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
RUN_TIMEOUT_SECS = int(os.environ.get("DEMO_RUN_TIMEOUT_SECS", "1500"))  # hard wall-clock cap per run
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


@app.get("/api/rpc-selftest")
def rpc_selftest(chain: str = "eth", mode: str = "calltracer"):
    """Gated diagnostic: which registered RPC providers can trace from here.

    Hosts only - never returns URLs with embedded keys or provider payloads.
    mode=calltracer | structlogs | replay mirrors the three calls the pipeline
    makes in txn_replayer so we can see exactly which one a provider rejects.
    """
    import faultseeker.utils.rpc_provider as rp

    # eth: a real tx exercises the full trace path; other chains: a dummy hash
    # still separates "method disabled" (provider rejects the call) from
    # "tx not found" (method available).
    probe_tx = ("0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb"
                if chain == "eth" else
                "0x0000000000000000000000000000000000000000000000000000000000000001")
    if mode == "structlogs":
        method = "debug_traceTransaction"
        params = [probe_tx, {"disableMemory": True, "disableStack": False,
                             "disableStorage": False, "timeout": "60s"}]
    elif mode == "structlogs-notimeout":
        method = "debug_traceTransaction"
        params = [probe_tx, {"disableMemory": True, "disableStack": False,
                             "disableStorage": False}]
    elif mode == "structlogs-noconfig":
        method = "debug_traceTransaction"
        params = [probe_tx]
    elif mode == "prestate":
        method = "debug_traceTransaction"
        params = [probe_tx, {"tracer": "prestateTracer", "timeout": "60s"}]
    elif mode == "prestatediff":
        method = "debug_traceTransaction"
        params = [probe_tx, {"tracer": "prestateTracer", "timeout": "60s",
                             "tracerConfig": {"diffMode": True}}]
    elif mode == "replay":
        method = "trace_replayTransaction"
        params = [probe_tx, ["trace", "stateDiff"]]
    else:
        method = "debug_traceTransaction"
        params = [probe_tx, {"tracer": "callTracer", "timeout": "60s"}]
    out = []
    for prov in rp._registry._providers(chain):
        host = re.sub(r"(https?://[^/\s]+).*", r"\1", prov.url)
        try:
            body = json.dumps({"jsonrpc": "2.0", "method": method,
                               "params": params, "id": 1}).encode()
            data = rp._http_post(prov.url, body, timeout=45)
            result = rp._check_rpc_error(data)
            entry = {"host": host, "ok": bool(result)}
            if isinstance(result, dict):
                entry["result_keys"] = sorted(result.keys())[:8]
                logs = result.get("structLogs")
                if isinstance(logs, list):
                    entry["struct_logs"] = len(logs)
            out.append(entry)
        except Exception as e:  # noqa: BLE001 - diagnostic reports every failure type
            out.append({"host": host, "ok": False,
                        "err": f"{type(e).__name__}: {str(e)[:140]}"})
    return {"chain": chain, "mode": mode, "providers": out}


@app.get("/api/llm-selftest")
def llm_selftest(model: str = "gemini-3.8-flash", max_keys: int = 2):
    """Gated diagnostic: one real 8-token LLM call per configured key.

    Reports per-key ok/error (type + first chars) - never returns key material.
    Mirrors what the pipeline's UniversalAgent does so we can see the exact
    provider error that the agent layer swallows as 'An error occurred.'
    """
    entry = next((m for m in MODELS if m["id"] == model), None)
    if not entry or not entry.get("keyEnv"):
        return {"model": model, "error": "unknown or keyless model"}
    keys = _key_list(entry["keyEnv"])
    out = []
    import openai as _oai
    from faultseeker.utils.agent import PROVIDER_CONFIG
    base_url = None
    for prefix, cfg in PROVIDER_CONFIG.items():
        if model.startswith(prefix):
            base_url = cfg[0]
            break
    for i, k in enumerate(keys[:max(1, max_keys)]):
        try:
            client = _oai.OpenAI(api_key=k, base_url=base_url, timeout=30)
            r = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Reply with the single word: ok"}],
                max_tokens=8,
            )
            out.append({"key_index": i + 1, "ok": True,
                        "reply": (r.choices[0].message.content or "")[:40]})
        except Exception as e:  # noqa: BLE001 - diagnostic reports every failure type
            out.append({"key_index": i + 1, "ok": False,
                        "err": f"{type(e).__name__}: {str(e)[:160]}"})
    return {"model": model, "base_url": base_url, "keys": out, "key_count": len(keys)}


@app.get("/healthz")
async def healthz():
    return {"ok": True}



def sse(ev, data):
    return f"event: {ev}\ndata: {json.dumps(data)}\n\n"


def worker(run_id, req, q):
    """Runs in a child process: events go to the parent via q (mp.Queue), the
    result is delivered ONLY through the JSON file in RUNS_DIR."""
    # Fork inherits uvicorn's SIGTERM/SIGINT handlers, which would swallow
    # terminate()/cancel: restore default disposition so the watchdog works.
    import signal
    for _sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(_sig, signal.SIG_DFL)
        except (OSError, ValueError):
            pass
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
        # Groq's free tier caps output tokens/min hard; parallel Stage 2 workers
        # blow through it together. Serialize unless the caller overrides.
        _groqish = (req.get("mode") or "").startswith(("qwen/", "openai/gpt-oss", "allam-", "llama-"))
        s2w = str(req.get("stage2_workers") or ("1" if _groqish else "")).strip()
        if s2w:
            env_prior["FAULTSEEKER_STAGE2_WORKERS"] = os.environ.get("FAULTSEEKER_STAGE2_WORKERS")
            os.environ["FAULTSEEKER_STAGE2_WORKERS"] = s2w
            env_set.append("FAULTSEEKER_STAGE2_WORKERS")
        fb_model = (req.get("fallback_model") or "").strip()
        if fb_model:
            env_prior["FAULTSEEKER_LLM_FALLBACK_MODEL"] = os.environ.get("FAULTSEEKER_LLM_FALLBACK_MODEL")
            os.environ["FAULTSEEKER_LLM_FALLBACK_MODEL"] = fb_model
            env_set.append("FAULTSEEKER_LLM_FALLBACK_MODEL")
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
            if model_key:
                raw_keys = re.sub(r"[\s,;]+", " ", model_key).split()
                keys = [k.strip().strip('"').strip("'") for k in raw_keys if k.strip()]
            else:
                keys = _key_list(entry["keyEnv"])
            if not keys:
                raise ValueError(f"model {mode} needs an API key (Settings, or server env {entry['keyEnv']})")
            if entry["keyEnv"] not in env_set:
                env_prior[entry["keyEnv"]] = os.environ.get(entry["keyEnv"])
                env_set.append(entry["keyEnv"])
            # Optional per-stage split: a different model (and key) for Stage 1.
            forensics = (req.get("forensics_model") or "").strip() or mode
            f_entry = next((m for m in MODELS if m["id"] == forensics), None)
            if not f_entry or not f_entry.get("keyEnv"):
                raise ValueError(f"unknown forensics model {forensics}")
            if forensics != mode:
                # Different Stage 1 provider: needs its own key material.
                f_key = (req.get("forensics_model_key") or "").strip()
                if f_key:
                    f_keys = [k.strip().strip('"').strip("'") for k in re.sub(r"[\s,;]+", " ", f_key).split() if k.strip()]
                else:
                    f_keys = _key_list(f_entry["keyEnv"])
                if not f_keys:
                    raise ValueError(f"forensics model {forensics} needs an API key")
                if f_entry["keyEnv"] not in env_set:
                    env_prior[f_entry["keyEnv"]] = os.environ.get(f_entry["keyEnv"])
                    env_set.append(f_entry["keyEnv"])
                os.environ[f_entry["keyEnv"]] = "\n".join(f_keys)
            if len(keys) > 1:
                os.environ[entry["keyEnv"]] = "\n".join(keys)
            for ki, one_key in enumerate(keys):
                if len(keys) == 1:
                    os.environ[entry["keyEnv"]] = one_key
                which = f" (key {ki + 1}/{len(keys)})" if len(keys) > 1 else ""
                split_note = f", Stage 1 on {forensics}" if forensics != mode else ""
                q.put(("log", f"mode: full pipeline Stage 1-3 with {mode}{which}{split_note} (cost tracking on)"))
                try:
                    result = fs_main(txn_hash=req["txn_hash"], chain=req["chain"],
                                     forensics_model=forensics, function_analysis_model=mode,
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
    runs[run_id] = {"q": queue.Queue(), "result": None, "proc": None}
    req["chain"] = chain
    req["txn_hash"] = tx

    def guarded():
        """Owns the child process: drains its event queue, enforces the hard
        run timeout, releases the global lock exactly once."""
        q = runs[run_id]["q"]
        mp_q = mp.Queue()
        proc = mp.Process(target=worker, args=(run_id, req, mp_q), daemon=True)
        proc.start()
        runs[run_id]["proc"] = proc
        deadline = time.time() + RUN_TIMEOUT_SECS
        ended = False
        try:
            while True:
                try:
                    ev, data = mp_q.get(timeout=2)
                    q.put((ev, data))
                    if ev == "end":
                        ended = True
                        break
                except queue.Empty:
                    pass
                if not proc.is_alive():
                    # drain whatever the child flushed before exiting
                    while True:
                        try:
                            ev, data = mp_q.get(timeout=0.2)
                            q.put((ev, data))
                            if ev == "end":
                                ended = True
                        except queue.Empty:
                            break
                    break
                if time.time() > deadline:
                    proc.terminate()
                    q.put(("error", f"run exceeded the {RUN_TIMEOUT_SECS // 60}-minute limit and was cancelled"))
                    break
            proc.join(timeout=5)
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=5)
        finally:
            if not ended:
                q.put(("end", None))
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


@app.post("/api/cancel/{run_id}")
async def cancel(run_id: str):
    r = runs.get(run_id)
    if not r:
        return JSONResponse({"error": "unknown run"}, status_code=404)
    proc = r.get("proc")
    if proc and proc.is_alive():
        proc.terminate()  # the watchdog notices and releases the lock
        r["q"].put(("log", "cancel requested - terminating the run process"))
        return {"cancelled": True}
    return {"cancelled": False, "reason": "no live process for this run"}


@app.get("/api/result/{run_id}")
async def result(run_id: str):
    r = runs.get(run_id)
    if r and r["result"] is not None:
        pass
    else:
        # the worker runs in a child process; its result arrives as a file
        out_path = os.path.join(RUNS_DIR, run_id + ".json")
        if not os.path.exists(out_path):
            return JSONResponse({"error": "no result yet"}, status_code=404)
        try:
            with open(out_path, encoding="utf-8") as f:
                r = runs.setdefault(run_id, {"q": queue.Queue(), "result": None, "proc": None})
                r["result"] = json.load(f)
        except (OSError, json.JSONDecodeError):
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
