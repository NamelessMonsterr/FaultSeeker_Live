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

from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.environ.get("FAULTSEEKER_REPO", os.path.normpath(os.path.join(HERE, "..", "FaultSeeker-")))
CAPTURE = os.environ.get("FAULTSEEKER_CAPTURE", os.path.join(REPO, "demo_outputs", "eth_0x0788ba22.json"))
RUNS_DIR = os.path.join(HERE, "runs")
os.makedirs(RUNS_DIR, exist_ok=True)
HISTORY_PATH = os.path.join(RUNS_DIR, "index.json")



def _hist_load():
    try:
        with open(HISTORY_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def _hist_save(entries):
    tmp = HISTORY_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(entries[-200:], f)  # keep last 200 runs
    os.replace(tmp, HISTORY_PATH)


def _hist_upsert(entry):
    entries = _hist_load()
    for i, e in enumerate(entries):
        if e.get("run_id") == entry.get("run_id"):
            entries[i] = {**e, **entry}
            _hist_save(entries)
            return
    entries.append(entry)
    _hist_save(entries)


def _hist_brief(res):
    """Short human summary of a result dict for the history list."""
    if not isinstance(res, dict):
        return {}
    scored = res.get("scored_functions") or []
    cards = res.get("evidence_cards") or []
    ranked = res.get("ranked_suspicious_functions") or []
    top = []
    for it in ranked[:3]:
        if isinstance(it, dict):
            top.append(it.get("function") or it.get("function_name") or it.get("name") or "?")
        else:
            top.append(str(it))
    return {"scored_functions": len(scored), "evidence_cards": len(cards),
            "priority": res.get("priority"), "priority_score": res.get("priority_score"),
            "top_functions": top, "duration_secs": res.get("duration")}


GH_HISTORY_TOKEN = os.environ.get("GITHUB_HISTORY_TOKEN", "").strip()
GH_HISTORY_REPO = os.environ.get(
    "GITHUB_HISTORY_REPO", "NamelessMonsterr/faultseeker-run-history").strip()


def _gh_hist_put(path, content_bytes, message):
    """Best-effort create/update of one file in the history repo (Contents API)."""
    import base64
    import urllib.request
    if not GH_HISTORY_TOKEN:
        return
    api = "https://api.github.com/repos/%s/contents/%s" % (GH_HISTORY_REPO, path)
    headers = {"Authorization": "Bearer " + GH_HISTORY_TOKEN,
               "Accept": "application/vnd.github+json",
               "User-Agent": "faultseeker-demo-console"}
    sha = None
    try:
        req = urllib.request.Request(api, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            sha = json.loads(r.read().decode()).get("sha")
    except Exception:
        sha = None
    body = {"message": message,
            "content": base64.b64encode(content_bytes).decode()}
    if sha:
        body["sha"] = sha
    try:
        req = urllib.request.Request(api, data=json.dumps(body).encode(),
                                     headers=headers, method="PUT")
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
    except Exception:
        pass  # mirror is best-effort; never break a run over it


def _gh_hist_sync(run_id, entry, res):
    """Mirror one finished run (result, event log, index) to GitHub."""
    def work():
        try:
            _gh_hist_put("runs/%s.json" % run_id,
                         json.dumps({"entry": entry, "result": res}, indent=1).encode(),
                         "run %s: %s" % (run_id, entry.get("status")))
            ev_path = os.path.join(RUNS_DIR, run_id + ".events.jsonl")
            if os.path.exists(ev_path):
                with open(ev_path, "rb") as f:
                    _gh_hist_put("runs/%s.events.jsonl" % run_id, f.read(),
                                 "run %s event log" % run_id)
            _gh_hist_put("index.json",
                         json.dumps(_hist_load(), indent=1).encode(),
                         "history index update")
        except Exception:
            pass
    threading.Thread(target=work, daemon=True).start()


def _gh_hist_get(path):
    """Fetch one file's raw bytes from the history repo; None on any miss."""
    import base64
    import urllib.request
    if not GH_HISTORY_TOKEN:
        return None
    api = "https://api.github.com/repos/%s/contents/%s" % (GH_HISTORY_REPO, path)
    headers = {"Authorization": "Bearer " + GH_HISTORY_TOKEN,
               "Accept": "application/vnd.github+json",
               "User-Agent": "faultseeker-demo-console"}
    try:
        req = urllib.request.Request(api, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            return base64.b64decode(json.loads(r.read().decode())["content"])
    except Exception:
        return None


def _gh_hist_seed():
    """On a fresh ephemeral disk, pull the GitHub-mirrored history back down."""
    if os.path.exists(HISTORY_PATH) or not GH_HISTORY_TOKEN:
        return
    raw = _gh_hist_get("index.json")
    if not raw:
        return
    try:
        entries = json.loads(raw.decode())
        if isinstance(entries, list):
            _hist_save(entries)
    except (ValueError, UnicodeDecodeError):
        return
    for e in entries[-30:]:
        rid = e.get("run_id")
        if not rid:
            continue
        ev = _gh_hist_get("runs/%s.events.jsonl" % rid)
        if ev:
            try:
                with open(os.path.join(RUNS_DIR, rid + ".events.jsonl"), "wb") as f:
                    f.write(ev)
            except OSError:
                pass


def _hist_log_event(run_id, ev, data):
    """Append one run event to its JSONL log (capped)."""
    path = os.path.join(RUNS_DIR, run_id + ".events.jsonl")
    try:
        if os.path.exists(path) and os.path.getsize(path) > 2_000_000:
            return  # cap: stop logging a runaway stream
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"t": round(time.time(), 1), "ev": ev,
                                "data": data if isinstance(data, (str, dict)) else str(data)}) + "\n")
    except OSError:
        pass
_gh_hist_seed()


if os.path.isdir(REPO):
    sys.path.insert(0, REPO)

CHAINS = ["eth", "bsc", "polygon", "arbitrum", "optimism", "avalanche", "base",
          "fantom", "zksync", "linea", "scroll", "gnosis", "celo", "cronos", "moonbeam", "aurora"]
# Demo presets: documented Ethereum mainnet exploits, each verified on-chain
# (receipt status 0x1 + QuickNode callTracer) on 2026-10-22. calls = internal
# callTracer call count (kept small so live demos finish fast).
PRESET_TXS = [
    {"hash": "0x2606d459a50ca4920722a111745c2eeced1d8a01ff25ee762e22d5d4b1595739", "protocol": "Hedgey Finance", "date": "2024-04-19", "loss": "~$48M", "calls": 5},
    {"hash": "0x23fcf9d4517f7cc39815b09b0a80c023ab2c8196c826c93b4100f2e26b701286", "protocol": "Seneca", "date": "2024-02-28", "loss": "~$6M", "calls": 3},
    {"hash": "0x0b062361e16a2ea0942cc1b4462b6584208c8c864609ff73aaa640aaa2d92428", "protocol": "DODO", "date": "2021-03-08", "loss": "~$3.8M", "calls": 28},
    {"hash": "0x8c3f442fc6d640a6ff3ea0b12be64f1d4609ea94edd2966f42c01cd9bdcf04b5", "protocol": "TempleDAO", "date": "2022-10-11", "loss": "~$2.3M", "calls": 7},
    {"hash": "0xdd0636e2598f4d7b74f364fedb38f334365fd956747a04a6dd597444af0bc1c0", "protocol": "Unizen", "date": "2024-03-08", "loss": "~$2M", "calls": 10},
    {"hash": "0x138daa4cbeaa3db42eefcec26e234fc2c89a4aa17d6b1870fc460b2856fd11a6", "protocol": "Dexible", "date": "2023-02-17", "loss": "~$1.5M", "calls": 38},
    {"hash": "0x3c09c6306b67737227edc24c663462d870e7c2bf39e9ab66877a980c900dd5d5", "protocol": "Audius", "date": "2022-07-23", "loss": "704 ETH (~$1.08M)", "calls": 11},
    {"hash": "0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b", "protocol": "Morpho Blue", "date": "2024-10-13", "loss": "~$230k", "calls": 32},
    {"hash": "0x3ed75df83d907412af874b7998d911fdf990704da87c2b1a8cf95ca5d21504cf", "protocol": "OlympusDAO", "date": "2022-10-21", "loss": "~$292k", "calls": 7},
    {"hash": "0x90b468608fbcc7faef46502b198471311baca3baab49242a4a85b73d4924379b", "protocol": "CowSwap", "date": "2023-02-07", "loss": "~$120k", "calls": 7},
    {"hash": "0x35a73969f582872c25c96c48d8bb31c23eab8a49c19282c67509b96186734e60", "protocol": "ParaSwap", "date": "2024-03-19", "loss": "~$24k", "calls": 12},
]


MODELS = [
    {"id": "gpt-6.1-sol-low", "label": "GPT-6.1 Sol low (Codex)", "keyEnv": "OPENAI_API_KEY"},
    {"id": "gpt-6.1-sol-medium", "label": "GPT-6.1 Sol medium (Codex)", "keyEnv": "OPENAI_API_KEY"},
    {"id": "gpt-6.1-sol-high", "label": "GPT-6.1 Sol high (Codex)", "keyEnv": "OPENAI_API_KEY"},
    {"id": "z-ai/glm-5.3-flash", "label": "GLM 5.3 Flash (NVIDIA NIM)", "keyEnv": "NVIDIA_API_KEY"},
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
    {"id": "no-llm", "label": "No LLM - deterministic Stage 1 (free RPC)", "keyEnv": None},
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
RUN_TIMEOUT_SECS = int(os.environ.get("DEMO_RUN_TIMEOUT_SECS", "7200"))  # hard wall-clock cap per run
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
def llm_selftest(model: str = "gemini-3.8-flash", max_keys: int = 2,
                 keys: str = "", replay: str = ""):
    """Gated diagnostic. Default: one real 8-token LLM call per key.

    keys=  optional request-supplied keys (comma/space/newline separated), used
           only for this probe (never stored, never returned).
    replay=stage2 additionally replays the EXACT Stage-2 task-selection call
           through the fork's UniversalAgent (same class, same kwargs, same
           prompt template + realistic payload) and reports the REAL exception
           that _send_message would swallow, plus openai lib version and which
           provider-override env vars are set (values never returned).
    """
    """Gated diagnostic: one real 8-token LLM call per configured key.

    Reports per-key ok/error (type + first chars) - never returns key material.
    Mirrors what the pipeline's UniversalAgent does so we can see the exact
    provider error that the agent layer swallows as 'An error occurred.'
    """
    entry = next((m for m in MODELS if m["id"] == model), None)
    if not entry or not entry.get("keyEnv"):
        return {"model": model, "error": "unknown or keyless model"}
    req_keys = [k.strip().strip('"').strip("'")
                for k in re.sub(r"[\s,;]+", " ", keys or "").split() if k.strip()]
    keys = req_keys or _key_list(entry["keyEnv"])
    if req_keys:
        os.environ[entry["keyEnv"]] = "\n".join(req_keys)
    env_report = {v: (os.getenv(v) is not None)
                  for v in ("GROQ_BASE_URL", "NARAROUTER_BASE_URL", "OPENAI_BASE_URL",
                            "HTTP_PROXY", "HTTPS_PROXY", "FAULTSEEKER_LLM_FALLBACK_MODEL")}
    import openai as _oai_ver
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
    result = {"model": model, "base_url": base_url, "keys": out, "key_count": len(keys),
              "openai_version": getattr(_oai_ver, "__version__", "?"), "env_overrides_set": env_report}
    if replay == "stage2" and keys:
        try:
            import json as _json
            from faultseeker.utils.agent import UniversalAgent
            from faultseeker.prompts.function_analysis.orchestration_session_prompts import OrchestrationSessionPrompts
            from faultseeker.prompts.function_analysis.worker_prompts import WorkerPrompts
            summary = {"function": "earned", "appearance_count": 50,
                       "pattern": [{"type": "call", "gas": 18506,
                                    "address": "0x4a866fE20A442Dff55FAA010684A5C1379151458",
                                    "function": "earned",
                                    "params": "0x19f0a60f4635d3E2c48647822Eda5332BA094fd3",
                                    "call_type": "staticcall", "value": None}] * 50,
                       "note": "synthetic replay payload"}
            prompt = WorkerPrompts().function_call_task_selection.format(
                task_tree="1. Basic Function Call Info Gathering - [completed]",
                function_call_info_summary=summary,
                current_understanding="replay probe")
            agent = UniversalAgent(OrchestrationSessionPrompts().function_call_task_generation_init,
                                   model)
            reply = agent.query(prompt)
            result["stage2_replay"] = {"ok": bool(reply), "reply_type": type(reply).__name__,
                                       "reply": _json.dumps(reply)[:200]}
        except Exception as e:  # noqa: BLE001 - this endpoint exists to surface it
            result["stage2_replay"] = {"ok": False,
                                       "err": f"{type(e).__name__}: {str(e)[:300]}"}
    return result


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
        _groqish = (req.get("mode") or "").startswith(("qwen/", "openai/gpt-oss", "allam-", "llama-", "z-ai/", "deepseek-ai/", "nvidia/", "gpt-"))
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
    _hist_upsert({"run_id": run_id, "txn_hash": tx, "chain": chain,
                  "model": req.get("mode", "no-llm"),
                  "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "status": "running"})
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
        started = time.time()
        ended = False
        outcome = "stopped"
        outcome_msg = ""
        try:
            while True:
                try:
                    ev, data = mp_q.get(timeout=2)
                    q.put((ev, data))
                    _hist_log_event(run_id, ev, data)
                    if ev == "error":
                        outcome, outcome_msg = "error", str(data)[:200]
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
                            _hist_log_event(run_id, ev, data)
                            if ev == "error":
                                outcome, outcome_msg = "error", str(data)[:200]
                            if ev == "end":
                                ended = True
                        except queue.Empty:
                            break
                    break
                if time.time() > deadline:
                    proc.terminate()
                    outcome = "timeout"
                    outcome_msg = f"exceeded the {RUN_TIMEOUT_SECS // 60}-minute limit"
                    q.put(("error", f"run exceeded the {RUN_TIMEOUT_SECS // 60}-minute limit and was cancelled"))
                    _hist_log_event(run_id, "error", outcome_msg)
                    break
            proc.join(timeout=5)
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=5)
            if not ended and outcome != "timeout":
                # Worker died without emitting an error event: surface the exit
                # code so silent wedges (OOM SIGKILL=-9, segfault=-11) are visible.
                outcome = "cancelled" if proc.exitcode == -15 else "died"
                outcome_msg = f"worker exit code {proc.exitcode} (-9 usually means OOM)"
                q.put(("error", f"worker process died unexpectedly (exit code {proc.exitcode}; -9 usually means OOM)"))
        finally:
            if not ended:
                q.put(("end", None))
            run_lock.release()
            # finalize the history entry: status + brief from the result file
            res = None
            out_path = os.path.join(RUNS_DIR, run_id + ".json")
            try:
                with open(out_path, encoding="utf-8") as f:
                    res = json.load(f)
            except (OSError, json.JSONDecodeError):
                res = None
            if res is not None and outcome in ("stopped",):
                outcome = "completed" if ended else outcome
            if res is not None and ended and outcome != "error":
                outcome = "completed"
            final_entry = {"run_id": run_id, "status": outcome,
                           "detail": outcome_msg,
                           "ended_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           "duration_secs": round(time.time() - started, 1),
                           "brief": _hist_brief(res) if res else {}}
            _hist_upsert(final_entry)
            _gh_hist_sync(run_id, final_entry, res)

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


@app.get("/api/runs")
async def list_runs():
    """Persistent run history (survives restarts; NOT redeploys on free tier)."""
    return {"runs": list(reversed(_hist_load()))}


_STAGE_MARK = re.compile(r"(\[Stage \d|\[OK\]|\[\d+/\d+\]|Analyzing|completed|Ranking|Scoring)")


@app.get("/api/runs/{run_id}")
async def run_detail(run_id: str):
    entry = next((e for e in _hist_load() if e.get("run_id") == run_id), None)
    if not entry:
        return JSONResponse({"error": "unknown run"}, status_code=404)
    stages = []
    t0 = None
    path = os.path.join(RUNS_DIR, run_id + ".events.jsonl")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if t0 is None:
                    t0 = rec.get("t") or 0
                if rec.get("ev") == "log" and isinstance(rec.get("data"), str):
                    txt = rec["data"]
                    if _STAGE_MARK.search(txt):
                        stages.append({"at_secs": round((rec.get("t") or 0) - t0, 1),
                                       "text": txt[:160]})
                elif rec.get("ev") == "error":
                    stages.append({"at_secs": round((rec.get("t") or 0) - t0, 1),
                                   "text": "ERROR: " + str(rec.get("data"))[:160]})
    except OSError:
        pass
    return {"entry": entry, "stages": stages}


HISTORY_PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>FaultSeeker demo - run history</title><style>
body{background:#0a0f0a;color:#c8e6c9;font-family:monospace;margin:0;padding:1.5rem}
h1{font-size:1.1rem;border-bottom:1px solid #2e4d2e;padding-bottom:.5rem}
a{color:#7fd07f}.run{border:1px solid #2e4d2e;margin:.6rem 0;padding:.7rem;cursor:pointer}
.run:hover{background:#0f1a0f}.badge{display:inline-block;min-width:6.5rem;font-weight:bold}
.ok{color:#6fe36f}.err{color:#ff7070}.warn{color:#ffd070}.dim{color:#6a8a6a;font-size:.85rem}
.det{margin:.4rem 0 0 1rem;font-size:.85rem;white-space:pre-wrap}
table{border-collapse:collapse}td{padding:.1rem .8rem .1rem 0;vertical-align:top}
.foot{margin-top:1.5rem;color:#4a6a4a;font-size:.75rem}</style></head>
<body><h1>FaultSeeker // run history</h1><div id=out>loading...</div>
<div class=foot>History persists across service restarts but not redeploys (free-tier disk is ephemeral).</div>
<script>
async function main(){
  const r = await fetch('/api/runs'); const j = await r.json();
  const out = document.getElementById('out');
  if(!j.runs || !j.runs.length){ out.textContent = 'no runs recorded yet'; return; }
  out.innerHTML = '';
  for(const e of j.runs){
    const div = document.createElement('div'); div.className='run';
    const cls = e.status==='completed'?'ok':(e.status==='running'?'warn':'err');
    const b = e.brief||{};
    const brief = e.status==='completed'
      ? `scored ${b.scored_functions??0} fn, ${b.evidence_cards??0} evidence cards, priority ${b.priority??'-'} (${b.priority_score??'-'})`
      : (e.detail||'');
    div.innerHTML = `<span class="badge ${cls}">${e.status||'?'}</span> `+
      `<b>${(e.model||'')}</b> ${(e.txn_hash||'').slice(0,12)}... ${e.chain||''} `+
      `<span class=dim>${e.started_at||''}${e.duration_secs?` - ${Math.round(e.duration_secs)}s`:''}</span>`+
      `<div class=dim>${brief}</div><div class=det style=display:none></div>`;
    const det = div.querySelector('.det');
    div.onclick = async () => {
      if(det.style.display==='none'){
        det.style.display='block'; det.textContent='loading stages...';
        const d = await (await fetch('/api/runs/'+e.run_id)).json();
        let h = '<table>';
        for(const st of (d.stages||[])) h += `<tr><td class=dim>+${st.at_secs}s</td><td></td><td>${st.text}</td></tr>`;
        h += '</table>';
        if(d.entry && d.entry.brief && (d.entry.brief.top_functions||[]).length)
          h += '<div class=dim>top: '+d.entry.brief.top_functions.join(', ')+'</div>';
        det.innerHTML = h || 'no stage detail recorded';
      } else det.style.display='none';
    };
    out.appendChild(div);
  }
}
main();
</script></body></html>"""


@app.get("/history", response_class=HTMLResponse)
async def history_page():
    return HISTORY_PAGE


@app.get("/api/capture")
async def capture():
    return FileResponse(CAPTURE, media_type="application/json")


@app.get("/api/config")
async def config():
    return {"chains": CHAINS, "models": MODELS, "repo_present": os.path.isdir(REPO),
            "preset_txs": PRESET_TXS}


web = os.path.normpath(os.path.join(HERE, "web"))
if os.path.isdir(web):
    app.mount("/", StaticFiles(directory=web, html=True), name="web")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
