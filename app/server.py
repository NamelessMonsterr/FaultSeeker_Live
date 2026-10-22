"""FaultSeeker demo server: serves the built UI and runs the real pipeline
(main-1) with per-stage SSE progress. Keys arrive per-request in the POST
body, are set into os.environ only for the duration of that run, and are
removed afterwards. They are never logged or written to disk."""
import io
import json
import os
import queue
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


def sse(ev, data):
    return f"event: {ev}\ndata: {json.dumps(data)}\n\n"


def worker(run_id, req):
    q = runs[run_id]["q"]
    env_set = []

    class Tap(io.TextIOBase):
        def write(self, s):
            if s and s.strip():
                line = s.strip()
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
            if "drpc" in rpc_url.lower():
                os.environ["DRPC_RPC_URL"] = rpc_url
                env_set.append("DRPC_RPC_URL")
                if rpc_key:
                    os.environ["DRPC_API_KEY"] = rpc_key
                    env_set.append("DRPC_API_KEY")
            else:
                var = f"{req['chain'].upper()}_RPC_URL"
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
            if not model_key:
                raise ValueError(f"model {mode} requires an API key in Settings")
            os.environ[entry["keyEnv"]] = model_key
            env_set.append(entry["keyEnv"])
            q.put(("log", f"mode: full pipeline Stage 1-3 with {mode} (cost tracking on)"))
            result = fs_main(txn_hash=req["txn_hash"], chain=req["chain"],
                             forensics_model=mode, function_analysis_model=mode,
                             track_cost=True, output_path=out_path)
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
            os.environ.pop(k, None)
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
    uvicorn.run(app, host="127.0.0.1", port=8420, log_level="warning")
