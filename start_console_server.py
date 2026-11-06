"""Launcher for FaultSeeker Console server with secure DPAPI credential loading."""
import os
import sys
from pathlib import Path

# Set up paths
REPO_ROOT = Path(__file__).resolve().parent
CONSOLE_DIR = REPO_ROOT / "console"

os.chdir(str(REPO_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(CONSOLE_DIR) not in sys.path:
    sys.path.insert(0, str(CONSOLE_DIR))

# Ensure child processes inherit these paths
os.environ["FAULTSEEKER_REPO"] = str(REPO_ROOT)
os.environ["PYTHONPATH"] = os.pathsep.join([str(REPO_ROOT), str(CONSOLE_DIR)])

# Securely load DPAPI key without logging or plaintext exposure
dpapi_path = Path(r"C:\Users\91701\AppData\Local\FaultSeeker\inception-key.dpapi")
if dpapi_path.exists():
    sys.path.insert(0, r"C:\Users\91701\AppData\Local\FaultSeeker")
    try:
        import faultseeker_local
        key = faultseeker_local.load_key(dpapi_path)
        if key:
            os.environ["INCEPTION_API_KEY"] = key
            print("Loaded DPAPI key for Inception Mercury-3.")
    except Exception as exc:
        print(f"Warning: Could not load DPAPI key: {exc}")

# Configure server settings
os.environ.setdefault("DEMO_GATE_PASSWORD", "demo-mercury")
os.environ.setdefault("INCEPTION_REASONING_EFFORT", "instant")
os.environ.setdefault("FAULTSEEKER_STAGE2_WORKERS", "1")
os.environ.setdefault("FAULTSEEKER_MODEL_TIME_BUDGET_SECS", "7200")
os.environ.setdefault("DEMO_REPLAY_SPEED", "0.02")   # 2% of real-time → ~2min replay
os.environ.setdefault("DEMO_REPLAY_MAX_GAP", "0.3")  # cap gaps at 0.3s for fast replay
os.environ["PYTHONUNBUFFERED"] = "1"

import uvicorn
from app.server import app
from app import server as _srv

# Inject Zunami Protocol golden run as a saved replay (no RPC, no LLM needed)
_LIVE_RUNS = r"C:\Users\91701\Downloads\faultseeker-demo-console-main\FaultSeeker_Live\app\runs"
_ZUNAMI_RESULT = str(CONSOLE_DIR / "app" / "samples" / "zunami_abee00d2aea0.result.json")
_srv.DEMO_REPLAYS["demo:zunami"] = {
    "label": "SAVED REPLAY - Zunami Protocol $2.1M (real run abee00d2aea0)",
    "events": os.path.join(_LIVE_RUNS, "abee00d2aea0.events.jsonl"),
    "result": _ZUNAMI_RESULT if os.path.exists(_ZUNAMI_RESULT) else os.path.join(_LIVE_RUNS, "abee00d2aea0.json"),
    "txn_hash": "0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb",
    "chain": "eth",
}
print(f"Injected Zunami replay: demo:zunami -> abee00d2aea0 ({len(_srv.DEMO_REPLAYS)} total replays)")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8420"))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"Starting FaultSeeker Console on http://{host}:{port}")
    print(f"Gate Password: {os.environ.get('DEMO_GATE_PASSWORD')}")
    uvicorn.run(app, host=host, port=port, log_level="info")
