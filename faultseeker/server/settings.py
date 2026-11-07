"""Runtime configuration for the web service, read once from the environment."""
import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The pipeline's agents read a .env file; load it here too so the server and its workers agree on which keys exist.
try:
    from dotenv import load_dotenv
    load_dotenv(os.environ.get("FAULTSEEKER_ENV_FILE", ROOT / ".env"))   # never overrides real environment variables
except ImportError:  # python-dotenv is part of requirements.txt; tolerate its absence in minimal test setups
    pass
WEB_DIR = ROOT / "web"
DATA_DIR = Path(os.environ.get("FAULTSEEKER_DATA_DIR", ROOT / "data"))
RUNS_DIR = DATA_DIR / "runs"
BENCHMARK_DIR = ROOT / "benchmark" / "ground_truth"
CAPTURE_FILE = ROOT / "captures" / "capture.json"
DEFAULT_CAPTURE_TX = os.environ.get(
    "FAULTSEEKER_CAPTURE_TX",
    "0x9f4ef3cc55b016ea6b867807a09f80d1b2e36f6cd6fccfaf0182f46060332c57",
)

# Test seam: module executed in the worker subprocess.
WORKER_MODULE = os.environ.get("FAULTSEEKER_WORKER_MODULE", "faultseeker.server.worker")

MAX_CONCURRENT_RUNS = max(1, int(os.environ.get("FAULTSEEKER_MAX_CONCURRENT", "1")))
RUN_TIMEOUT_SECONDS = int(os.environ.get("FAULTSEEKER_RUN_TIMEOUT", "3600"))
MAX_STORED_RUNS = int(os.environ.get("FAULTSEEKER_MAX_STORED_RUNS", "100"))
MAX_LINE_BYTES = int(os.environ.get("FAULTSEEKER_MAX_LINE_BYTES", str(32 * 1024 * 1024)))
MAX_LOG_LINES_MEMORY = 4000
MAX_LOG_LINE_CHARS = 4000
MAX_LOG_FILE_BYTES = 5 * 1024 * 1024
ALLOW_PRIVATE_RPC = os.environ.get("FAULTSEEKER_ALLOW_PRIVATE_RPC", "") == "1"
MAX_BODY_BYTES = 16 * 1024

ON_RENDER = bool(os.environ.get("RENDER"))

from faultseeker import chains as _chains  # noqa: E402

CHAINS = [dict(c) for c in _chains.CHAINS.values()]
CHAIN_IDS = {c["id"] for c in CHAINS if c["support"] != "unsupported"}
# Platform names used by the benchmark ground-truth files.
PLATFORM_TO_CHAIN = {"Ethereum": "eth", "BNBChain": "bsc"}

_MODEL_LABELS = {
    "gpt-4o-mini": "GPT-4o mini",
    "gpt-4o": "GPT-4o",
    "gpt-4.1-mini": "GPT-4.1 mini",
    "gpt-4.1": "GPT-4.1",
}


def _csv(name: str, default: str):
    return [m.strip() for m in os.environ.get(name, default).split(",") if m.strip()]


def server_has_openai_key() -> bool:
    return bool(os.environ.get("OPENAI_API_KEY", "").strip())


def models():
    """Selectable analysis models. Names starting with 'gpt' use OpenAI, anything else uses Ollama
    (this mirrors faultseeker.utils.utils.build_agent)."""
    default = os.environ.get("FAULTSEEKER_DEFAULT_MODEL", "gpt-4o-mini").strip().lower()
    out = []
    for m in _csv("FAULTSEEKER_OPENAI_MODELS", "gpt-4o-mini,gpt-4o,gpt-4.1-mini,gpt-4.1"):
        m = m.lower()
        out.append({"id": m, "label": _MODEL_LABELS.get(m, m), "provider": "openai",
                    "key_required": not server_has_openai_key()})
    for m in _csv("FAULTSEEKER_OLLAMA_MODELS", ""):
        out.append({"id": m.lower(), "label": f"{m} (Ollama)", "provider": "ollama", "key_required": False})
    for item in out:
        item["default"] = item["id"] == default
    if out and not any(i["default"] for i in out):
        out[0]["default"] = True
    return out


def environment_report():
    """What the deployed container can actually do. Cheap, no network."""
    issues = []
    if not shutil.which("cast"):
        issues.append("Foundry 'cast' is missing, so transactions cannot be replayed.")
    if not shutil.which("getCode"):
        issues.append("'getCode' is missing, so contract source cannot be downloaded.")
    if not shutil.which("curl"):
        issues.append("'curl' is missing, so explorer pages cannot be fetched.")
    if not (ROOT / "foundry.toml").exists():
        issues.append("foundry.toml is missing, so server RPC aliases are unavailable.")
    if not models():
        issues.append("No analysis models are configured.")
    return {
        "host": "render" if ON_RENDER else "local",
        "ready": not issues,
        "issues": issues,
        "server_model_key": server_has_openai_key(),
        "explorer_key": bool(os.environ.get("ETHERSCAN_API_KEY", "").strip()),
    }
