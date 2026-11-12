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

MAX_CONCURRENT_RUNS = 1   # fixed: the pipeline writes to shared relative folders (temp2/, Implementation/)
RUN_TIMEOUT_SECONDS = int(os.environ.get("FAULTSEEKER_RUN_TIMEOUT", "3600"))
MAX_STORED_RUNS = int(os.environ.get("FAULTSEEKER_MAX_STORED_RUNS", "100"))
MAX_LINE_BYTES = int(os.environ.get("FAULTSEEKER_MAX_LINE_BYTES", str(32 * 1024 * 1024)))
MAX_LOG_LINES_MEMORY = 4000
MAX_LOG_LINE_CHARS = 4000
MAX_LOG_FILE_BYTES = 5 * 1024 * 1024
ALLOW_PRIVATE_RPC = os.environ.get("FAULTSEEKER_ALLOW_PRIVATE_RPC", "") == "1"
MAX_BODY_BYTES = 16 * 1024

ON_RENDER = bool(os.environ.get("RENDER"))
# "Public" means reachable by people other than the operator. Render and the Docker image set it automatically.
PUBLIC_MODE = ON_RENDER or os.environ.get("FAULTSEEKER_PUBLIC", "") == "1"
ALLOW_UNSAFE_PUBLIC = os.environ.get("FAULTSEEKER_ALLOW_UNSAFE_PUBLIC", "") == "1"
ACCESS_CODE = os.environ.get("FAULTSEEKER_ACCESS_CODE", "")
ACCESS_CODE_MIN_LENGTH = 12
SESSION_HOURS = float(os.environ.get("FAULTSEEKER_SESSION_HOURS", "12"))
LOGIN_MAX_FAILURES_PER_IP = int(os.environ.get("FAULTSEEKER_LOGIN_MAX_FAILURES", "5"))
LOGIN_WINDOW_SECONDS = int(os.environ.get("FAULTSEEKER_LOGIN_WINDOW_SECONDS", "900"))
LOGIN_MAX_FAILURES_GLOBAL = int(os.environ.get("FAULTSEEKER_LOGIN_MAX_FAILURES_GLOBAL", "50"))

# Foundry: the version the Docker image installs and the versions the test-suite has been run against.
PINNED_FOUNDRY_VERSION = "1.9.0"
TESTED_FOUNDRY_VERSIONS = ("1.4.4", "1.5.1", "1.9.0")

from faultseeker import chains as _chains  # noqa: E402

CHAINS = [dict(c) for c in _chains.CHAINS.values()]
CHAIN_IDS = {c["id"] for c in CHAINS if c["support"] != "unsupported"}
# Platform names used by the benchmark ground-truth files.
PLATFORM_TO_CHAIN = {"Ethereum": "eth", "BNBChain": "bsc"}



from faultseeker import providers as _providers  # noqa: E402


def registry() -> "_providers.Registry":
    return _providers.load_registry()


def server_held_key_envs():
    """Names of provider key variables that hold a value in the server's own environment."""
    return [name for name in registry().all_key_envs() if os.environ.get(name, "").strip()]


def server_has_key(provider) -> bool:
    return bool(provider.api_key_env and os.environ.get(provider.api_key_env, "").strip())


def models():
    """Models offered to users, from the single registry (config/models.json) filtered by FAULTSEEKER_ENABLED_MODELS."""
    reg = registry()
    default = os.environ.get("FAULTSEEKER_DEFAULT_MODEL", "").strip().lower()
    out = []
    for spec in reg.enabled():
        provider = reg.providers[spec.provider_id]
        out.append({"id": spec.id, "label": spec.label, "provider": provider.id, "provider_label": provider.label,
                    "key_required": bool(provider.api_key_env) and not server_has_key(provider),
                    "key_optional": bool(provider.api_key_env) and server_has_key(provider)})
    ids = [m["id"] for m in out]
    chosen = default if default in ids else (ids[0] if ids else "")
    for m in out:
        m["default"] = m["id"] == chosen
    return out


def unavailable_models():
    """Registry models that cannot be offered, with the reason (names environment variables, never values)."""
    enabled = {m["id"] for m in models()}
    return [{"id": s.id, "reason": r} for s, r in registry().availability() if r and s.id not in enabled]


def startup_problems():
    """Fatal configuration problems. The server refuses to start while any exist."""
    problems = []
    try:
        reg = registry()
        reg.enabled()
        held = [n for n in reg.all_key_envs() if os.environ.get(n, "").strip()]
    except _providers.ProviderConfigError as exc:
        return [f"Model registry: {exc}"]
    if ACCESS_CODE and len(ACCESS_CODE) < ACCESS_CODE_MIN_LENGTH:
        problems.append(f"FAULTSEEKER_ACCESS_CODE must be at least {ACCESS_CODE_MIN_LENGTH} characters.")
    if held and not ACCESS_CODE and PUBLIC_MODE and not ALLOW_UNSAFE_PUBLIC:
        problems.append(
            "A server-held model API key is set (" + ", ".join(held) + ") but access protection is not. Anyone who finds the "
            "URL could spend that key. Set FAULTSEEKER_ACCESS_CODE (12+ characters), or remove the server key so users bring "
            "their own, or set FAULTSEEKER_ALLOW_UNSAFE_PUBLIC=1 to accept the risk explicitly.")
    return problems


_cast_version = None


def cast_version() -> str:
    """`cast --version` once, in a clean environment (cached). '' when cast is unavailable."""
    global _cast_version
    if _cast_version is None:
        import re
        import subprocess
        try:
            env = {k: v for k, v in os.environ.items() if k == "PATH"}
            out = subprocess.run(["cast", "--version"], capture_output=True, text=True, timeout=15, env=env).stdout
            m = re.search(r"(\d+\.\d+\.\d+)", out)
            _cast_version = m.group(1) if m else ""
        except (OSError, subprocess.SubprocessError):
            _cast_version = ""
    return _cast_version


def environment_report():
    """What the deployed container can actually do. Cheap, no network."""
    issues, notes = [], []
    if not shutil.which("cast"):
        issues.append("Foundry 'cast' is missing, so transactions cannot be replayed.")
    if not shutil.which("getCode"):
        issues.append("'getCode' is missing, so contract source cannot be downloaded.")
    if not shutil.which("curl"):
        issues.append("'curl' is missing, so explorer pages cannot be fetched.")
    if not (ROOT / "foundry.toml").exists():
        issues.append("foundry.toml is missing, so server RPC aliases are unavailable.")
    try:
        if not models():
            issues.append("No analysis models are available. See the model registry and its environment variables.")
    except _providers.ProviderConfigError as exc:
        issues.append(f"Model registry: {exc}")
    version = cast_version() if shutil.which("cast") else ""
    if version and version not in TESTED_FOUNDRY_VERSIONS:
        notes.append(f"cast {version} has not been tested with this release (tested: {', '.join(TESTED_FOUNDRY_VERSIONS)}).")
    return {
        "host": "render" if ON_RENDER else "local",
        "ready": not issues,
        "issues": issues,
        "notes": notes,
        "cast_version": version,
        "server_model_keys": sorted(p.id for p in registry().providers.values() if server_has_key(p)),
        "explorer_key": bool(os.environ.get("ETHERSCAN_API_KEY", "").strip()),
    }
