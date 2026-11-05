"""
Auto Model Selector — FaultSeeker++
=====================================
Detects which API keys / local models are available and lets the
user interactively choose which to use before the pipeline starts.
"""

import os
import subprocess
import logging
from dotenv import load_dotenv

load_dotenv(override=True)   # .env always wins over system env vars
logger = logging.getLogger(__name__)

# ── Cloud provider preference list ─────────────────────────────────────
# Format: (env_var, model_name, label)
CLOUD_PREFERENCE = [
    ('GOOGLE_API_KEY',    'gemini-2.0-flash',          'Gemini 2.0 Flash  (Google — free tier)'),
    ('DASHSCOPE_API_KEY', 'qwen-turbo',                 'Qwen Turbo        (Alibaba DashScope)'),
    ('XAI_API_KEY',       'grok-3-mini',                'Grok 3 Mini       (xAI)'),
    ('OPENAI_API_KEY',    'gpt-4o-mini',                'GPT-4o Mini       (OpenAI)'),
    ('ANTHROPIC_API_KEY', 'claude-3-haiku-20240307',    'Claude 3 Haiku    (Anthropic)'),
]

# ── Local Ollama model preference order (used for non-interactive auto-detect) ─
LOCAL_PREFERENCE = [
    'llama3:8b',
    'deepseek-r1:14b',
    'mistral',
    'qwen2:7b',
    'phi3:mini',
    'qwen2:0.5b',
    'tinyllama',
]


# ───────────────────────────────────────────────────────────────────────
# Detection helpers
# ───────────────────────────────────────────────────────────────────────

def _get_ollama_models() -> list:
    """Return list of locally installed Ollama model names."""
    try:
        result = subprocess.run(
            ['ollama', 'list'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return []
        lines = result.stdout.strip().splitlines()
        models = []
        for line in lines[1:]:   # skip header
            parts = line.split()
            if parts:
                models.append(parts[0])   # keep original case + tag
        return models
    except Exception:
        return []


def _has_cloud_key(env_var: str) -> bool:
    """Return True if the env var is set and non-empty placeholder."""
    val = os.getenv(env_var, '').strip()
    return bool(val) and val not in ('sk-...', 'xai-...', 'AIza...', 'sk-ant-...')


def detect_best_local_model() -> str | None:
    """Return the best available local Ollama model, or None."""
    installed = _get_ollama_models()
    if not installed:
        return None
    for preferred in LOCAL_PREFERENCE:
        for m in installed:
            if preferred.lower() in m.lower():
                return m   # return exact installed tag
    return installed[0] if installed else None


def detect_best_cloud_model() -> tuple[str, str] | tuple[None, None]:
    """Return (model_name, label) for the first configured cloud provider."""
    for env_var, model, label in CLOUD_PREFERENCE:
        if _has_cloud_key(env_var):
            return model, label
    return None, None


# ───────────────────────────────────────────────────────────────────────
# Interactive selector
# ───────────────────────────────────────────────────────────────────────

def interactive_model_selection() -> dict:
    """
    Detect installed local models + available cloud keys, display a
    numbered menu, and ask the user which mode to run in.

    Returns the same dict shape as auto_select_models():
      {
        'cloud_model'       : str   — model for Stage 1 (or primary single model)
        'actual_cloud_model': str | None — real cloud API model
        'local_model'       : str | None
        'use_hybrid'        : bool
        'cloud_label'       : str
      }
    """
    local_models  = _get_ollama_models()
    cloud_options = [(env, mdl, lbl)
                     for env, mdl, lbl in CLOUD_PREFERENCE
                     if _has_cloud_key(env)]

    print("\n" + "-" * 56)
    print("  FaultSeeker++ - Model Selection")
    print("-" * 56)

    # -- Show local models ------------------------------------------
    if local_models:
        print("\n  [Local] Local Ollama models installed:")
        for i, m in enumerate(local_models, 1):
            print(f"     [{i}] {m}")
    else:
        print("\n  [Warning] No local Ollama models found.")
        print("      Run:  ollama pull phi3:mini")

    # -- Show cloud models ------------------------------------------
    if cloud_options:
        print("\n  [Cloud] Cloud APIs available:")
        for env, mdl, lbl in cloud_options:
            print(f"     - {lbl}")
    else:
        print("\n  [Warning] No cloud API keys found in .env")
        print("      Add GOOGLE_API_KEY=<key> to .env for free cloud access.")

    # ── Build menu ─────────────────────────────────────────────────
    print("\n  -----------------------------------------------------")
    options = []   # list of (display_label, result_dict)

    # Option: local-only (one entry per installed model)
    for m in local_models:
        options.append((
            f"Local only  ->  {m}",
            {
                'cloud_model':        m,
                'actual_cloud_model': None,
                'local_model':        m,
                'use_hybrid':         False,
                'cloud_label':        'Local (Ollama)',
            }
        ))

    # Option: cloud-only (one entry per available cloud)
    for env, mdl, lbl in cloud_options:
        options.append((
            f"Cloud only  ->  {lbl}",
            {
                'cloud_model':        mdl,
                'actual_cloud_model': mdl,
                'local_model':        None,
                'use_hybrid':         False,
                'cloud_label':        lbl,
            }
        ))

    # Option: hybrid (each local x each cloud)
    for m in local_models:
        for env, mdl, lbl in cloud_options:
            options.append((
                f"Hybrid      ->  {m}  +  {lbl}",
                {
                    'cloud_model':        m,       # Stage 1 (simple) -> local
                    'actual_cloud_model': mdl,     # Stage 2 Tier 3   -> cloud
                    'local_model':        m,
                    'use_hybrid':         True,
                    'cloud_label':        lbl,
                }
            ))

    if not options:
        raise RuntimeError(
            "\n❌ No LLM available!\n"
            "   • Start Ollama and pull a model:  ollama pull phi3:mini\n"
            "   • Or add a cloud API key to .env (see .env.example)"
        )

    print("  Select mode:")
    for i, (label, _) in enumerate(options, 1):
        print(f"     [{i}] {label}")
    print("-" * 56)

    # ── Read choice ────────────────────────────────────────────────
    while True:
        try:
            raw = input(f"  Enter choice [1-{len(options)}]: ").strip()
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                label, cfg = options[idx]
                print(f"\n  [OK] Selected: {label}\n")
                logger.info(f"User selected: {label} -> {cfg}")
                return cfg
            else:
                print(f"  [!] Please enter a number between 1 and {len(options)}.")
        except (ValueError, EOFError):
            # Non-interactive environment (CI/pipe) → auto-pick best option
            best = options[0][1]
            print(f"\n  [Info] Non-interactive mode -- auto-selecting: {options[0][0]}\n")
            return best


# ───────────────────────────────────────────────────────────────────────
# Non-interactive auto-selector (used when -forensics_model is explicit)
# ───────────────────────────────────────────────────────────────────────

def auto_select_models(prefer_local: bool = True) -> dict:
    """
    Non-interactive version: silently picks the best available model.
    Called only when both -forensics_model and -function_analysis_model
    are explicitly set via CLI flags.
    """
    local_model  = detect_best_local_model()
    cloud_model, cloud_label = detect_best_cloud_model()

    if cloud_model is None and local_model is None:
        raise RuntimeError(
            "\n❌ No LLM available!\n"
            "   Either:\n"
            "   • Start Ollama and pull a model: ollama pull phi3:mini\n"
            "   • Or set an API key in .env (see .env.example)"
        )

    use_hybrid    = (local_model is not None) and (cloud_model is not None)
    primary_model = local_model or cloud_model

    return {
        'cloud_model':        primary_model,
        'actual_cloud_model': cloud_model,
        'local_model':        local_model,
        'use_hybrid':         use_hybrid,
        'cloud_label':        cloud_label or 'Local (Ollama)',
    }


def print_model_selection(config: dict):
    """Print a user-friendly summary of the selected models."""
    print("[Model Configuration]:")
    if config['use_hybrid']:
        print(f"   Stage 1  -> {config['local_model']} (local Ollama)")
        print(f"   Stage 2  -> {config['actual_cloud_model']} ({config['cloud_label']})")
        print("   Mode     : Hybrid")
    else:
        print(f"   Model    : {config['cloud_model']} ({config['cloud_label']})")
        print("   Mode     : Single")
    print()
