import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Maps model prefix → required env var name
_MODEL_KEY_MAP = {
    'gpt-':     'OPENAI_API_KEY',
    'o1-':      'OPENAI_API_KEY',
    'o3-':      'OPENAI_API_KEY',
    'o4-':      'OPENAI_API_KEY',
    'grok-':    'XAI_API_KEY',
    'qwen-':    'DASHSCOPE_API_KEY',
    'gemini-':  'GOOGLE_API_KEY',
    'claude-':  'ANTHROPIC_API_KEY',
}


@dataclass
class FaultSeekerConfig:

    # Model configurations
    forensics_model: str = 'gpt-4o-mini'
    function_analysis_model: str = 'gpt-4o-mini'
    # The actual cloud API model for the router's Tier 3 tasks (may differ from function_analysis_model)
    cloud_model: str = ''

    # Directory configurations
    cache_dir: str = './data/cache'
    output_dir: str = './data/output'
    exploit_dir: str = './data/exploit'

    # Analysis parameters
    max_functions_to_analyze: int = 10
    task_tree_max_depth: int = 30

    # Gap 1+6: Hybrid LLM routing and cost tracking
    auto_route: bool = False                    # Enable hybrid routing
    routing_strategy: str = 'hybrid'            # 'local-first', 'cloud-first', 'hybrid', 'cloud-only'
    local_model: str = 'llama3:8b'              # Local model for Ollama
    confidence_gate: float = 0.6                # Min confidence for local model
    track_cost: bool = False                    # Enable cost tracking

    # Gap 2: Human-in-the-Loop
    human_in_loop: bool = False                 # Enable HITL checkpoints

    # Logistic calibration model (paper §5.3) — path to pre-trained calibrator JSON.
    # When set, Stage 3 replaces the heuristic 4-factor scorer with the logistic
    # calibrator, matching the paper's final reported confidence scores.
    calibration_model_path: str = ''            # e.g. './data/models/calibrator.json'

    # ===== Cache Directories (Minimized - Only Heavy Operations) =====
    # Only caching: replay (expensive blockchain replay) and contracts (reusable, rate-limited)

    def get_forensics_cache_dir(self) -> str:
        """Stage 1: Main forensics results cache (kept for AddressClassifier)"""
        path = os.path.join(self.cache_dir, 'forensics')
        os.makedirs(path, exist_ok=True)
        return path

    def get_contract_cache_dir(self) -> str:
        """✅ ESSENTIAL: Contract source code cache (reusable, rate-limited)"""
        path = os.path.join(self.cache_dir, 'contracts')
        os.makedirs(path, exist_ok=True)
        return path

    def get_replay_cache_dir(self) -> str:
        """✅ ESSENTIAL: Transaction replay cache (expensive, 2hr timeout)"""
        path = os.path.join(self.cache_dir, 'replay')
        os.makedirs(path, exist_ok=True)
        return path


    def validate_api_keys(self):
        """Raise RuntimeError early if a required API key is missing."""
        from dotenv import load_dotenv
        load_dotenv()

        models_to_check = [self.forensics_model, self.function_analysis_model]
        if self.cloud_model:
            models_to_check.append(self.cloud_model)
        if self.auto_route and self.local_model:
            # local_model is Ollama — no API key needed
            pass

        for model in models_to_check:
            for prefix, env_var in _MODEL_KEY_MAP.items():
                if model.startswith(prefix):
                    if not os.getenv(env_var):
                        raise RuntimeError(
                            f"Missing API key for model '{model}': "
                            f"set the '{env_var}' environment variable in your .env file."
                        )
                    break  # matched prefix, no need to check others

    def __post_init__(self):
        """Ensure all directories exist and API keys are valid after initialization."""
        os.makedirs(self.cache_dir, exist_ok=True)
        self.validate_api_keys()
