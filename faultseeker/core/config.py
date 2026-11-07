import os
from dataclasses import dataclass


@dataclass
class FaultSeekerConfig:

    # Model configurations
    forensics_model: str = 'gpt-4o-mini'
    function_analysis_model: str = 'gpt-4o-mini'

    # Directory configurations
    cache_dir: str = './data/cache'
    output_dir: str = './data/output'
    exploit_dir: str = './data/exploit'

    # Analysis parameters
    max_functions_to_analyze: int = 10
    task_tree_max_depth: int = 30

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


    def __post_init__(self):
        """Ensure all directories exist after initialization."""
        import os
        os.makedirs(self.cache_dir, exist_ok=True)
