from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import os


class BaseAgent(ABC):

    def __init__(self, model: str = 'gpt-4o-mini', cache_dir: Optional[str] = None):
        """
        Initialize the base agent.

        Args:
            model: LLM model identifier (default: 'gpt-4o-mini')
            cache_dir: Optional cache directory path
        """
        self.model = model
        self.cache_dir = cache_dir

        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)

    @abstractmethod
    def run(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the agent's main logic.

        This method must be implemented by all subclasses.

        Args:
            **kwargs: Agent-specific arguments

        Returns:
            Dict containing the agent's analysis results

        Raises:
            NotImplementedError: If not implemented by subclass
        """
        pass

    def check_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Check if cached results exist for the given key.

        Args:
            cache_key: Unique identifier for the cached result

        Returns:
            Cached result dict if found, None otherwise
        """
        if not self.cache_dir:
            return None

        import json
        cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")

        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return None

        return None

    def save_cache(self, cache_key: str, data: Dict[str, Any]) -> None:
        """
        Save results to cache.

        Args:
            cache_key: Unique identifier for the cached result
            data: Data to cache
        """
        if not self.cache_dir:
            return

        import json
        cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")

        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save cache: {e}")
