import os
import json
import time
import re
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
from faultseeker.core.config import FaultSeekerConfig


class FaultSeekerPipeline:

    def __init__(self, config: FaultSeekerConfig):
        """
        Initialize the FaultSeeker pipeline.

        Args:
            config: FaultSeeker configuration object
        """
        self.config = config
        self.forensics_orchestrator = None
        self.function_analyzer = None
        self._agents_initialized = False

    @staticmethod
    def _parse_txn_link(txn_link: str) -> Tuple[str, str]:
        # Extract transaction hash (0x followed by 64 hex characters)
        pattern = r'(0x[0-9a-fA-F]{64})'
        matches = re.findall(pattern, txn_link)
        if not matches:
            raise ValueError(f"Could not extract transaction hash from link: {txn_link}")
        txn_hash = matches[0]

        # Determine chain from URL
        txn_link_lower = txn_link.lower()
        if 'bsc' in txn_link_lower:
            chain = 'bsc'
        elif 'eth' in txn_link_lower:
            chain = 'eth'
        else:
            raise ValueError(f"The blockchain network is not supported or cannot be determined from the link: {txn_link}")

        return txn_hash, chain

    def _initialize_agents(self):
        if self._agents_initialized:
            return

        print("   → Initializing forensics orchestrator...")
        # Import here to avoid circular dependencies and missing dependencies at import time
        from faultseeker.forensics.orchestrator import ForensicsOrchestrator
        from faultseeker.function_analysis.function_ranker import FunctionRanker
        from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer

        # Initialize Stage 1: Forensics
        self.forensics_orchestrator = ForensicsOrchestrator(
            model=self.config.forensics_model,
            cache_dir=self.config.get_forensics_cache_dir()
        )

        print("   → Initializing function ranker...")
        # Initialize Stage 2a: Function Ranking
        self.function_ranker = FunctionRanker()

        print("   → Initializing function analyzer...")
        # Initialize Stage 2b: Function Analysis
        self.function_analyzer = FunctionAnalyzer(
            model=self.config.function_analysis_model
        )

        self._agents_initialized = True

    def analyze_transaction(self,
                          txn_link: Optional[str] = None,
                          txn_hash: Optional[str] = None,
                          chain: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a transaction and identify vulnerabilities.

        Args:
            txn_link: Transaction link (e.g., https://etherscan.io/tx/0x...)
            txn_hash: Transaction hash (alternative to txn_link)
            chain: Blockchain identifier (required if txn_hash is provided)

        Returns:
            Dictionary containing forensics and function analysis results

        Raises:
            ValueError: If input parameters are invalid
            RuntimeError: If analysis stages fail
        """
        start_time = time.time()

        # Validate and parse input
        if not txn_link and not (txn_hash and chain):
            raise ValueError("Either txn_link or (txn_hash and chain) must be provided")

        # Parse txn_link if provided
        if txn_link:
            txn_hash, chain = self._parse_txn_link(txn_link)

        # Ensure agents are initialized
        self._initialize_agents()

        print(f"\n🔬 [Stage 1] Transaction-Level Forensics")
        print(f"   → Fetching transaction data from blockchain...")

        # Stage 1: Transaction-Level Forensics
        stage1 = self.forensics_orchestrator.run(txn_hash, chain)
        forensics_result, txn_seq, txn_info = stage1 if stage1 else (None, None, None)

        if not forensics_result:
            raise RuntimeError("Stage 1 (Forensics) failed to produce results")

        print(f"   ✓ Forensics analysis completed")

        print(f"\n🧩 [Stage 2] Task-Driven Function Analysis")
        print(f"   → Ranking suspicious functions...")

        # Stage 2a: Function Ranking (fast, deterministic)
        tx_analysis = {
            'transaction_hash': forensics_result.transaction_hash,
            'chain': forensics_result.chain,
            'trace': forensics_result.trace,
            'repeated_patterns': forensics_result.repeated_patterns,
            'function_call_loc_memo': forensics_result.function_call_loc_memo
        }
        ranking_result = self.function_ranker.rank(forensics_result, tx_analysis)

        print(f"   ✓ Ranking completed - {len(ranking_result.address_list)} addresses to analyze")
        print(f"   → Analyzing vulnerable functions...")

        # Stage 2b: In-Depth Function Analysis (LLM-driven, uses ranking output)
        analysis_result = self.function_analyzer.run(forensics_result, txn_seq, txn_info, ranking_result)

        if not analysis_result:
            raise RuntimeError("Stage 2 (Function Analysis) failed to produce results")

        print(f"   ✓ Function analysis completed")

        # Build clean final output with only essential results
        result = {
            'transaction_hash': forensics_result.transaction_hash,
            'chain': forensics_result.chain,

            # Main analysis results
            'ranked_suspicious_functions': analysis_result.get('ranked_result', []),
            'potentially_vulnerable_functions': analysis_result.get('potentially_vulnerable_functions', []),
            'transaction_understanding': analysis_result.get('transaction_understanding', ''),

            # Metadata
            'duration': time.time() - start_time,
            'timestamp': datetime.now().isoformat(),

            # Optional: Store full results for debugging (can be removed in production)
            '_debug': {
                'forensics_duration': forensics_result.duration,
                'analysis_duration': analysis_result.get('duration'),
                'functions_to_inspect_count': forensics_result.get_function_count()
            }
        }

        return result

    def save_results(self, result: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """
        Save analysis results to file.

        Args:
            result: Analysis results to save
            output_path: Optional custom output path. If None, generates timestamped path.

        Returns:
            Path where results were saved
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.config.output_dir, f"analysis_{timestamp}.json")

        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Save results
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2)

        return output_path

    def analyze_and_save(self,
                        txn_link: Optional[str] = None,
                        txn_hash: Optional[str] = None,
                        chain: Optional[str] = None,
                        output_path: Optional[str] = None) -> str:
        """
        Convenience method to run analysis and save results in one call.

        Args:
            txn_link: Transaction link
            txn_hash: Transaction hash
            chain: Blockchain identifier
            output_path: Optional output file path

        Returns:
            Path where results were saved
        """
        result = self.analyze_transaction(txn_link, txn_hash, chain)
        saved_path = self.save_results(result, output_path)
        return saved_path
