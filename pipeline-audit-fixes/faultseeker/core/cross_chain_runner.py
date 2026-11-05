"""
Cross-Chain Analysis Runner — FaultSeeker++ Gap 6
==================================================
Runs FaultSeeker++ analysis across multiple EVM chains and generates
a comparative report showing:
  - Per-chain vulnerability distribution
  - Confidence score distribution by chain
  - Cross-chain attack pattern comparison
  - Cost / routing summary per chain

Usage:
    python -m faultseeker.core.cross_chain_runner --txns benchmark/benchmark_classification_fixed.csv --chains eth bsc arbitrum base
    python -m faultseeker.core.cross_chain_runner --txns benchmark/benchmark_classification_fixed.csv --limit 5 --chains polygon avalanche
"""

import csv
import json
import os
import logging
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Chain-specific RPC endpoints (archive-capable) ────────────────────
CHAIN_RPC_MAP: Dict[str, str] = {
    "eth": os.getenv("ETH_RPC_URL", "https://rpc.ankr.com/eth"),
    "bsc": os.getenv("BSC_RPC_URL", "https://rpc.ankr.com/bsc"),
    "arbitrum": os.getenv("ARBITRUM_RPC_URL", "https://rpc.ankr.com/arbitrum"),
    "optimism": os.getenv("OPTIMISM_RPC_URL", "https://rpc.ankr.com/optimism"),
    "base": os.getenv("BASE_RPC_URL", "https://rpc.ankr.com/base"),
    "polygon": os.getenv("POLYGON_RPC_URL", "https://rpc.ankr.com/polygon"),
    "avalanche": os.getenv("AVALANCHE_RPC_URL", "https://rpc.ankr.com/avalanche"),
    "zksync": os.getenv("ZKSYNC_RPC_URL", "https://rpc.ankr.com/zksync_era"),
}

# ── Chain-specific etherscan/explorer API keys ────────────────────────
CHAIN_API_KEY_MAP: Dict[str, str] = {
    "eth": os.getenv("ETHERSCAN_API_KEY", ""),
    "bsc": os.getenv("BSCSCAN_API_KEY", ""),
    "arbitrum": os.getenv("ARBISCAN_API_KEY", ""),
    "optimism": os.getenv("OPTIMISM_API_KEY", ""),
    "base": os.getenv("BASESCAN_API_KEY", ""),
    "polygon": os.getenv("POLYGONSCAN_API_KEY", ""),
    "avalanche": os.getenv("SNOWTRACE_API_KEY", ""),
    "zksync": os.getenv("ZKSYNC_API_KEY", ""),
}

SUPPORTED_CHAINS = list(CHAIN_RPC_MAP.keys())


# ── Data structures ───────────────────────────────────────────────────

class ChainAnalysisResult:
    """Holds aggregated results for a single chain."""

    def __init__(self, chain: str):
        self.chain = chain
        self.total_txns = 0
        self.successful = 0  # completed analyses with scored output
        self.failed = 0
        self.dry_runs = 0    # pipeline unavailable; not a real analysis
        self.partials = 0    # pipeline ran but analysis_status == 'partial'
        # Ground-truth distribution (from benchmark CSV, not pipeline output)
        self.gt_vuln_type_counts: Dict[str, int] = defaultdict(int)
        # Pipeline-detected distribution (only from fully completed runs)
        self.detected_vuln_type_counts: Dict[str, int] = defaultdict(int)
        # Legacy alias kept for downstream compat; maps to gt counts
        self.vuln_type_counts: Dict[str, int] = self.gt_vuln_type_counts
        self.confidence_scores: List[float] = []
        self.complexity_counts: Dict[str, int] = defaultdict(int)
        self.txn_results: List[Dict] = []

    def add_result(self, txn_hash: str, vuln_type: str, complexity: str,
                   confidence: float, success: bool, raw: Optional[Dict] = None):
        """Record one transaction result.

        ``success`` must reflect *completed* analysis only — dry-run and
        partial results must NOT set success=True (see CrossChainAnalyzer).
        Ground-truth vuln_type is always recorded; detected vuln type is
        only recorded for fully completed runs.
        """
        self.total_txns += 1
        raw = raw or {}
        is_dry = raw.get("dry_run", False)
        analysis_status = raw.get("analysis_status", "")
        is_partial = not is_dry and analysis_status == "partial"

        # Always record ground-truth distribution
        self.gt_vuln_type_counts[vuln_type] += 1
        self.complexity_counts[complexity] += 1

        if is_dry:
            self.dry_runs += 1
            self.failed += 1
        elif is_partial:
            self.partials += 1
            self.failed += 1
        elif success:
            self.successful += 1
            self.confidence_scores.append(confidence)
            # Record pipeline-detected types only from real completed runs
            for detected in (raw.get("detected_vulnerability_types") or []):
                self.detected_vuln_type_counts[str(detected)] += 1
        else:
            self.failed += 1

        self.txn_results.append({
            "txn_hash": txn_hash,
            "vuln_type": vuln_type,       # ground-truth label from CSV
            "complexity": complexity,
            "confidence": confidence,
            "success": success,
            "dry_run": is_dry,
            "partial": is_partial,
            "raw": raw,
        })

    def avg_confidence(self) -> float:
        if not self.confidence_scores:
            return 0.0
        return round(sum(self.confidence_scores) / len(self.confidence_scores), 3)

    def to_dict(self) -> Dict:
        return {
            "chain": self.chain,
            "total_txns": self.total_txns,
            "successful": self.successful,       # completed analyses only
            "dry_runs": self.dry_runs,           # pipeline unavailable
            "partials": self.partials,           # partial/inconclusive
            "failed": self.failed,               # dry_runs + partials + errors
            # Completion rate excludes dry-runs and partials from the numerator
            "success_rate": round(self.successful / max(self.total_txns, 1) * 100, 1),
            "avg_confidence": self.avg_confidence(),
            # Ground-truth distribution (from benchmark CSV)
            "gt_vuln_type_distribution": dict(
                sorted(self.gt_vuln_type_counts.items(), key=lambda x: -x[1])[:5]
            ),
            # Pipeline-detected distribution (completed runs only)
            "detected_vuln_types": dict(
                sorted(self.detected_vuln_type_counts.items(), key=lambda x: -x[1])[:5]
            ),
            # Legacy key kept for downstream compat
            "top_vuln_types": dict(
                sorted(self.gt_vuln_type_counts.items(), key=lambda x: -x[1])[:5]
            ),
            "complexity_distribution": dict(self.complexity_counts),
        }


class CrossChainAnalyzer:
    """
    Orchestrates multi-chain analysis using the FaultSeeker++ pipeline.
    """

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        local_model: str = "phi3:mini",
        use_hybrid: bool = True,
        output_dir: str = "reports/cross_chain",
    ):
        self.model = model
        self.local_model = local_model
        self.use_hybrid = use_hybrid
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: Dict[str, ChainAnalysisResult] = {}

    def load_benchmark(self, csv_path: str, chains: Optional[List[str]] = None,
                       limit: Optional[int] = None) -> Dict[str, List[Dict]]:
        """
        Load transactions from the benchmark CSV, grouped by chain.

        Returns:
            Dict mapping chain → list of transaction dicts
        """
        grouped: Dict[str, List[Dict]] = defaultdict(list)

        with open(csv_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                chain = row.get("chain", "").strip().lower()
                txn_hash = row.get("txn_hash", "").strip()
                if not txn_hash or not chain:
                    continue
                if chains and chain not in chains:
                    continue
                grouped[chain].append({
                    "txn_hash": txn_hash,
                    "chain": chain,
                    "vuln_type": row.get("vuln_type", "Unknown"),
                    "complexity": row.get("class", "Unknown"),
                    "loss_usd": row.get("loss_usd", "0"),
                })

        # Apply per-chain limit
        if limit:
            grouped = {chain: txns[:limit] for chain, txns in grouped.items()}

        logger.info(f"Loaded {sum(len(v) for v in grouped.values())} transactions "
                    f"across {len(grouped)} chains")
        return dict(grouped)

    def _run_single_txn(self, txn_hash: str, chain: str) -> Optional[Dict]:
        """
        Run the FaultSeeker++ pipeline on a single transaction.
        Imports lazily to allow the module to be imported without heavy deps.
        """
        try:
            from faultseeker.main import run_analysis

            result = run_analysis(
                txn_hash=txn_hash,
                chain=chain,
                model=self.model,
                local_model=self.local_model if self.use_hybrid else None,
            )
            return result
        except ImportError:
            # Graceful degradation if pipeline not fully available
            logger.warning("run_analysis not available — running in dry-run mode")
            return {"dry_run": True, "txn_hash": txn_hash, "chain": chain}
        except Exception as e:
            logger.error(f"Failed to analyze {txn_hash} on {chain}: {e}")
            return None

    def _extract_confidence(self, result: Optional[Dict]) -> float:
        """Extract a representative confidence score from a pipeline result."""
        if not result:
            return 0.0

        scores = []
        for item in result.get("scored_functions", []) or []:
            if not isinstance(item, dict):
                continue
            confidence = item.get("confidence", {})
            if isinstance(confidence, dict) and confidence.get("overall") is not None:
                scores.append(float(confidence["overall"]))
            elif item.get("confidence_score") is not None:
                scores.append(float(item["confidence_score"]))
        if scores:
            return round(sum(scores) / len(scores), 3)

        pvf = result.get("potentially_vulnerable_functions")
        if pvf is None:
            pvf = result.get("function_analysis", {}).get("potentially_vulnerable_functions", {})
        if not pvf:
            return float(result.get("priority_score", 0.0) or 0.0)

        scores = []
        values = pvf.values() if isinstance(pvf, dict) else pvf
        for v in values:
            if isinstance(v, dict):
                cs = v.get("confidence_score", [])
                if isinstance(cs, list):
                    scores.extend([float(x) for x in cs if x])
                elif cs:
                    scores.append(float(cs))
        return round(sum(scores) / len(scores), 3) if scores else float(result.get("priority_score", 0.0) or 0.0)

    def run(self, csv_path: str, chains: Optional[List[str]] = None,
            limit: Optional[int] = None) -> Dict:
        """
        Run cross-chain analysis on all selected chains and transactions.

        Returns:
            Aggregated report dict
        """
        benchmark = self.load_benchmark(csv_path, chains=chains, limit=limit)

        for chain, txns in benchmark.items():
            logger.info(f"\n{'─'*50}")
            logger.info(f"  Analyzing chain: {chain.upper()} ({len(txns)} transactions)")
            logger.info(f"{'─'*50}")

            chain_result = ChainAnalysisResult(chain)

            for i, txn in enumerate(txns, 1):
                txn_hash = txn["txn_hash"]
                print(f"  [{i}/{len(txns)}] {chain.upper()} | {txn_hash[:20]}...")

                raw = self._run_single_txn(txn_hash, chain)
                # Completed analysis: raw exists, no top-level error key,
                # not a dry-run placeholder, not a partial/inconclusive run.
                success = (
                    raw is not None
                    and not raw.get("dry_run", False)
                    and raw.get("analysis_status", "completed") not in ("partial", "failed")
                    and "error" not in raw
                )
                confidence = self._extract_confidence(raw)

                chain_result.add_result(
                    txn_hash=txn_hash,
                    vuln_type=txn["vuln_type"],
                    complexity=txn["complexity"],
                    confidence=confidence,
                    success=success,
                    raw=raw,
                )

            self.results[chain] = chain_result

        return self._generate_report()

    def _generate_report(self) -> Dict:
        """Build and save the cross-chain report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = {
            "timestamp": timestamp,
            "faultseeker_version": "FaultSeeker++",
            "chains_analyzed": list(self.results.keys()),
            "per_chain": {chain: r.to_dict() for chain, r in self.results.items()},
            "summary": self._build_summary(),
        }

        # Save JSON report
        report_path = self.output_dir / f"cross_chain_report_{timestamp}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        # Save human-readable text report
        txt_path = self.output_dir / f"cross_chain_report_{timestamp}.txt"
        self._write_text_report(report, txt_path)

        print(f"\n✅ Cross-chain report saved to: {report_path}")
        print(f"📄 Text report saved to:        {txt_path}")
        return report

    def _build_summary(self) -> Dict:
        """Build a cross-chain summary."""
        total_txns = sum(r.total_txns for r in self.results.values())
        total_success = sum(r.successful for r in self.results.values())
        all_scores = [s for r in self.results.values() for s in r.confidence_scores]

        # Aggregate vuln types across all chains
        all_vuln_types: Dict[str, int] = defaultdict(int)
        for r in self.results.values():
            for k, v in r.vuln_type_counts.items():
                all_vuln_types[k] += v

        return {
            "total_transactions": total_txns,
            "total_successful": total_success,
            "overall_success_rate": round(total_success / max(total_txns, 1) * 100, 1),
            "overall_avg_confidence": round(
                sum(all_scores) / len(all_scores), 3) if all_scores else 0.0,
            "top_vuln_types_across_chains": dict(
                sorted(all_vuln_types.items(), key=lambda x: -x[1])[:10]
            ),
            "best_performing_chain": max(
                self.results, key=lambda c: self.results[c].avg_confidence(), default="N/A"
            ),
        }

    def _write_text_report(self, report: Dict, path: Path):
        """Write a human-readable text report."""
        lines = [
            "=" * 60,
            "  FaultSeeker++ Cross-Chain Analysis Report",
            f"  Generated: {report['timestamp']}",
            "=" * 60,
            "",
            f"  Chains Analyzed: {', '.join(report['chains_analyzed'])}",
            "",
        ]

        summary = report["summary"]
        lines += [
            "── SUMMARY ──────────────────────────────────────────────",
            f"  Total Transactions   : {summary['total_transactions']}",
            f"  Successful           : {summary['total_successful']}",
            f"  Overall Success Rate : {summary['overall_success_rate']}%",
            f"  Avg Confidence Score : {summary['overall_avg_confidence']}",
            f"  Best Performing Chain: {summary['best_performing_chain']}",
            "",
            "  Top Vulnerability Types (All Chains):",
        ]
        for vuln, count in summary["top_vuln_types_across_chains"].items():
            lines.append(f"    {vuln:<40}  {count}")

        lines.append("")
        lines.append("── PER-CHAIN RESULTS ────────────────────────────────────")
        for chain, data in report["per_chain"].items():
            lines += [
                f"",
                f"  Chain         : {chain.upper()}",
                f"  Transactions  : {data['total_txns']} "
                f"(✓ {data['successful']} / ✗ {data['failed']})",
                f"  Success Rate  : {data['success_rate']}%",
                f"  Avg Confidence: {data['avg_confidence']}",
                f"  Top Vuln Types: {list(data['top_vuln_types'].keys())[:3]}",
                f"  Complexity    : {data['complexity_distribution']}",
            ]

        lines += ["", "=" * 60]
        path.write_text("\n".join(lines), encoding="utf-8")


# ── CLI Entry Point ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="FaultSeeker++ Cross-Chain Analysis Runner (Gap 6)"
    )
    parser.add_argument(
        "--txns", default="benchmark/benchmark_classification_fixed.csv",
        help="Path to benchmark CSV file"
    )
    parser.add_argument(
        "--chains", nargs="+", choices=SUPPORTED_CHAINS, default=None,
        help="Chains to analyze (default: all)"
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Max transactions per chain (for quick testing)"
    )
    parser.add_argument(
        "--model", default="gpt-4o-mini",
        help="Cloud LLM model name"
    )
    parser.add_argument(
        "--local-model", default="phi3:mini",
        help="Local Ollama model name"
    )
    parser.add_argument(
        "--cloud-only", action="store_true",
        help="Skip hybrid routing, use cloud model only"
    )
    parser.add_argument(
        "--output-dir", default="reports/cross_chain",
        help="Directory to save reports"
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    analyzer = CrossChainAnalyzer(
        model=args.model,
        local_model=args.local_model,
        use_hybrid=not args.cloud_only,
        output_dir=args.output_dir,
    )

    report = analyzer.run(
        csv_path=args.txns,
        chains=args.chains,
        limit=args.limit,
    )

    # Print summary to stdout
    summary = report["summary"]
    print(f"\n{'='*50}")
    print(f"  Cross-Chain Analysis Complete")
    print(f"{'='*50}")
    print(f"  Total TXNs  : {summary['total_transactions']}")
    print(f"  Success Rate: {summary['overall_success_rate']}%")
    print(f"  Avg Confidence: {summary['overall_avg_confidence']}")
    print(f"  Best Chain  : {summary['best_performing_chain']}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
