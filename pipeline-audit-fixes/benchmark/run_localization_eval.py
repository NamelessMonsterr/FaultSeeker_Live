"""Fault-localization evaluation: Top-k accuracy and MRR on real ground truth.

This is the metric that matches the paper's actual contribution. It uses the
curated ``benchmark/ground_truth/*.json`` corpus, which contains genuine
contract/function/line targets for each incident.

Usage::

    python benchmark/run_localization_eval.py --predictions-dir data/output

Exit codes: 0 = metrics written, 2 = no predictions available.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.honest_eval.localization import (  # noqa: E402
    GROUND_TRUTH_DIR,
    load_ground_truth,
    load_predictions,
    localization_metrics,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(ROOT, "reports", "honest_results")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate fault localization against curated ground truth."
    )
    parser.add_argument("--ground-truth-dir", default=GROUND_TRUTH_DIR)
    parser.add_argument(
        "--predictions-dir",
        default=os.path.join(ROOT, "data", "output"),
        help="Directory of pipeline output JSON files (scored_functions).",
    )
    parser.add_argument("--results-dir", default=RESULTS_DIR)
    parser.add_argument(
        "--match",
        choices=["function", "line", "either"],
        default="function",
        help="Granularity at which a prediction counts as correct.",
    )
    args = parser.parse_args()

    targets = load_ground_truth(args.ground_truth_dir)
    predictions, provenance = load_predictions(args.predictions_dir)
    metrics = localization_metrics(targets, predictions, provenance_by_tx=provenance, match=args.match)

    corpus = {
        "ground_truth_dir": os.path.relpath(args.ground_truth_dir, ROOT),
        "predictions_dir": os.path.relpath(args.predictions_dir, ROOT),
        "ground_truth_files_with_targets": len(targets),
        "function_level_targets": sum(len(t.functions) for t in targets),
        "line_level_targets": sum(len(t.lines) for t in targets),
        "transactions_with_valid_predictions": len(predictions),
    }
    payload = {
        "corpus": corpus,
        "predictions_provenance": provenance,
        "metrics": metrics,
    }

    os.makedirs(args.results_dir, exist_ok=True)
    out_path = os.path.join(args.results_dir, "localization_metrics.json")
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    print("Localization ground truth")
    print(f"  transactions with targets          : {corpus['ground_truth_files_with_targets']}")
    print(f"  function-level targets             : {corpus['function_level_targets']}")
    print(f"  line-level targets                 : {corpus['line_level_targets']}")
    print(f"  transactions with valid predictions: {corpus['transactions_with_valid_predictions']}")
    print(f"  usable traces (trace_status='ok')  : {metrics.get('evaluated', 0)}")
    print(f"  excluded unavailable traces        : {metrics.get('excluded_unavailable_traces', 0)}")
    print(f"  excluded error traces              : {metrics.get('excluded_error_traces', 0)}")
    print(f"  usable trace ratio                 : {metrics.get('usable_trace_ratio', 0.0) * 100:.1f}%")
    print()

    if metrics.get("blocker"):
        print("BLOCKED: " + metrics["blocker"])
        print()
        print(f"Wrote {out_path}")
        return 2

    fn_metrics = localization_metrics(targets, predictions, match="function")
    line_metrics = localization_metrics(targets, predictions, match="line")

    # Strict structural validity assertion: line-level Top-k hit rate CANNOT exceed function-level Top-k hit rate
    if fn_metrics.get("evaluated", 0) > 0:
        for k in (1, 3, 5, 10):
            line_hit = line_metrics.get(f"top_{k}_accuracy", 0.0)
            fn_hit = fn_metrics.get(f"top_{k}_accuracy", 0.0)
            assert line_hit <= fn_hit + 1e-9, (
                f"VIOLATION: Line-level Top-{k} ({line_hit:.4f}) exceeds Function-level Top-{k} ({fn_hit:.4f}). "
                "A correct line match requires a correct function match; check prediction matching logic for substring leakage!"
            )

    print(f"Localization results (match={metrics['match_mode']})")
    print(f"  evaluated : {metrics['evaluated']}")
    for k in (1, 3, 5, 10):
        key = f"top_{k}_accuracy"
        if key in metrics:
            print(f"  Top-{k:<3}  : {metrics[key]:.4f} ({metrics[f'top_{k}_hits']} hits)")
    print(f"  MRR       : {metrics['mrr']:.4f}")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
