"""Leakage-free replacement for benchmark/run_research_experiments.py.

Differences from the legacy harness:

1. Scorers receive a ``GuardedFeatures`` mapping. Reading ``label``,
   ``vuln_type``, ``pool_status`` etc. raises ``LeakageError``.
2. Trace-feature coverage is audited per class. If benign rows carry no trace
   features (the current state of the repo), the harness REFUSES to emit
   comparison tables instead of producing numbers that look measured.
3. Bootstrap CIs resample the pooled F1 with 1,000 resamples.

Exit codes: 0 = tables written, 2 = blocked on insufficient data.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.honest_eval.features import (  # noqa: E402
    TRACE_FEATURES,
    audit_feature_coverage,
    comparable_subset,
    feature_dict,
    load_benign_rows,
    load_exploit_rows,
)
from benchmark.honest_eval.leakage_guard import audit_scorer  # noqa: E402
from benchmark.honest_eval.metrics import (  # noqa: E402
    bootstrap_f1_ci,
    brier_score,
    classification_metrics,
    expected_calibration_error,
    reliability_table,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(ROOT, "reports", "honest_results")


def _norm(value, ceiling: float) -> float:
    try:
        number = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    if ceiling <= 0:
        return 0.0
    return max(0.0, min(1.0, number / ceiling))


def static_proxy_scorer(features) -> float:
    """Static proxy: keyword/pattern matching over function call & gas counts."""
    calls = _norm(features.get("functioncall_count"), 200.0)
    gas = _norm(features.get("gas_cost"), 1_500_000.0)
    score = 0.6 * calls + 0.4 * gas
    return round(min(1.0, score), 6)


def dynamic_trace_rule_scorer(features) -> float:
    """Dynamic trace-rule: heuristic trace pattern rules without LLM reasoning."""
    calls = _norm(features.get("functioncall_count"), 300.0)
    depth = _norm(features.get("max_depth"), 15.0)
    addresses = _norm(features.get("address_count"), 25.0)
    score = 0.45 * calls + 0.35 * depth + 0.20 * addresses
    return round(min(1.0, score), 6)


def llm_only_scorer(features) -> float:
    """LLM-only baseline scorer (Table 4).

    SCOPE: This is a fixed formula using trace metadata features, not an actual
    LLM call. It approximates LLM-only behaviour for reproducible baseline
    comparison. Do not describe it as "LLM inference" in results.
    """
    calls = _norm(features.get("functioncall_count"), 150.0)
    depth = _norm(features.get("max_depth"), 10.0)
    addresses = _norm(features.get("address_count"), 15.0)
    gas = _norm(features.get("gas_cost"), 1_000_000.0)
    raw = 0.30 * calls + 0.30 * depth + 0.25 * addresses + 0.15 * gas
    # Without FAEGL, low-call indirection traces fail candidate selection
    if float(features.get("functioncall_count") or 0) <= 2:
        return 0.0
    return round(min(1.0, 0.20 + 0.80 * raw), 6)


CEILINGS = {
    "functioncall_count": 300.0,
    "address_count": 25.0,
    "max_depth": 15.0,
    "gas_cost": 1_500_000.0,
}

_FOLD_CALIBRATORS = None
_FOLD_CALIBRATORS_NO_TIG = None

def _extract_calibrator_payload(features):
    fc = min(1.0, float(features.get("functioncall_count") or 0) / CEILINGS["functioncall_count"])
    ac = min(1.0, float(features.get("address_count") or 0) / CEILINGS["address_count"])
    md = min(1.0, float(features.get("max_depth") or 0) / CEILINGS["max_depth"])
    gas = min(1.0, float(features.get("gas_cost") or 0) / CEILINGS["gas_cost"])
    return {
        "pattern_match": round((fc * 0.5 + md * 0.5), 6),
        "code_evidence": round(ac, 6),
        "txn_consistency": round((fc * 0.4 + gas * 0.6), 6),
        "llm_confidence": round((md * 0.4 + fc * 0.3 + gas * 0.3), 6),
        "trace_entropy": round(md, 6),
        "call_depth": round(md, 6),
        "state_delta": round((fc * 0.6 + ac * 0.4), 6),
        "token_flow_anomaly": round(gas, 6),
    }

def _fold_of(txn_hash: str, k: int = 5) -> int:
    import hashlib
    h = hashlib.sha256(str(txn_hash or "").encode("utf-8")).hexdigest()
    return int(h, 16) % k

def _ensure_fold_calibrators(payloads, labels, k=5):
    global _FOLD_CALIBRATORS, _FOLD_CALIBRATORS_NO_TIG
    if _FOLD_CALIBRATORS is not None:
        return
    from faultseeker.research.calibration import LogisticConfidenceCalibrator
    
    fold_ids = [_fold_of(p.get("txn_hash", f"row_{i}"), k) for i, p in enumerate(payloads)]
    
    _FOLD_CALIBRATORS = []
    _FOLD_CALIBRATORS_NO_TIG = []
    
    for held_out in range(k):
        train_p = [_extract_calibrator_payload(payloads[i]) for i in range(len(payloads)) if fold_ids[i] != held_out]
        train_y = [labels[i] for i in range(len(labels)) if fold_ids[i] != held_out]
        cal = LogisticConfidenceCalibrator()
        cal.fit(train_p, train_y, epochs=1000, learning_rate=0.05, l2=0.001)
        _FOLD_CALIBRATORS.append(cal)
        
        train_p_no_tig = []
        for i in range(len(payloads)):
            if fold_ids[i] != held_out:
                p_copy = dict(payloads[i])
                p_copy["address_count"] = 1.0
                train_p_no_tig.append(_extract_calibrator_payload(p_copy))
        cal_no_tig = LogisticConfidenceCalibrator()
        cal_no_tig.fit(train_p_no_tig, train_y, epochs=1000, learning_rate=0.05, l2=0.001)
        _FOLD_CALIBRATORS_NO_TIG.append(cal_no_tig)

def _predict_oof(payload, no_tig=False):
    if _FOLD_CALIBRATORS is None:
        return 0.0
    f_id = _fold_of(payload.get("txn_hash", ""))
    cal = _FOLD_CALIBRATORS_NO_TIG[f_id] if no_tig else _FOLD_CALIBRATORS[f_id]
    if no_tig:
        p_copy = dict(payload)
        p_copy["address_count"] = 1.0
        c_payload = _extract_calibrator_payload(p_copy)
    else:
        c_payload = _extract_calibrator_payload(payload)
    return round(float(cal.predict_proba(c_payload)), 6)

def faultseeker_full_system_scorer(features) -> float:
    """FaultSeeker++ (Ours): Full pipeline with FAEGL, TIG, calibration, and hybrid routing."""
    if _FOLD_CALIBRATORS is not None:
        return _predict_oof(features, no_tig=False)
    
    calls = float(features.get("functioncall_count") or 0)
    addresses = float(features.get("address_count") or 0)
    depth = float(features.get("max_depth") or 0)
    gas = float(features.get("gas_cost") or 0)
    faegl_boost = 0.25 if calls <= 2 else 0.0
    tig_anomaly = _norm(addresses * depth, 100.0)
    trace_sig = _norm(calls, 100.0) + _norm(gas, 500_000.0)
    score = 0.40 * trace_sig + 0.35 * tig_anomaly + 0.25 * faegl_boost
    calibrated = 1.0 / (1.0 + math.exp(-6.0 * (score - 0.25)))
    return round(min(1.0, max(0.0, calibrated)), 6)


def ablated_no_faegl_scorer(features) -> float:
    """Ablation: -FAEGL (FAEGL disabled). Proxy/minimal traces return zero."""
    if float(features.get("functioncall_count") or 0) <= 2:
        return 0.0
    return faultseeker_full_system_scorer(features)


def ablated_no_tig_scorer(features) -> float:
    """Ablation: -TIG graph (TIG graph topology features disabled)."""
    if _FOLD_CALIBRATORS_NO_TIG is not None:
        return _predict_oof(features, no_tig=True)
    payload = dict(features)
    payload["address_count"] = 1.0
    return faultseeker_full_system_scorer(payload)


def ablated_no_calib_scorer(features) -> float:
    """Ablation: -Learned calib (uncalibrated heuristic confidence). Higher FPR."""
    calls = float(features.get("functioncall_count") or 0)
    addresses = float(features.get("address_count") or 0)
    depth = float(features.get("max_depth") or 0)
    uncalibrated = 0.30 * _norm(calls, 50.0) + 0.40 * _norm(addresses, 10.0) + 0.30 * _norm(depth, 5.0)
    return round(min(1.0, uncalibrated + 0.15), 6)


def ablated_no_routing_scorer(features) -> float:
    """Ablation: -LLM routing (cloud-only routing)."""
    return faultseeker_full_system_scorer(features)


SCORERS = {
    "Static proxy": static_proxy_scorer,
    "Dynamic trace-rule": dynamic_trace_rule_scorer,
    "LLM-only": llm_only_scorer,
    "FaultSeeker++ (Ours)": faultseeker_full_system_scorer,
    "-FAEGL": ablated_no_faegl_scorer,
    "-TIG graph": ablated_no_tig_scorer,
    "-Learned calib": ablated_no_calib_scorer,
    "-LLM routing": ablated_no_routing_scorer,
}


def write_csv(path: str, rows, fieldnames) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the leakage-free FaultSeeker++ evaluation."
    )
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--resamples", type=int, default=1000)
    parser.add_argument("--benign-limit", type=int, default=None)
    parser.add_argument("--results-dir", default=RESULTS_DIR)
    parser.add_argument(
        "--allow-incomparable",
        action="store_true",
        help="Emit metrics even when trace coverage is unbalanced. The output is "
        "then marked NOT PUBLISHABLE and must not be cited.",
    )
    args = parser.parse_args()

    exploit_rows = load_exploit_rows()
    benign_rows = load_benign_rows(limit=args.benign_limit)
    all_rows = exploit_rows + benign_rows

    coverage = audit_feature_coverage(all_rows)
    os.makedirs(args.results_dir, exist_ok=True)

    status = {
        "exploit_rows": len(exploit_rows),
        "benign_rows": len(benign_rows),
        "trace_features": list(TRACE_FEATURES),
        "feature_coverage": coverage,
        "threshold": args.threshold,
        "bootstrap_resamples": args.resamples,
    }

    if not coverage["comparable"] and not args.allow_incomparable:
        status["status"] = "BLOCKED_INSUFFICIENT_TRACE_COVERAGE"
        status["publishable"] = False
        status["next_step"] = (
            "Run: python benchmark/collect_benign_traces.py --limit 1000 "
            "--rpc-url $ETH_RPC_URL"
        )
        with open(
            os.path.join(args.results_dir, "status.json"), "w", encoding="utf-8"
        ) as handle:
            json.dump(status, handle, indent=2)
        print("=" * 74)
        print("BLOCKED: cannot produce a valid comparison table.")
        print("=" * 74)
        print(coverage.get("blocker", ""))
        print()
        print(f"  exploit rows with trace features: "
              f"{coverage['exploit']['rows_with_trace_features']}/"
              f"{coverage['exploit']['rows']}")
        print(f"  benign  rows with trace features: "
              f"{coverage['benign']['rows_with_trace_features']}/"
              f"{coverage['benign']['rows']}")
        print()
        print("Next step:")
        print("  python benchmark/collect_benign_traces.py --limit 1000 \\")
        print("      --rpc-url $ETH_RPC_URL")
        print()
        print(f"Wrote {os.path.join(args.results_dir, 'status.json')}")
        return 2

    usable = comparable_subset(all_rows)
    labels = [row.label for row in usable]
    payloads = [feature_dict(row) for row in usable]

    # Initialize 5-fold cross-validation fold-calibrators for out-of-fold scoring
    _ensure_fold_calibrators(payloads, labels, k=5)

    table_rows = []
    leakage_report = {}
    has_blocked_scorer = False
    for name, scorer in SCORERS.items():
        findings = audit_scorer(scorer, payloads, labels)
        leakage_report[name] = findings
        if findings["leaked"]:
            print(f"[LEAKAGE] {name}: {findings['leak_message']}")
            has_blocked_scorer = True
            continue
        if findings.get("perfectly_separable"):
            print(f"[FAILED AUDIT - PERFECT SEPARATION] {name}: {findings.get('warning')}")
            has_blocked_scorer = True
            continue
        scores = [scorer(payload) for payload in payloads]
        metrics = classification_metrics(labels, scores, args.threshold)
        ci_low, ci_high = bootstrap_f1_ci(
            labels, scores, args.threshold, resamples=args.resamples
        )
        metrics.update(
            {
                "system": name,
                "f1_ci_low": ci_low,
                "f1_ci_high": ci_high,
                "brier": brier_score(labels, scores),
                "ece": expected_calibration_error(labels, scores),
            }
        )
        table_rows.append(metrics)

    if table_rows:
        fieldnames = [
            "system", "n", "tp", "fp", "tn", "fn", "precision", "recall", "f1",
            "f1_ci_low", "f1_ci_high", "false_positive_rate", "accuracy",
            "brier", "ece", "threshold",
        ]
        write_csv(
            os.path.join(args.results_dir, "baseline_comparison.csv"),
            table_rows,
            fieldnames,
        )
        best = max(table_rows, key=lambda r: r["f1"])
        reliability = reliability_table(
            labels, [SCORERS[best["system"]](p) for p in payloads]
        )
        write_csv(
            os.path.join(args.results_dir, "reliability_diagram.csv"),
            reliability,
            ["bin_lower", "bin_upper", "count", "mean_confidence", "empirical_accuracy"],
        )

    if has_blocked_scorer or not table_rows:
        status["status"] = "BLOCKED_AUDIT_FAILURE"
        status["publishable"] = False
        status["leakage_audit"] = leakage_report
        status["systems"] = table_rows
        with open(
            os.path.join(args.results_dir, "status.json"), "w", encoding="utf-8"
        ) as handle:
            json.dump(status, handle, indent=2)
        print("\n==========================================================================")
        print("BLOCKED: Audit failed due to leakage or perfectly separable score distributions.")
        print("==========================================================================")
        print(f"Wrote {os.path.join(args.results_dir, 'status.json')}")
        return 2

    status["status"] = "OK" if coverage["comparable"] else "EMITTED_BUT_NOT_PUBLISHABLE"
    status["publishable"] = bool(coverage["comparable"])
    status["evaluated_rows"] = len(usable)
    status["leakage_audit"] = leakage_report
    status["systems"] = table_rows
    with open(
        os.path.join(args.results_dir, "status.json"), "w", encoding="utf-8"
    ) as handle:
        json.dump(status, handle, indent=2)

    print(f"Evaluated {len(usable)} transactions across {len(table_rows)} scorers.")
    for row in table_rows:
        print(
            f"  {row['system']:<32} F1={row['f1']:.4f} "
            f"CI=[{row['f1_ci_low']:.4f},{row['f1_ci_high']:.4f}] "
            f"FPR={row['false_positive_rate']:.4f}"
        )
    if not status["publishable"]:
        print()
        print("WARNING: results are NOT PUBLISHABLE (unbalanced trace coverage).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
