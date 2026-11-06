"""Retrain + evaluate the calibrator with K-FOLD CROSS-VALIDATION.

Fixes a train/test leakage bug in the original benchmark/retrain_calibrator.py:
that script fit the logistic calibrator on ALL 1,231 rows (231 exploit + 1,000
benign) and then evaluated it on those SAME 1,231 rows. Every reported number
(F1, FPR, Brier, ECE) was therefore measuring memorization, not generalization.

This version:
  1. Splits rows into K folds (deterministic, by txn_hash).
  2. For each fold f: trains a calibrator on the OTHER K-1 folds only, then
     scores fold f's rows with that calibrator. No row is ever scored by a
     calibrator that saw it during training.
  3. Aggregates out-of-fold predictions across all K folds into one
     confusion matrix / F1 / FPR / Brier / ECE -- these numbers are safe to
     report and cite.
  4. Separately, fits one FINAL calibrator on all 1,231 rows for deployment
     (data/models/calibrator.json) -- this is fine to ship as the production
     model, it is just not fine to evaluate on the same data it was fit on.

Usage:
    python benchmark/retrain_calibrator_kfold.py --folds 5
"""
import argparse
import csv
import hashlib
import json
import os
import sys

sys.path.insert(0, ".")
from dotenv import load_dotenv
load_dotenv()

from faultseeker.research.calibration import LogisticConfidenceCalibrator

EXPLOIT_CSV = "benchmark/benchmark_classification_fixed.csv"
BENIGN_TRACES = "benchmark/imported/benign_traces.csv"
MODEL_OUT = "data/models/calibrator.json"
CV_METRICS_OUT = "data/models/calibrator_cv_metrics.json"

CEILINGS = {
    "functioncall_count": 300.0,
    "address_count": 25.0,
    "max_depth": 15.0,
    "gas_cost": 1_500_000.0,
}


def normalize(row):
    normed = {}
    for feat, ceiling in CEILINGS.items():
        try:
            v = float(row.get(feat) or 0.0)
        except (TypeError, ValueError):
            v = 0.0
        normed[feat] = max(0.0, min(1.0, v / ceiling)) if ceiling > 0 else 0.0
    fc, ac, md, gas = (
        normed["functioncall_count"],
        normed["address_count"],
        normed["max_depth"],
        normed["gas_cost"],
    )
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


def fold_of(txn_hash: str, k: int) -> int:
    """Deterministic fold assignment from txn_hash so re-runs are reproducible."""
    h = hashlib.sha256(txn_hash.encode("utf-8")).hexdigest()
    return int(h, 16) % k


def load_rows():
    """Returns list of (txn_hash, features_dict, label)."""
    rows = []
    with open(EXPLOIT_CSV, encoding="utf-8-sig") as f:
        for raw in csv.DictReader(f):
            txn = str(raw.get("txn_hash") or raw.get("hash") or "").strip().lower()
            if not txn:
                # fall back to a stable synthetic key so every row still gets a fold
                txn = "exploit_row_%d" % len(rows)
            rows.append((txn, normalize(raw), 1))
    n_exploit = len(rows)

    with open(BENIGN_TRACES, encoding="utf-8-sig") as f:
        for raw in csv.DictReader(f):
            if str(raw.get("collection_status", "").strip().lower()) != "ok":
                continue
            txn = str(raw.get("txn_hash") or "").strip().lower()
            if not txn:
                txn = "benign_row_%d" % len(rows)
            rows.append((txn, normalize(raw), 0))
    n_benign = len(rows) - n_exploit

    print(f"Loaded {n_exploit} exploit rows, {n_benign} benign rows, {len(rows)} total")
    return rows


def evaluate_confusion(scores, labels, threshold=0.5):
    tp = sum(1 for s, y in zip(scores, labels) if y == 1 and s >= threshold)
    fp = sum(1 for s, y in zip(scores, labels) if y == 0 and s >= threshold)
    tn = sum(1 for s, y in zip(scores, labels) if y == 0 and s < threshold)
    fn = sum(1 for s, y in zip(scores, labels) if y == 1 and s < threshold)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    brier = sum((s - y) ** 2 for s, y in zip(scores, labels)) / len(labels)
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4), "brier": round(brier, 4),
        "n": len(labels),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--epochs", type=int, default=1000)
    ap.add_argument("--lr", type=float, default=0.05)
    ap.add_argument("--l2", type=float, default=0.001)
    args = ap.parse_args()
    K = args.folds

    rows = load_rows()
    fold_ids = [fold_of(txn, K) for txn, _, _ in rows]

    print(f"\nFold sizes: {[fold_ids.count(k) for k in range(K)]}")

    oof_scores = [None] * len(rows)  # out-of-fold prediction for every row

    for held_out in range(K):
        train_idx = [i for i in range(len(rows)) if fold_ids[i] != held_out]
        test_idx = [i for i in range(len(rows)) if fold_ids[i] == held_out]

        X_train = [rows[i][1] for i in train_idx]
        y_train = [rows[i][2] for i in train_idx]

        cal = LogisticConfidenceCalibrator()
        cal.fit(X_train, y_train, epochs=args.epochs, learning_rate=args.lr, l2=args.l2)

        for i in test_idx:
            oof_scores[i] = cal.predict_proba(rows[i][1])

        train_exploit = sum(y_train)
        print(f"  fold {held_out}: trained on {len(train_idx)} rows "
              f"({train_exploit} exploit / {len(train_idx)-train_exploit} benign), "
              f"scored {len(test_idx)} held-out rows")

    assert all(s is not None for s in oof_scores), "every row must get an out-of-fold score"

    labels = [r[2] for r in rows]
    cv_metrics = evaluate_confusion(oof_scores, labels, threshold=0.5)

    print("\n" + "=" * 60)
    print(f"{K}-FOLD CROSS-VALIDATED RESULTS (leakage-free)")
    print("=" * 60)
    for k, v in cv_metrics.items():
        print(f"  {k}: {v}")

    # ---- Final production model: fit on ALL rows (fine for deployment,
    #      NOT the number we report as evaluation performance) ----
    X_all = [r[1] for r in rows]
    y_all = [r[2] for r in rows]
    final_cal = LogisticConfidenceCalibrator()
    final_cal.fit(X_all, y_all, epochs=args.epochs, learning_rate=args.lr, l2=args.l2)
    os.makedirs("data/models", exist_ok=True)
    final_cal.save(MODEL_OUT)
    print(f"\nSaved production calibrator (fit on all data) to {MODEL_OUT}")
    print("NOTE: do not evaluate this saved model against the training set and "
          "report those numbers -- use the cross-validated numbers above instead.")

    with open(CV_METRICS_OUT, "w") as f:
        json.dump({
            "method": f"{K}-fold cross-validation, deterministic fold-by-hash assignment",
            "leakage": "none: every prediction scored by a model that never saw that row in training",
            "folds": K,
            "dataset": {"exploit_rows": sum(1 for r in rows if r[2] == 1),
                        "benign_rows": sum(1 for r in rows if r[2] == 0),
                        "total": len(rows)},
            "cv_metrics": cv_metrics,
        }, f, indent=2)
    print(f"Saved CV metrics to {CV_METRICS_OUT}")


if __name__ == "__main__":
    main()
