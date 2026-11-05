"""Classification, calibration and bootstrap metrics for FaultSeeker++.

All functions here operate on (label, score) pairs only -- they never see the
dataset -- so they cannot leak. The bootstrap resamples the *pooled* metric,
which fixes a real defect in the legacy harness where per-chain F1 values were
resampled, producing a CI whose lower bound exceeded the point estimate.
"""

from __future__ import annotations

import math
import random
from typing import Dict, List, Sequence, Tuple


def confusion(labels: Sequence[int], scores: Sequence[float], threshold: float) -> Dict[str, int]:
    tp = fp = tn = fn = 0
    for y, s in zip(labels, scores):
        predicted = 1 if s >= threshold else 0
        if y == 1 and predicted == 1:
            tp += 1
        elif y == 0 and predicted == 1:
            fp += 1
        elif y == 0 and predicted == 0:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def classification_metrics(
    labels: Sequence[int], scores: Sequence[float], threshold: float
) -> Dict[str, float]:
    """Return precision/recall/F1/accuracy/FPR metrics.

    Raises:
        ValueError: if len(labels) != len(scores).
    """
    if len(labels) != len(scores):
        raise ValueError(
            f"classification_metrics: labels/scores length mismatch "
            f"({len(labels)} vs {len(scores)})"
        )
    cm = confusion(labels, scores, threshold)
    tp, fp, tn, fn = cm["tp"], cm["fp"], cm["tn"], cm["fn"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(labels) if labels else 0.0
    out: Dict[str, float] = dict(cm)
    out.update(
        {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "accuracy": round(accuracy, 4),
            "threshold": threshold,
            "n": len(labels),
        }
    )
    return out


def f1_score(labels: Sequence[int], scores: Sequence[float], threshold: float) -> float:
    cm = confusion(labels, scores, threshold)
    tp, fp, fn = cm["tp"], cm["fp"], cm["fn"]
    denom = 2 * tp + fp + fn
    return (2 * tp / denom) if denom else 0.0


def bootstrap_f1_ci(
    labels: Sequence[int],
    scores: Sequence[float],
    threshold: float,
    resamples: int = 1000,
    alpha: float = 0.05,
    seed: int = 17,
) -> Tuple[float, float]:
    """Percentile bootstrap CI for the pooled F1.

    Resamples transactions with replacement and recomputes pooled F1 on each
    resample, so the interval is guaranteed to bracket the point estimate in
    the usual way.
    """
    n = len(labels)
    if n == 0 or resamples <= 0:
        return (0.0, 0.0)
    rng = random.Random(seed)
    stats: List[float] = []
    for _ in range(resamples):
        idx = [rng.randrange(n) for _ in range(n)]
        rs_labels = [labels[i] for i in idx]
        rs_scores = [scores[i] for i in idx]
        stats.append(f1_score(rs_labels, rs_scores, threshold))
    stats.sort()
    lo = stats[max(0, int(math.floor((alpha / 2) * len(stats))))]
    hi = stats[min(len(stats) - 1, int(math.ceil((1 - alpha / 2) * len(stats))) - 1)]
    return (round(lo, 4), round(hi, 4))


def brier_score(labels: Sequence[int], probabilities: Sequence[float]) -> float:
    """Mean squared error between predicted probability and outcome (Eq. 7).

    Returns:
        float score, or None if any probability is nonfinite (nan/inf).

    Raises:
        ValueError: if len(labels) != len(probabilities).
    """
    if len(labels) != len(probabilities):
        raise ValueError(
            f"brier_score: labels/probabilities length mismatch "
            f"({len(labels)} vs {len(probabilities)})"
        )
    if not labels:
        return 0.0
    for p in probabilities:
        if not math.isfinite(p):
            return None  # type: ignore[return-value]
    total = sum((p - y) ** 2 for y, p in zip(labels, probabilities))
    return round(total / len(labels), 6)


def expected_calibration_error(
    labels: Sequence[int], probabilities: Sequence[float], bins: int = 10
) -> float:
    """Binned expected calibration error (Eq. 8), B=10 by default."""
    n = len(labels)
    if n == 0 or bins <= 0:
        return 0.0
    buckets: List[List[Tuple[int, float]]] = [[] for _ in range(bins)]
    for y, p in zip(labels, probabilities):
        p = min(max(float(p), 0.0), 1.0)
        index = min(bins - 1, int(p * bins))
        buckets[index].append((int(y), p))
    ece = 0.0
    for bucket in buckets:
        if not bucket:
            continue
        acc = sum(y for y, _ in bucket) / len(bucket)
        conf = sum(p for _, p in bucket) / len(bucket)
        ece += (len(bucket) / n) * abs(acc - conf)
    return round(ece, 6)


def reliability_table(
    labels: Sequence[int], probabilities: Sequence[float], bins: int = 10
) -> List[Dict[str, float]]:
    """Per-bin accuracy/confidence rows for a reliability diagram."""
    buckets: List[List[Tuple[int, float]]] = [[] for _ in range(bins)]
    for y, p in zip(labels, probabilities):
        p = min(max(float(p), 0.0), 1.0)
        buckets[min(bins - 1, int(p * bins))].append((int(y), p))
    rows = []
    for i, bucket in enumerate(buckets):
        rows.append(
            {
                "bin_lower": round(i / bins, 3),
                "bin_upper": round((i + 1) / bins, 3),
                "count": len(bucket),
                "mean_confidence": round(
                    sum(p for _, p in bucket) / len(bucket), 4
                )
                if bucket
                else 0.0,
                "empirical_accuracy": round(
                    sum(y for y, _ in bucket) / len(bucket), 4
                )
                if bucket
                else 0.0,
            }
        )
    return rows


def mcnemar_counts(
    labels: Sequence[int],
    scores_a: Sequence[float],
    scores_b: Sequence[float],
    threshold: float,
) -> Dict[str, int]:
    """Discordant-pair counts for McNemar's test between two systems."""
    b = c = 0
    for y, sa, sb in zip(labels, scores_a, scores_b):
        pa = 1 if sa >= threshold else 0
        pb = 1 if sb >= threshold else 0
        correct_a = pa == y
        correct_b = pb == y
        if correct_a and not correct_b:
            b += 1
        elif correct_b and not correct_a:
            c += 1
    return {"a_only_correct": b, "b_only_correct": c}


def mcnemar_statistic(counts: Dict[str, int]) -> Dict[str, float]:
    """Continuity-corrected chi-square statistic for McNemar's test."""
    b = counts["a_only_correct"]
    c = counts["b_only_correct"]
    if b + c == 0:
        return {"chi_square": 0.0, "discordant_pairs": 0}
    chi = (abs(b - c) - 1) ** 2 / (b + c)
    return {"chi_square": round(chi, 4), "discordant_pairs": b + c}
