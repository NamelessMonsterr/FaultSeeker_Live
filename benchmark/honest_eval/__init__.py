"""Leakage-free evaluation harness for FaultSeeker++.

This package replaces the legacy `run_research_experiments.py` scoring path,
which derived every score from the ground-truth `label` column. Modules here
never receive labels alongside features, and `leakage_guard` makes label access
raise at runtime.
"""

from .leakage_guard import GuardedFeatures, LeakageError, audit_scorer
from .metrics import (
    bootstrap_f1_ci,
    brier_score,
    classification_metrics,
    expected_calibration_error,
    f1_score,
    mcnemar_counts,
    mcnemar_statistic,
    reliability_table,
)
from .features import (
    EvalRow,
    audit_feature_coverage,
    comparable_subset,
    feature_dict,
    load_benign_rows,
    load_exploit_rows,
)
from .localization import (
    LocalizationTarget,
    load_ground_truth,
    load_predictions,
    localization_metrics,
    rank_of_first_hit,
)

__all__ = [
    "GuardedFeatures",
    "LeakageError",
    "audit_scorer",
    "bootstrap_f1_ci",
    "brier_score",
    "classification_metrics",
    "expected_calibration_error",
    "f1_score",
    "mcnemar_counts",
    "mcnemar_statistic",
    "reliability_table",
    "EvalRow",
    "audit_feature_coverage",
    "comparable_subset",
    "feature_dict",
    "load_benign_rows",
    "load_exploit_rows",
    "LocalizationTarget",
    "load_ground_truth",
    "load_predictions",
    "localization_metrics",
    "rank_of_first_hit",
]
