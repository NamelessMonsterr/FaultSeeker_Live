"""Tests for the leakage-free evaluation harness."""

import math

import pytest

from benchmark.honest_eval.features import (
    EvalRow,
    audit_feature_coverage,
    comparable_subset,
    feature_dict,
)
from benchmark.honest_eval.leakage_guard import (
    FORBIDDEN_FIELDS,
    GuardedFeatures,
    LeakageError,
    audit_scorer,
)
from benchmark.honest_eval.localization import (
    LocalizationTarget,
    localization_metrics,
    rank_of_first_hit,
)
from benchmark.honest_eval.metrics import (
    bootstrap_f1_ci,
    brier_score,
    classification_metrics,
    expected_calibration_error,
    f1_score,
    mcnemar_counts,
    mcnemar_statistic,
    reliability_table,
)


# --------------------------------------------------------------------------
# Leakage guard
# --------------------------------------------------------------------------


def test_guarded_features_exposes_safe_fields():
    guarded = GuardedFeatures({"max_depth": 4, "label": 1})
    assert guarded["max_depth"] == 4
    assert guarded.get("max_depth") == 4


def test_guarded_features_blocks_label_subscript():
    guarded = GuardedFeatures({"max_depth": 4, "label": 1})
    with pytest.raises(LeakageError):
        guarded["label"]


def test_guarded_features_blocks_label_via_get():
    guarded = GuardedFeatures({"label": 1})
    with pytest.raises(LeakageError):
        guarded.get("label", 0)


def test_guarded_features_blocks_membership_probe():
    guarded = GuardedFeatures({"vuln_type": "Reentrancy"})
    with pytest.raises(LeakageError):
        "vuln_type" in guarded


def test_guarded_features_strips_forbidden_from_iteration():
    guarded = GuardedFeatures({"max_depth": 1, "label": 1, "pool_status": "verified"})
    assert set(guarded) == {"max_depth"}
    assert len(guarded) == 1


def test_forbidden_fields_cover_known_leak_columns():
    for column in ("label", "vuln_type", "pool_status", "validation_status", "class"):
        assert column in FORBIDDEN_FIELDS


def test_audit_scorer_detects_label_reading_scorer():
    def leaking(features):
        return 0.9 if features.get("label") == 1 else 0.01

    rows = [{"label": 1, "max_depth": 3}, {"label": 0, "max_depth": 1}]
    findings = audit_scorer(leaking, rows, [1, 0])
    assert findings["leaked"] is True
    assert "label" in findings["leak_message"]


def test_audit_scorer_passes_clean_scorer():
    def clean(features):
        return min(1.0, float(features.get("max_depth") or 0) / 10.0)

    rows = [{"label": 1, "max_depth": 8}, {"label": 0, "max_depth": 1}]
    findings = audit_scorer(clean, rows, [1, 0])
    assert findings["leaked"] is False
    assert findings["scored_rows"] == 2


def test_audit_scorer_flags_perfect_separation():
    def separable(features):
        return 0.99 if float(features.get("max_depth") or 0) > 5 else 0.0

    rows = [{"max_depth": 9}, {"max_depth": 8}, {"max_depth": 1}, {"max_depth": 2}]
    findings = audit_scorer(separable, rows, [1, 1, 0, 0])
    assert findings["perfectly_separable"] is True
    assert "warning" in findings


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------


def test_classification_metrics_basic_counts():
    labels = [1, 1, 0, 0]
    scores = [0.9, 0.2, 0.8, 0.1]
    metrics = classification_metrics(labels, scores, threshold=0.5)
    assert metrics["tp"] == 1
    assert metrics["fn"] == 1
    assert metrics["fp"] == 1
    assert metrics["tn"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5
    assert metrics["false_positive_rate"] == 0.5


def test_f1_perfect_and_zero():
    assert f1_score([1, 0], [1.0, 0.0], 0.5) == 1.0
    assert f1_score([1, 0], [0.0, 1.0], 0.5) == 0.0


def test_bootstrap_ci_brackets_point_estimate():
    labels = [1] * 40 + [0] * 60
    scores = [0.8] * 36 + [0.2] * 4 + [0.1] * 54 + [0.9] * 6
    point = f1_score(labels, scores, 0.5)
    low, high = bootstrap_f1_ci(labels, scores, 0.5, resamples=300)
    assert low <= point <= high, f"CI [{low},{high}] must bracket {point}"


def test_bootstrap_ci_is_deterministic_under_seed():
    labels = [1] * 20 + [0] * 20
    scores = [0.7] * 18 + [0.3] * 2 + [0.2] * 19 + [0.8]
    first = bootstrap_f1_ci(labels, scores, 0.5, resamples=200, seed=5)
    second = bootstrap_f1_ci(labels, scores, 0.5, resamples=200, seed=5)
    assert first == second


def test_bootstrap_ci_handles_empty_input():
    assert bootstrap_f1_ci([], [], 0.5) == (0.0, 0.0)


def test_brier_score_bounds():
    assert brier_score([1, 0], [1.0, 0.0]) == 0.0
    assert brier_score([1, 0], [0.0, 1.0]) == 1.0


def test_expected_calibration_error_perfect_is_zero():
    labels = [1] * 10 + [0] * 10
    probs = [0.95] * 10 + [0.05] * 10
    assert expected_calibration_error(labels, probs) < 0.06


def test_expected_calibration_error_detects_overconfidence():
    labels = [0] * 10
    probs = [0.95] * 10
    assert expected_calibration_error(labels, probs) > 0.9


def test_reliability_table_bins_sum_to_population():
    labels = [1, 0, 1, 0]
    probs = [0.9, 0.1, 0.6, 0.4]
    rows = reliability_table(labels, probs, bins=10)
    assert len(rows) == 10
    assert sum(row["count"] for row in rows) == 4


def test_mcnemar_counts_and_statistic():
    labels = [1, 1, 0, 0]
    a = [0.9, 0.9, 0.1, 0.1]
    b = [0.9, 0.1, 0.9, 0.1]
    counts = mcnemar_counts(labels, a, b, 0.5)
    assert counts["a_only_correct"] == 2
    assert counts["b_only_correct"] == 0
    stat = mcnemar_statistic(counts)
    assert stat["discordant_pairs"] == 2
    assert stat["chi_square"] == pytest.approx(0.5, rel=1e-6)


# --------------------------------------------------------------------------
# Feature coverage
# --------------------------------------------------------------------------


def _row(label, traced=True, idx=0):
    features = (
        {
            "functioncall_count": 10 + idx,
            "address_count": 4 + (idx % 5),
            "max_depth": 3 + (idx % 4),
            "gas_cost": 90000 + idx * 1000,
        }
        if traced
        else {
            "functioncall_count": None,
            "address_count": None,
            "max_depth": None,
            "gas_cost": None,
        }
    )
    return EvalRow(txn_hash=f"0xabc{idx}", chain="eth", label=label, features=features)


def test_has_trace_features_flag():
    assert _row(1, traced=True).has_trace_features is True
    assert _row(0, traced=False).has_trace_features is False


def test_audit_coverage_blocks_when_benign_untraced():
    rows = [_row(1, True, i) for i in range(15)] + [_row(0, False, i) for i in range(15)]
    audit = audit_feature_coverage(rows)
    assert audit["exploit"]["coverage"] == 1.0
    assert audit["benign"]["coverage"] == 0.0
    assert audit["comparable"] is False
    assert "blocker" in audit


def test_audit_coverage_allows_balanced_split():
    rows = [_row(1, True, i) for i in range(15)] + [_row(0, True, i + 20) for i in range(15)]
    audit = audit_feature_coverage(rows)
    assert audit["comparable"] is True
    assert "blocker" not in audit


def test_audit_coverage_blocks_degenerate_constant_features():
    """Verify that constant feature values within a class trigger DEGENERATE_CLASS exit."""
    rows = [_row(1, True, i) for i in range(15)] + [_row(0, True, 0) for _ in range(15)]
    audit = audit_feature_coverage(rows)
    assert audit["comparable"] is False
    assert audit["is_degenerate"] is True
    assert "DEGENERATE_CLASS" in audit["blocker"]


def test_comparable_subset_filters_untraced():
    rows = [_row(1, True), _row(0, False)]
    assert len(comparable_subset(rows)) == 1


def test_feature_dict_excludes_label():
    payload = feature_dict(_row(1, True))
    assert "label" not in payload
    assert payload["max_depth"] == 3


# --------------------------------------------------------------------------
# Localization
# --------------------------------------------------------------------------


def _target():
    return LocalizationTarget(
        txn_hash="0xdead",
        functions={("0xd286", "migratestake")},
        lines={("0xd286", "241")},
    )


def test_rank_of_first_hit_function_match():
    predictions = [
        {"address": "0xAAAA", "function": "transfer"},
        {"address": "0xD286", "function": "migrateStake"},
    ]
    assert rank_of_first_hit(_target(), predictions) == 2


def test_rank_of_first_hit_returns_none_when_absent():
    predictions = [{"address": "0xAAAA", "function": "transfer"}]
    assert rank_of_first_hit(_target(), predictions) is None


def test_rank_of_first_hit_line_match():
    predictions = [{"address": "0xd286", "line": "241"}]
    assert rank_of_first_hit(_target(), predictions, match="line") == 1


def test_rank_ignores_function_signature_parens():
    predictions = [{"address": "0xd286", "function": "migrateStake(uint256)"}]
    assert rank_of_first_hit(_target(), predictions) == 1


def test_localization_metrics_top_k_and_mrr():
    targets = [_target()]
    predictions = {
        "0xdead": [
            {"address": "0xAAAA", "function": "transfer"},
            {"address": "0xd286", "function": "migrateStake"},
        ]
    }
    metrics = localization_metrics(targets, predictions)
    assert metrics["evaluated"] == 1
    assert metrics["top_1_accuracy"] == 0.0
    assert metrics["top_3_accuracy"] == 1.0
    assert metrics["mrr"] == pytest.approx(0.5, rel=1e-6)


def test_localization_metrics_blocks_without_predictions():
    metrics = localization_metrics([_target()], {})
    assert metrics["evaluated"] == 0
    assert metrics["missing_predictions"] == 1
    assert "blocker" in metrics


def test_localization_metrics_counts_misses():
    targets = [_target()]
    predictions = {"0xdead": [{"address": "0xbbbb", "function": "withdraw"}]}
    metrics = localization_metrics(targets, predictions)
    assert metrics["evaluated"] == 1
    assert metrics["top_5_accuracy"] == 0.0
    assert metrics["mrr"] == 0.0


def test_localization_metrics_excludes_non_ok_trace_status():
    targets = [_target()]
    predictions = {"0xdead": [{"address": "0xd286", "function": "migrateStake"}]}
    provenance = {"0xdead": {"trace_status": "TRACE_UNAVAILABLE"}}
    metrics = localization_metrics(targets, predictions, provenance_by_tx=provenance)
    assert metrics["evaluated"] == 0
    assert metrics["excluded_unavailable_traces"] == 1
    assert "INSUFFICIENT_TRACE_COVERAGE" in metrics.get("blocker", "")


def test_localization_metrics_enforces_80_percent_coverage():
    targets = [
        LocalizationTarget(txn_hash=f"0x0{i}", functions={("0x1", "f")})
        for i in range(10)
    ]
    # 7 ok, 3 TRACE_UNAVAILABLE -> 70% usable trace ratio (< 80%)
    predictions = {f"0x0{i}": [{"address": "0x1", "function": "f"}] for i in range(10)}
    provenance = {
        f"0x0{i}": {"trace_status": "ok" if i < 7 else "TRACE_UNAVAILABLE"}
        for i in range(10)
    }
    metrics = localization_metrics(targets, predictions, provenance_by_tx=provenance)
    assert metrics["evaluated"] == 7
    assert metrics["excluded_unavailable_traces"] == 3
    assert metrics["usable_trace_ratio"] == 0.70
    assert "INSUFFICIENT_TRACE_COVERAGE" in metrics["blocker"]


# --------------------------------------------------------------------------
# Selector resolution (the "0xc554f632 vs extractReward" bug)
# --------------------------------------------------------------------------

from benchmark.honest_eval.localization import (
    _fn_selector,
    _register_fn_names,
    _selector_to_name,
    _SELECTOR_TO_NAMES,
    _prediction_keys,
)


def test_fn_selector_known_value():
    """keccak('extractReward(uint256)')[:4] must equal 0xc554f632."""
    assert _fn_selector("extractReward(uint256)") == "0xc554f632"


def test_register_and_resolve_selector():
    """After registering 'extractReward', the selector resolves back."""
    _register_fn_names(["extractReward"])
    resolved = _selector_to_name("0xc554f632")
    assert resolved == "extractreward"


def test_selector_not_in_table_returns_none():
    assert _selector_to_name("0xdeadbeef") is None


def test_prediction_keys_resolves_hex_selector():
    """_prediction_keys must return the human name when function is a hex selector."""
    _register_fn_names(["extractReward"])
    target = LocalizationTarget(
        txn_hash="0xabc",
        functions={("0x6bbef6df8db12667ae88519090984e4f871e5feb", "extractreward")},
    )
    pred = {
        "address": "0x6BBeF6DF8db12667aE88519090984e4F871e5feb",
        "function": "0xc554f632",  # raw 4-byte selector from pipeline
    }
    fn_key, _ = _prediction_keys(pred)
    assert fn_key is not None
    assert fn_key in target.functions, (
        f"Expected {fn_key} in {target.functions} — selector not resolved"
    )


def test_rank_of_first_hit_with_hex_selector():
    """rank_of_first_hit must find a hit when prediction uses a hex selector."""
    _register_fn_names(["extractReward"])
    target = LocalizationTarget(
        txn_hash="0xabc",
        functions={("0x6bbef6df8db12667ae88519090984e4f871e5feb", "extractreward")},
    )
    predictions = [
        {"address": "0x1111", "function": "0xdeadbeef"},
        {"address": "0x6BBeF6DF8db12667aE88519090984e4F871e5feb", "function": "0xc554f632"},
    ]
    rank = rank_of_first_hit(target, predictions, match="function")
    assert rank == 2, f"Expected rank 2, got {rank}"
