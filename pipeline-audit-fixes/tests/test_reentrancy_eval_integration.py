import pytest

from benchmark.run_eval import (
    normalize_signals,
    build_dataset_row,
    _compute_reentrancy_metrics,
)
from faultseeker.forensics.result import (
    ForensicsResult,
    extract_reentrancy_analysis,
    compute_priority_breakdown,
    compute_priority_score,
)


def _sample_reentrancy(
    score=0.675,
    detected=True,
    tier="POSSIBLE_REENTRANCY",
    fallback=True,
    storage=False,
    cross_fn=True,
    before_return=True,
    state_slot=False,
):
    return {
        "score": score,
        "detected": detected,
        "tier": tier,
        "signals": {
            "same_function_reentry": False,
            "cross_function_reentry": cross_fn,
            "reentry_before_return": before_return,
            "slot_rewrite": False,
            "write_after_call": False,
            "state_slot_reentry": state_slot,
        },
        "context": {
            "fallback_mode": fallback,
            "storage_trace_available": storage,
        },
    }


def test_extract_reentrancy_analysis_supports_legacy_flat_fields():
    raw = {
        "reentrancy_score": 0.2,
        "reentrancy_detection_threshold": 0.65,
        "reentrancy_confidence_tier": "NOT_REENTRANCY",
        "reentrancy_signals": {
            "cross_function_reentry": True,
            "reentry_before_return": True,
        },
        "reentrancy_context": {
            "fallback_mode": True,
            "storage_trace_available": False,
        },
    }

    reentrancy = extract_reentrancy_analysis(raw)

    assert reentrancy["score"] == 0.2
    assert reentrancy["detected"] is False
    assert reentrancy["tier"] == "NOT_REENTRANCY"
    assert reentrancy["signals"]["cross_function_reentry"] is True
    assert reentrancy["signals"]["reentry_before_return"] is True
    assert reentrancy["context"]["fallback_mode"] is True
    assert normalize_signals(raw)["reentrancy_detected"] is False


def test_build_dataset_row_flattens_only_compact_reentrancy_fields():
    priority = {
        "total": 0.8754,
        "exploitability": 0.75,
        "reentrancy": 0.459,
        "flashloan": 0.0,
        "price_manipulation": 0.0,
        "liquidity_drain": 0.081,
        "reentrancy_source": "fallback",
    }
    result = {
        "txn_hash": "0xabc",
        "chain": "eth",
        "vuln_type": "Reentrancy",
        "difficulty": "Complex",
        "verdict": "EXPLOIT",
        "confidence": 0.75,
        "rule": "reentrancy_pattern",
        "predicted_type": "Reentrancy",
        "priority_score": priority["total"],
        "priority": priority,
        "reentrancy": _sample_reentrancy(),
    }

    row = build_dataset_row(result)

    assert row["reentrancy_score"] == 0.675
    assert row["reentrancy_detected"] is True
    assert row["reentrancy_tier"] == "POSSIBLE_REENTRANCY"
    assert row["reentrancy_fallback"] is True
    assert row["reentrancy_source"] == "fallback"
    assert row["priority_reentrancy"] == 0.459
    assert row["priority_flashloan"] == 0.0
    assert row["priority_price_manipulation"] == 0.0
    assert row["priority_liquidity_drain"] == 0.081
    assert row["reentry_cross_fn"] is True
    assert row["reentry_before_return"] is True
    assert row["reentry_state_slot"] is False
    assert "reentrancy" not in row


def test_priority_total_uses_probabilistic_union():
    signals = {
        "flash_loan_detected": True,
        "profit_extraction_eth": 2.0,
        "large_transfer_to_eoa": True,
        "reentrancy": _sample_reentrancy(score=0.675, fallback=True, storage=False),
    }

    priority = compute_priority_breakdown(signals, exploitability_score=0.75)

    assert priority["exploitability"] == 0.75
    assert priority["reentrancy"] == pytest.approx(0.459, rel=1e-4)
    assert priority["flashloan"] == 0.6
    assert priority["liquidity_drain"] == 0.35
    assert priority["total"] == pytest.approx(0.9648, rel=1e-4)
    assert 0.0 <= priority["total"] <= 1.0


def test_reentrancy_metrics_use_tier_weighting_and_trace_rates():
    results = [
        {
            "txn_hash": "0x1",
            "chain": "eth",
            "dasp": "Reentrancy",
            "swc": "",
            "signals": {"reentrancy": _sample_reentrancy(score=0.675, tier="POSSIBLE_REENTRANCY", fallback=True, storage=False)},
        },
        {
            "txn_hash": "0x2",
            "chain": "eth",
            "dasp": "Reentrancy",
            "swc": "",
            "signals": {"reentrancy": _sample_reentrancy(score=0.9, tier="CONFIRMED_REENTRANCY", fallback=False, storage=True, state_slot=True)},
        },
        {
            "txn_hash": "0x3",
            "chain": "eth",
            "dasp": "",
            "swc": "",
            "signals": {"reentrancy": _sample_reentrancy(score=0.75, tier="HIGH_RISK_REENTRANCY", fallback=True, storage=False)},
        },
    ]

    metrics = _compute_reentrancy_metrics(results)

    assert metrics["support"] == 2
    assert metrics["weighted_precision"] == pytest.approx(1.5 / 2.3, rel=1e-3)
    assert metrics["weighted_recall"] == pytest.approx(0.75, rel=1e-3)
    assert metrics["detected_recall"] == 1.0
    assert metrics["fallback_detection_rate"] == 0.5
    assert metrics["storage_trace_detection_rate"] == 0.5
    assert metrics["avg_score"] == pytest.approx(0.7875, rel=1e-4)


def test_forensics_result_serialization_exposes_grouped_reentrancy_and_priority():
    signals = {
        "flash_loan_detected": False,
        "reentrancy": _sample_reentrancy(),
    }
    result = ForensicsResult(
        transaction_hash="0x" + "1" * 64,
        chain="eth",
        rule_verdict="EXPLOIT",
        rule_confidence=0.75,
        matched_rule="reentrancy_pattern",
        vuln_type_hint="Reentrancy",
        signals=signals,
    )

    data = result.to_dict()
    classification = data["classification"]

    assert classification["reentrancy"]["tier"] == "POSSIBLE_REENTRANCY"
    assert classification["reentrancy"]["signals"]["cross_function_reentry"] is True
    assert classification["priority"]["reentrancy_source"] == "fallback"
    assert classification["priority_score"] == compute_priority_score(signals, exploitability_score=0.75)

    loaded = ForensicsResult.from_json_dict(data)
    assert loaded.rule_verdict == "EXPLOIT"
    assert loaded.rule_confidence == 0.75
    assert loaded.signals["reentrancy"]["detected"] is True


def test_priority_breakdown_discounts_fallback_reentrancy():
    fallback_signals = {
        "reentrancy": _sample_reentrancy(score=0.8, fallback=True, storage=False),
    }
    storage_signals = {
        "reentrancy": _sample_reentrancy(score=0.8, fallback=False, storage=True),
    }

    fallback_priority = compute_priority_breakdown(fallback_signals)
    storage_priority = compute_priority_breakdown(storage_signals)

    assert fallback_priority["reentrancy_source"] == "fallback"
    assert storage_priority["reentrancy_source"] == "storage"
    assert fallback_priority["reentrancy"] == pytest.approx(0.544, rel=1e-4)
    assert storage_priority["reentrancy"] == pytest.approx(0.64, rel=1e-4)
    assert fallback_priority["total"] < storage_priority["total"]
    assert 0.0 <= fallback_priority["total"] <= 1.0
    assert 0.0 <= storage_priority["total"] <= 1.0
