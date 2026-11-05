from faultseeker.forensics.interaction_graph import TransactionInteractionGraph
from faultseeker.research.adversarial import AdversarialRobustnessEvaluator
from faultseeker.research.calibration import LogisticConfidenceCalibrator
from faultseeker.research.failure_aware_localization import FailureAwareExploitGraphLocalizer
from faultseeker.research.statistics import (
    bootstrap_ci,
    mcnemar_test,
    paired_t_test,
    wilcoxon_signed_rank,
)


def test_logistic_calibrator_trains_and_reports_calibration_metrics():
    rows = [
        {"pattern_match": 0.1, "code_evidence": 0.2, "txn_consistency": 0.1, "llm_confidence": 0.2},
        {"pattern_match": 0.2, "code_evidence": 0.2, "txn_consistency": 0.3, "llm_confidence": 0.4},
        {"pattern_match": 0.8, "code_evidence": 0.7, "txn_consistency": 0.9, "llm_confidence": 0.8},
        {"pattern_match": 0.9, "code_evidence": 0.8, "txn_consistency": 0.7, "llm_confidence": 0.9},
    ]
    labels = [0, 0, 1, 1]

    model = LogisticConfidenceCalibrator().fit(rows, labels, epochs=120)
    low = model.predict_proba(rows[0])
    high = model.predict_proba(rows[-1])
    metrics = model.evaluate(rows, labels, bins=4)

    assert 0.0 <= low <= 1.0
    assert 0.0 <= high <= 1.0
    assert high > low
    assert 0.0 <= metrics.brier_score <= 1.0
    assert 0.0 <= metrics.expected_calibration_error <= 1.0


def test_transaction_interaction_graph_extracts_motifs_and_metrics():
    tx_analysis = {
        "trace": {
            "address": "0xA",
            "function": "entry",
            "children": [
                {
                    "address": "0xB",
                    "function": "delegate",
                    "call_type": "delegatecall",
                    "children": [{"address": "0xA", "function": "callback", "call_type": "call", "children": []}],
                }
            ],
        },
        "storage_events": [{"address": "0xA", "slot": "0x01", "depth": 1}],
    }
    txn_info = {"token_transfer": {"edges": [{"source": "0xA", "target": "0xB", "label": "TOKEN (10)"}]}}

    metrics = TransactionInteractionGraph.from_analysis({}, tx_analysis, txn_info).metrics()

    assert metrics["node_count"] >= 3
    assert metrics["delegatecall_edges"] == 1
    assert metrics["storage_slot_edges"] == 1
    assert "proxy_delegatecall" in metrics["motifs"]
    assert metrics["anomaly_score"] > 0


def test_failure_aware_exploit_graph_localizer_selects_modes_and_ranks_candidates():
    localizer = FailureAwareExploitGraphLocalizer()
    tx_analysis = {
        "trace": {
            "type": "call",
            "call_type": "call",
            "address": "0xVictim",
            "function": "withdraw",
            "children": [
                {
                    "type": "delegatecall",
                    "call_type": "delegatecall",
                    "address": "0xProxy",
                    "function": "fallback",
                    "depth": 1,
                    "children": [
                        {
                            "type": "call",
                            "call_type": "call",
                            "address": "0xToken",
                            "function": "transfer",
                            "depth": 2,
                            "children": [],
                        }
                    ],
                }
            ],
        },
        "storage_events": [{"address": "0xVictim", "slot": "0x01", "depth": 1}],
        "token_transfer": {"edges": [{"source": "0xVictim", "target": "0xAttacker"}]},
    }
    graph_metrics = {"anomaly_score": 0.7, "cycle_count": 1}

    decision = localizer.decide(
        {"others": []},
        tx_analysis,
        {"address_to_be_inspected": {"0xproxy": {}}},
        graph_metrics,
    )
    ranked = localizer.rank_candidates(
        [
            {"address": "0xVictim", "call_type": "call", "depth": 0},
            {"address": "0xProxy", "call_type": "delegatecall", "depth": 1},
        ],
        decision.features,
        {"0xproxy": 2},
    )

    assert decision.activated is True
    assert decision.algorithm == "FAEGL"
    assert "graph_expansion" in decision.selected_modes
    assert "proxy_unwrapping" in decision.selected_modes
    assert decision.features["state_delta"] > 0
    assert ranked[0]["address"] == "0xProxy"
    assert ranked[0]["_faegl_score"] > ranked[1]["_faegl_score"]


def test_adversarial_evaluator_generates_attack_variants_and_degradation_report():
    evaluator = AdversarialRobustnessEvaluator()
    tx_analysis = {"trace": {"function": "withdraw", "call_type": "call", "children": []}}

    def analyzer(data):
        function_name = data["trace"].get("function", "")
        return {"priority_score": 0.8 if function_name == "withdraw" else 0.4}

    report = evaluator.evaluate(tx_analysis, analyzer)

    assert report["baseline_score"] == 0.8
    assert "misleading_function_names" in report["attacks"]
    assert report["attacks"]["misleading_function_names"]["degraded"] is True


def test_statistical_helpers_return_reproducible_values():
    values = [0.7, 0.8, 0.9, 0.85]
    low, high = bootstrap_ci(values, samples=100, seed=7)
    t = paired_t_test([0.9, 0.8, 0.7], [0.7, 0.7, 0.6])
    w = wilcoxon_signed_rank([0.9, 0.8, 0.7], [0.7, 0.7, 0.6])
    m = mcnemar_test([True, True, False, False], [True, False, True, False])

    assert low <= high
    assert t["n"] == 3
    assert w["n"] == 3
    assert m["b01"] == 1
    assert m["b10"] == 1
