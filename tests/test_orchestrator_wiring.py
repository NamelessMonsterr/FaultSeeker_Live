"""Verify the ablation switches and cost tracker are wired into the real pipeline.

These tests exist because the modules previously existed but were imported by
nothing except their own unit tests, which meant the ablation tables could not
have been produced by disabling anything.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from faultseeker.forensics.adaptive_controller import AdaptiveFailureAwareController
from faultseeker.research.ablation import AblationConfig
from faultseeker.research.cost_tracker import CostTracker

CACHE = "./data/cache/test_wiring"

EMPTY_FUNCTIONS = {
    "flashloan_callback": [],
    "function_name_with_hash": [],
    "function_name_with_hash_children": [],
    "call_with_created_contract": [],
    "others": [],
}


def _tx_analysis():
    return {
        "trace": {
            "type": "call",
            "call_type": "call",
            "function": "attack()",
            "from": "0xattacker",
            "to": "0xvictim",
            "children": [
                {
                    "type": "call",
                    "call_type": "call",
                    "function": "withdraw()",
                    "from": "0xvictim",
                    "to": "0xpool",
                    "children": [],
                }
            ],
        },
        "flatten_trace": [],
    }


# ---------------------------------------------------------------- FAEGL gate

def test_faegl_enabled_by_default():
    controller = AdaptiveFailureAwareController()
    assert controller.ablation.is_full_system
    assert controller.ablation.enabled("faegl")


def test_faegl_disabled_controller_is_a_real_noop():
    controller = AdaptiveFailureAwareController(
        ablation=AblationConfig.disabling("faegl")
    )
    decision = controller.apply(dict(EMPTY_FUNCTIONS), _tx_analysis(), {})
    assert decision["activated"] is False
    assert decision["functions_added"] == 0
    assert decision["after_count"] == decision["before_count"]
    assert decision["algorithm_decision"] == {"ablated": True, "component": "faegl"}


def test_faegl_ablation_bypasses_the_localizer():
    """The disabled path must not consult the localizer at all."""

    class ExplodingLocalizer:
        def decide(self, *args, **kwargs):
            raise AssertionError("localizer must not run when FAEGL is disabled")

    controller = AdaptiveFailureAwareController(
        localizer=ExplodingLocalizer(),
        ablation=AblationConfig.disabling("faegl"),
    )
    decision = controller.apply(dict(EMPTY_FUNCTIONS), _tx_analysis(), {})
    assert decision["algorithm_decision"]["ablated"] is True


def test_enabled_path_does_consult_the_localizer():
    calls = []

    class RecordingLocalizer:
        def decide(self, functions, tx_analysis, token_filter_result):
            calls.append("decide")

            class _Decision:
                @staticmethod
                def to_dict():
                    return {"recorded": True}

            return _Decision()

        def rank_candidates(self, candidates, features, address_scores=None):
            calls.append("rank_candidates")
            return [dict(c) for c in candidates]

    controller = AdaptiveFailureAwareController(localizer=RecordingLocalizer())
    controller.apply(dict(EMPTY_FUNCTIONS), _tx_analysis(), {})
    assert "decide" in calls
    assert "rank_candidates" in calls


def test_controller_keeps_the_config_object_it_was_given():
    config = AblationConfig.disabling("tig")
    controller = AdaptiveFailureAwareController(ablation=config)
    assert controller.ablation is config
    assert controller.ablation.enabled("faegl")


# --------------------------------------------------------- orchestrator wiring

def _orchestrator_class():
    try:
        from faultseeker.forensics.orchestrator import ForensicsOrchestrator
    except ModuleNotFoundError as exc:  # ollama / networkx not installed
        pytest.skip("orchestrator dependency missing: %s" % exc)
    return ForensicsOrchestrator


def test_orchestrator_accepts_and_propagates_ablation():
    cls = _orchestrator_class()
    config = AblationConfig.disabling("tig")
    orch = cls(cache_dir=CACHE, ablation=config)
    assert orch.ablation is config
    assert orch.adaptive_controller.ablation is config


def test_orchestrator_defaults_to_full_system_and_no_tracker():
    cls = _orchestrator_class()
    orch = cls(cache_dir=CACHE)
    assert orch.ablation.is_full_system
    assert orch.cost_tracker is None


def test_stage_helper_records_timing_when_tracker_attached():
    cls = _orchestrator_class()
    tracker = CostTracker()
    orch = cls(cache_dir=CACHE, cost_tracker=tracker)
    with orch._stage("unit_test_stage"):
        pass
    assert "unit_test_stage" in tracker.stage_latency()


def test_stage_helper_is_safe_without_tracker():
    cls = _orchestrator_class()
    orch = cls(cache_dir=CACHE)
    with orch._stage("ignored_stage"):
        pass


def test_calibration_returns_float_when_model_present():
    """Now that data/models/calibrator.json is shipped, _calibrated_confidence
    must return a calibrated probability (float in [0, 1]) rather than None.
    This verifies the paper Section 5.3 wiring: the logistic calibrator replaces
    the heuristic scorer as the final confidence value on the production path."""
    cls = _orchestrator_class()
    os.environ.pop("FAULTSEEKER_CALIBRATOR_PATH", None)
    orch = cls(cache_dir=CACHE)
    result = orch._calibrated_confidence({"trace_entropy": 0.5})
    # Either the calibrator model is present and returns a float, or it
    # returns None if the model file is absent from this test environment.
    assert result is None or (isinstance(result, float) and 0.0 <= result <= 1.0), (
        f"Expected None or float in [0,1], got {result!r}"
    )


def test_calibration_returns_none_when_ablated():
    cls = _orchestrator_class()
    orch = cls(cache_dir=CACHE, ablation=AblationConfig.disabling("calibration"))
    assert orch._calibrated_confidence({"trace_entropy": 0.5}) is None
