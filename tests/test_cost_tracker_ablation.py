"""Tests for runtime/cost instrumentation and real ablation switches."""

import pytest

from faultseeker.research.ablation import (
    COMPONENTS,
    AblationConfig,
    standard_ablation_suite,
)
from faultseeker.research.cost_tracker import CostTracker


# --------------------------------------------------------------------------
# CostTracker
# --------------------------------------------------------------------------


def test_local_tier_is_free():
    tracker = CostTracker()
    call = tracker.record_llm_call(
        stage="stage2",
        tier="local",
        model="qwen2.5-coder:7b",
        prompt_tokens=10_000,
        completion_tokens=2_000,
    )
    assert call.cost_usd == 0.0


def test_cloud_tier_cost_is_computed_from_pricing():
    tracker = CostTracker()
    call = tracker.record_llm_call(
        stage="stage3",
        tier="cloud",
        model="gpt-4o",
        prompt_tokens=1_000_000,
        completion_tokens=0,
    )
    assert call.cost_usd == pytest.approx(2.50, rel=1e-6)


def test_cost_reduction_is_measured_not_assumed():
    tracker = CostTracker()
    for _ in range(8):
        tracker.record_llm_call(
            stage="stage2", tier="local", model="local",
            prompt_tokens=1000, completion_tokens=100,
        )
    for _ in range(2):
        tracker.record_llm_call(
            stage="stage3", tier="cloud", model="gpt-4o",
            prompt_tokens=1000, completion_tokens=100,
        )
    report = tracker.report()
    assert report["measured"] is True
    assert report["llm_calls"] == 10
    assert report["actual_cost_usd"] < report["counterfactual_all_cloud_cost_usd"]
    assert 0.0 < report["cost_reduction_vs_all_cloud"] < 1.0


def test_all_cloud_run_reports_zero_reduction():
    tracker = CostTracker()
    tracker.record_llm_call(
        stage="stage3", tier="cloud", model="gpt-4o",
        prompt_tokens=5000, completion_tokens=500,
    )
    report = tracker.report()
    assert report["cost_reduction_vs_all_cloud"] == 0.0


def test_tier_distribution_shares_sum_to_one():
    tracker = CostTracker()
    for tier in ("local", "local", "cloud", "cloud"):
        tracker.record_llm_call(
            stage="s", tier=tier, model="gpt-4o",
            prompt_tokens=100, completion_tokens=10,
        )
    distribution = tracker.tier_distribution()
    assert distribution["local"]["share"] == 0.5
    assert distribution["cloud"]["share"] == 0.5
    assert sum(v["share"] for v in distribution.values()) == pytest.approx(1.0)


def test_stage_timer_records_latency():
    tracker = CostTracker()
    with tracker.stage("stage1_signal_extraction"):
        sum(range(1000))
    latency = tracker.stage_latency()
    assert "stage1_signal_extraction" in latency
    assert latency["stage1_signal_extraction"]["calls"] == 1
    assert latency["stage1_signal_extraction"]["total_secs"] >= 0.0


def test_stage_timer_records_even_on_exception():
    tracker = CostTracker()
    with pytest.raises(ValueError):
        with tracker.stage("failing_stage"):
            raise ValueError("boom")
    assert "failing_stage" in tracker.stage_latency()


def test_prefilter_rate_is_tracked():
    tracker = CostTracker()
    for index in range(10):
        tracker.record_transaction(prefiltered=index < 4)
    report = tracker.report()
    assert report["transactions"] == 10
    assert report["prefiltered_benign"] == 4
    assert report["prefilter_rate"] == 0.4


def test_empty_tracker_reports_zeros_not_estimates():
    report = CostTracker().report()
    assert report["llm_calls"] == 0
    assert report["actual_cost_usd"] == 0.0
    assert report["cost_reduction_vs_all_cloud"] == 0.0
    assert report["prefilter_rate"] == 0.0


# --------------------------------------------------------------------------
# AblationConfig
# --------------------------------------------------------------------------


def test_full_system_enables_everything():
    config = AblationConfig.full_system()
    assert config.is_full_system is True
    assert config.disabled_components == []
    for component in COMPONENTS:
        assert config.enabled(component) is True


def test_disabling_component_reports_disabled():
    config = AblationConfig.disabling("faegl")
    assert config.enabled("faegl") is False
    assert config.enabled("tig") is True
    assert config.is_full_system is False
    assert config.disabled_components == ["faegl"]


def test_variant_name_reflects_ablation():
    assert AblationConfig.full_system().variant_name() == "full_system"
    assert AblationConfig.disabling("calibration").variant_name() == "minus_calibration"


def test_unknown_component_rejected():
    with pytest.raises(ValueError):
        AblationConfig.disabling("not_a_component")
    with pytest.raises(ValueError):
        AblationConfig.full_system().enabled("nope")


def test_from_env_reads_flags():
    config = AblationConfig.from_env({"FAULTSEEKER_DISABLE_TIG": "true"})
    assert config.enabled("tig") is False
    assert config.enabled("faegl") is True


def test_from_env_ignores_unset_and_false_values():
    config = AblationConfig.from_env({"FAULTSEEKER_DISABLE_TIG": "0"})
    assert config.is_full_system is True


def test_standard_suite_covers_full_system_plus_each_component():
    suite = standard_ablation_suite()
    assert len(suite) == len(COMPONENTS) + 1
    assert suite[0].is_full_system is True
    disabled = {config.variant_name() for config in suite[1:]}
    assert disabled == {f"minus_{name}" for name in COMPONENTS}


def test_config_is_hashable_and_serializable():
    config = AblationConfig.disabling("faegl", "tig")
    assert isinstance(hash(config), int)
    payload = config.to_dict()
    assert payload["disable_faegl"] is True
    assert set(payload["disabled_components"]) == {"faegl", "tig"}
