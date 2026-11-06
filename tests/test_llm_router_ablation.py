"""Verify the LLM-routing ablation and the CostTracker bridge are real.

Before this, `--disable-llm-routing` was a flag that nothing consulted, and
`record_llm_call` was never invoked from production code, so every reported
cost number was a constant rather than a measurement.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from faultseeker.research.ablation import AblationConfig
from faultseeker.research.cost_tracker import CostTracker


def _router_class():
    try:
        from faultseeker.core.llm_router import HybridLLMRouter
    except ModuleNotFoundError as exc:  # ollama / openai not installed
        pytest.skip("llm_router dependency missing: %s" % exc)
    return HybridLLMRouter


def _router(**kwargs):
    cls = _router_class()
    kwargs.setdefault("local_model", "llama3:8b")
    kwargs.setdefault("cloud_model", "gpt-4o-mini")
    return cls(**kwargs)


# ------------------------------------------------------------ routing ablation

def test_routing_enabled_sends_tier1_to_the_local_model():
    router = _router()
    assert router.ablation.is_full_system
    assert router.select_model(tier_override=1) == "llama3:8b"


def test_routing_disabled_forces_every_query_to_cloud():
    router = _router(ablation=AblationConfig.disabling("llm_routing"))
    assert router.select_model(tier_override=1) == "gpt-4o-mini"
    assert router.select_model(tier_override=2) == "gpt-4o-mini"
    assert router.select_model(tier_override=3) == "gpt-4o-mini"


def test_routing_ablation_changes_the_selected_model():
    full = _router().select_model(tier_override=1)
    ablated = _router(
        ablation=AblationConfig.disabling("llm_routing")
    ).select_model(tier_override=1)
    assert full != ablated


def test_disabling_another_component_leaves_routing_alone():
    router = _router(ablation=AblationConfig.disabling("tig"))
    assert router.select_model(tier_override=1) == "llama3:8b"


# --------------------------------------------------------- cost tracker bridge

def test_record_query_feeds_the_cost_tracker():
    tracker = CostTracker()
    router = _router(cost_tracker=tracker)
    router.record_query(
        model="gpt-4o-mini",
        tier=3,
        prompt_length=4000,
        response_length=400,
        duration_ms=1500,
        agent_role="VulnerabilityAnalyzer",
    )
    assert len(tracker.calls) == 1
    call = tracker.calls[0]
    assert call.model == "gpt-4o-mini"
    assert call.tier == "cloud"
    assert call.stage == "VulnerabilityAnalyzer"
    assert call.prompt_tokens == 1000  # 4000 chars / 4
    assert call.completion_tokens == 100
    assert call.latency_secs == 1.5
    assert call.cost_usd > 0


def test_local_calls_are_recorded_as_free_local_tier():
    tracker = CostTracker()
    router = _router(cost_tracker=tracker)
    router.record_query(model="llama3:8b", tier=1, prompt_length=8000, response_length=800)
    call = tracker.calls[0]
    assert call.tier == "local"
    assert call.cost_usd == 0.0


def test_stage_defaults_when_no_agent_role_given():
    tracker = CostTracker()
    router = _router(cost_tracker=tracker)
    router.record_query(model="gpt-4o-mini", tier=3, prompt_length=40, response_length=4)
    assert tracker.calls[0].stage == "llm_query"


def test_router_without_tracker_does_not_crash():
    router = _router()
    assert router.cost_tracker is None
    router.record_query(model="gpt-4o-mini", tier=3, prompt_length=40, response_length=4)
    assert router.cost_summary.total_queries == 1


def test_tracker_measures_a_real_cost_reduction():
    """A mixed local/cloud run must show savings against the all-cloud counterfactual."""
    tracker = CostTracker()
    router = _router(cost_tracker=tracker)
    for _ in range(8):
        router.record_query(model="llama3:8b", tier=1, prompt_length=4000, response_length=400)
    for _ in range(2):
        router.record_query(model="gpt-4o-mini", tier=3, prompt_length=4000, response_length=400)
    report = tracker.report()
    assert report["measured"] is True
    assert report["llm_calls"] == 10
    assert report["counterfactual_all_cloud_cost_usd"] > report["actual_cost_usd"]
    # Reduction is reported as a fraction in [0, 1], not a percentage.
    assert 0.0 < report["cost_reduction_vs_all_cloud"] < 1.0
    assert report["tier_distribution"]["local"]["share"] == 0.8


# ------------------------------------------------------- orchestrator handoff

def test_orchestrator_propagates_ablation_and_tracker_into_router():
    try:
        from faultseeker.forensics.orchestrator import ForensicsOrchestrator
    except ModuleNotFoundError as exc:
        pytest.skip("orchestrator dependency missing: %s" % exc)
    router = _router()
    tracker = CostTracker()
    config = AblationConfig.disabling("llm_routing")
    ForensicsOrchestrator(
        cache_dir="./data/cache/test_wiring",
        router=router,
        ablation=config,
        cost_tracker=tracker,
    )
    assert router.ablation is config
    assert router.cost_tracker is tracker
    assert router.select_model(tier_override=1) == "gpt-4o-mini"
