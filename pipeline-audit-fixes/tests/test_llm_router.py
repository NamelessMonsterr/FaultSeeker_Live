"""
tests/test_llm_router.py
Unit tests for HybridLLMRouter (Gap 1+6).
Covers: tier-based model selection, cost accumulation, savings calculation.
"""

import pytest
from faultseeker.core.llm_router import (
    HybridLLMRouter,
    AGENT_TIER_MAP,
    COST_RATES,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def router():
    return HybridLLMRouter(
        local_model='llama3:8b',
        cloud_model='gpt-4o-mini',
        routing_strategy='hybrid',
        track_cost=True,
    )


@pytest.fixture
def cloud_only_router():
    return HybridLLMRouter(
        local_model='llama3:8b',
        cloud_model='gpt-4o-mini',
        routing_strategy='cloud-only',
        track_cost=True,
    )


# ── select_model() ─────────────────────────────────────────────────────────────

class TestSelectModel:

    def test_tier1_agent_returns_local(self, router):
        """AddressClassifier is Tier 1 — should get local model."""
        model = router.select_model(agent_role='AddressClassifier')
        assert model == 'llama3:8b'

    def test_children_filtering_returns_local(self, router):
        """children_call_filtering is Tier 1."""
        model = router.select_model(agent_role='children_call_filtering')
        assert model == 'llama3:8b'

    def test_tier3_agent_returns_cloud(self, router):
        """reasoning_agent is Tier 3 — should get cloud model."""
        model = router.select_model(agent_role='reasoning_agent')
        assert model == 'gpt-4o-mini'

    def test_tier3_processing_returns_cloud(self, router):
        """processing_agent is Tier 3."""
        model = router.select_model(agent_role='processing_agent')
        assert model == 'gpt-4o-mini'

    def test_cloud_only_strategy_always_returns_cloud(self, cloud_only_router):
        """cloud-only strategy ignores tier and always returns cloud model."""
        for role in AGENT_TIER_MAP:
            model = cloud_only_router.select_model(agent_role=role)
            assert model == 'gpt-4o-mini', f"Expected cloud for {role}, got {model}"

    def test_tier_override_forces_local(self, router):
        """tier_override=1 should return local even for high-tier roles."""
        model = router.select_model(agent_role='reasoning_agent', tier_override=1)
        assert model == 'llama3:8b'

    def test_tier_override_forces_cloud(self, router):
        """tier_override=3 should return cloud even for low-tier roles."""
        model = router.select_model(agent_role='AddressClassifier', tier_override=3)
        assert model == 'gpt-4o-mini'

    def test_unknown_role_returns_valid_model(self, router):
        """Unknown roles should fall back to heuristic and return a valid model."""
        model = router.select_model(agent_role='unknown_agent', prompt_text='analyze this vulnerability')
        assert model in ('llama3:8b', 'gpt-4o-mini')


# ── get_tier() ────────────────────────────────────────────────────────────────

class TestGetTier:

    def test_known_roles_return_correct_tier(self, router):
        assert router.get_tier(agent_role='AddressClassifier') == 1
        assert router.get_tier(agent_role='generation_agent') == 2
        assert router.get_tier(agent_role='reasoning_agent') == 3

    def test_heuristic_complex_prompt_is_tier3(self, router):
        prompt = "analyze this reentrancy vulnerability in the cross-contract attack vector"
        tier = router.get_tier(prompt_text=prompt)
        assert tier == 3

    def test_heuristic_simple_prompt_is_tier1(self, router):
        prompt = "classify this address and label it"
        tier = router.get_tier(prompt_text=prompt)
        assert tier == 1


# ── record_query() and cost accumulation ──────────────────────────────────────

class TestCostTracking:

    def test_local_query_costs_zero(self, router):
        router.record_query(model='llama3:8b', tier=1, prompt_length=400, response_length=200)
        summary = router.get_cost_summary()
        assert summary['total_cost_usd'] == 0.0

    def test_cloud_query_costs_nonzero(self, router):
        router.record_query(model='gpt-4o-mini', tier=3, prompt_length=4000, response_length=1000)
        summary = router.get_cost_summary()
        assert summary['total_cost_usd'] > 0.0

    def test_query_count_increments(self, router):
        router.record_query(model='llama3:8b', tier=1, prompt_length=100, response_length=50)
        router.record_query(model='gpt-4o-mini', tier=3, prompt_length=200, response_length=100)
        summary = router.get_cost_summary()
        assert summary['total_queries'] == 2

    def test_local_and_cloud_counts_split(self, router):
        router.record_query(model='llama3:8b', tier=1, prompt_length=100, response_length=50)
        router.record_query(model='llama3:8b', tier=1, prompt_length=100, response_length=50)
        router.record_query(model='gpt-4o-mini', tier=3, prompt_length=200, response_length=100)
        summary = router.get_cost_summary()
        assert summary['local_queries'] == 2
        assert summary['cloud_queries'] == 1

    def test_savings_with_local_queries(self, router):
        """Local queries should show positive savings vs cloud-only baseline."""
        router.record_query(model='llama3:8b', tier=1, prompt_length=4000, response_length=1000)
        summary = router.get_cost_summary()
        assert summary['savings_usd'] >= 0.0
        assert summary['estimated_cloud_only_cost'] > 0.0

    def test_savings_percent_in_valid_range(self, router):
        router.record_query(model='llama3:8b', tier=1, prompt_length=4000, response_length=1000)
        router.record_query(model='gpt-4o-mini', tier=3, prompt_length=2000, response_length=500)
        summary = router.get_cost_summary()
        assert 0.0 <= summary['savings_percent'] <= 100.0

    def test_no_tracking_skips_records(self):
        r = HybridLLMRouter(track_cost=False)
        r.record_query(model='gpt-4o-mini', tier=3, prompt_length=4000, response_length=1000)
        # Should not accumulate
        assert r.cost_summary.total_queries == 0


# ── _is_local_model() ─────────────────────────────────────────────────────────

class TestIsLocalModel:

    def test_ollama_models_are_local(self, router):
        for model in ('llama3:8b', 'mistral:7b', 'codellama:13b', 'phi3'):
            assert router._is_local_model(model), f"{model} should be local"

    def test_gpt_models_are_cloud(self, router):
        for model in ('gpt-4o', 'gpt-4o-mini', 'gpt-4.1', 'o3-mini'):
            assert not router._is_local_model(model), f"{model} should be cloud"
