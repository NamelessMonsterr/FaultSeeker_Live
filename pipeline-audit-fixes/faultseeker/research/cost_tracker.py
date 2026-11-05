"""Runtime and cost instrumentation for the tiered LLM routing pipeline.

The paper reports per-stage latency and an aggregate cost reduction from tiered
routing, but no measurement code existed. This module records real wall-clock
timings and real token counts so those numbers can be produced from evidence.

Usage::

    tracker = CostTracker()
    with tracker.stage("stage1_signal_extraction"):
        signals = extractor.run(tx)
    tracker.record_llm_call(
        stage="stage2_function_analysis", tier="local",
        model="qwen2.5-coder:7b", prompt_tokens=1800, completion_tokens=300,
    )
    report = tracker.report()
"""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# USD per 1M tokens. Local models are free at inference time; the electricity
# cost is not modelled and is reported as zero rather than estimated.
DEFAULT_PRICING: Dict[str, Dict[str, float]] = {
    "gpt-4o": {"prompt": 2.50, "completion": 10.00},
    "gpt-4o-mini": {"prompt": 0.15, "completion": 0.60},
    "gpt-4.1": {"prompt": 2.00, "completion": 8.00},
    "claude-3-5-sonnet": {"prompt": 3.00, "completion": 15.00},
    "deepseek-chat": {"prompt": 0.27, "completion": 1.10},
    "local": {"prompt": 0.0, "completion": 0.0},
}

LOCAL_TIERS = frozenset({"local", "ollama", "self_hosted"})


@dataclass
class LlmCall:
    stage: str
    tier: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_secs: float = 0.0
    cost_usd: float = 0.0


@dataclass
class StageTiming:
    stage: str
    elapsed_secs: float


@dataclass
class CostTracker:
    """Collects per-stage latency, token usage and USD cost for one run."""

    pricing: Dict[str, Dict[str, float]] = field(
        default_factory=lambda: dict(DEFAULT_PRICING)
    )
    calls: List[LlmCall] = field(default_factory=list)
    timings: List[StageTiming] = field(default_factory=list)
    transactions: int = 0
    prefiltered_benign: int = 0
    counterfactual_model: str = "gpt-4o"

    @contextmanager
    def stage(self, name: str):
        """Time a pipeline stage."""
        started = time.perf_counter()
        try:
            yield
        finally:
            self.timings.append(
                StageTiming(stage=name, elapsed_secs=time.perf_counter() - started)
            )

    def price_for(self, model: str, tier: str = "") -> Dict[str, float]:
        if str(tier).lower() in LOCAL_TIERS:
            return self.pricing["local"]
        return self.pricing.get(str(model).lower(), self.pricing["local"])

    def cost_of(
        self, model: str, prompt_tokens: int, completion_tokens: int, tier: str = ""
    ) -> float:
        price = self.price_for(model, tier)
        cost = (prompt_tokens / 1_000_000) * price.get("prompt", 0.0) + (
            completion_tokens / 1_000_000
        ) * price.get("completion", 0.0)
        return round(cost, 8)

    def record_llm_call(
        self,
        stage: str,
        tier: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_secs: float = 0.0,
    ) -> LlmCall:
        call = LlmCall(
            stage=stage,
            tier=str(tier).lower(),
            model=model,
            prompt_tokens=int(prompt_tokens),
            completion_tokens=int(completion_tokens),
            latency_secs=float(latency_secs),
            cost_usd=self.cost_of(model, prompt_tokens, completion_tokens, tier),
        )
        self.calls.append(call)
        return call

    def record_transaction(self, prefiltered: bool = False) -> None:
        self.transactions += 1
        if prefiltered:
            self.prefiltered_benign += 1

    def stage_latency(self) -> Dict[str, Dict[str, float]]:
        grouped: Dict[str, List[float]] = {}
        for timing in self.timings:
            grouped.setdefault(timing.stage, []).append(timing.elapsed_secs)
        return {
            stage: {
                "calls": len(values),
                "total_secs": round(sum(values), 4),
                "mean_secs": round(sum(values) / len(values), 4),
                "max_secs": round(max(values), 4),
            }
            for stage, values in grouped.items()
        }

    def tier_distribution(self) -> Dict[str, Dict[str, float]]:
        grouped: Dict[str, List[LlmCall]] = {}
        for call in self.calls:
            grouped.setdefault(call.tier, []).append(call)
        total = len(self.calls)
        return {
            tier: {
                "calls": len(items),
                "share": round(len(items) / total, 4) if total else 0.0,
                "cost_usd": round(sum(c.cost_usd for c in items), 6),
                "prompt_tokens": sum(c.prompt_tokens for c in items),
                "completion_tokens": sum(c.completion_tokens for c in items),
            }
            for tier, items in grouped.items()
        }

    def counterfactual_cost(self) -> float:
        """Cost if every recorded call had gone to the frontier cloud model."""
        total = 0.0
        for call in self.calls:
            total += self.cost_of(
                self.counterfactual_model,
                call.prompt_tokens,
                call.completion_tokens,
                tier="cloud",
            )
        return round(total, 6)

    def report(self) -> Dict[str, Any]:
        actual = round(sum(call.cost_usd for call in self.calls), 6)
        counterfactual = self.counterfactual_cost()
        reduction = (
            round(1 - (actual / counterfactual), 4) if counterfactual > 0 else 0.0
        )
        return {
            "measured": True,
            "transactions": self.transactions,
            "prefiltered_benign": self.prefiltered_benign,
            "prefilter_rate": round(self.prefiltered_benign / self.transactions, 4)
            if self.transactions
            else 0.0,
            "llm_calls": len(self.calls),
            "prompt_tokens": sum(c.prompt_tokens for c in self.calls),
            "completion_tokens": sum(c.completion_tokens for c in self.calls),
            "actual_cost_usd": actual,
            "counterfactual_all_cloud_cost_usd": counterfactual,
            "counterfactual_model": self.counterfactual_model,
            "cost_reduction_vs_all_cloud": reduction,
            "cost_per_transaction_usd": round(actual / self.transactions, 6)
            if self.transactions
            else 0.0,
            "stage_latency": self.stage_latency(),
            "tier_distribution": self.tier_distribution(),
        }

    def write_report(self, path: str) -> Dict[str, Any]:
        import os

        report = self.report()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        return report
