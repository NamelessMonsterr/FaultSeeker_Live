from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class ChainSemanticProfile:
    chain: str
    trace_methods: List[str]
    explorer_reliability: str
    common_failure_modes: List[str] = field(default_factory=list)
    heuristic_weights: Dict[str, float] = field(default_factory=dict)


PROFILES = {
    "eth": ChainSemanticProfile(
        chain="eth",
        trace_methods=["debug_traceTransaction", "trace_replayTransaction", "cast run"],
        explorer_reliability="high",
        common_failure_modes=["archive_rpc_required", "provider_rate_limit"],
        heuristic_weights={"source_code": 1.0, "state_delta": 1.0, "token_flow": 1.0},
    ),
    "bsc": ChainSemanticProfile(
        chain="bsc",
        trace_methods=["debug_traceTransaction", "cast run"],
        explorer_reliability="medium",
        common_failure_modes=["public_trace_unavailable", "high_contract_clone_rate"],
        heuristic_weights={"source_code": 0.8, "state_delta": 1.1, "token_flow": 1.2},
    ),
    "arbitrum": ChainSemanticProfile(
        chain="arbitrum",
        trace_methods=["debug_traceTransaction", "cast run"],
        explorer_reliability="medium",
        common_failure_modes=["l2_trace_shape_drift", "retryable_ticket_noise"],
        heuristic_weights={"source_code": 0.9, "state_delta": 1.0, "token_flow": 0.9},
    ),
    "base": ChainSemanticProfile(
        chain="base",
        trace_methods=["debug_traceTransaction", "cast run"],
        explorer_reliability="medium",
        common_failure_modes=["new_protocol_bias", "proxy_density"],
        heuristic_weights={"source_code": 0.9, "state_delta": 1.0, "token_flow": 1.0},
    ),
    "zksync": ChainSemanticProfile(
        chain="zksync",
        trace_methods=["debug_traceTransaction"],
        explorer_reliability="low",
        common_failure_modes=["nonstandard_explorer", "limited_trace_parity"],
        heuristic_weights={"source_code": 0.7, "state_delta": 1.2, "token_flow": 0.8},
    ),
}


def get_chain_profile(chain: str) -> ChainSemanticProfile:
    return PROFILES.get(str(chain or "").lower(), PROFILES["eth"])
