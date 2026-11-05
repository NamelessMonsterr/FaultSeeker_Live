from faultseeker.research.chain_profiles import get_chain_profile
from faultseeker.research.mempool import MempoolRiskScorer
from faultseeker.research.remediation import suggest_remediations
from faultseeker.research.temporal import TemporalAttackCorrelator


def test_chain_profiles_are_chain_specific():
    eth = get_chain_profile("eth")
    zksync = get_chain_profile("zksync")

    assert eth.chain == "eth"
    assert zksync.chain == "zksync"
    assert eth.heuristic_weights != zksync.heuristic_weights


def test_temporal_correlator_groups_repeated_attacker_victim_pairs():
    results = [
        {"txn_hash": "0x1", "chain": "eth", "potential_attacker": ["0xa"], "potential_victim": ["0xb"], "priority_score": 0.4},
        {"txn_hash": "0x2", "chain": "eth", "potential_attacker": ["0xa"], "potential_victim": ["0xb"], "priority_score": 0.9},
        {"txn_hash": "0x3", "chain": "eth", "potential_attacker": ["0xc"], "potential_victim": ["0xd"], "priority_score": 0.1},
    ]

    campaigns = TemporalAttackCorrelator().correlate(results)

    assert len(campaigns) == 1
    assert campaigns[0]["transaction_count"] == 2
    assert campaigns[0]["max_priority_score"] == 0.9


def test_remediation_suggestions_follow_vulnerability_hint():
    suggestions = suggest_remediations("Reentrancy", {"reentrancy_detected": True})

    assert any("ReentrancyGuard" in item for item in suggestions)


def test_mempool_risk_scorer_flags_large_contract_creation():
    tx = {"hash": "0xabc", "to": "", "value": hex(11 * 10**18), "input": "0x" + "swap" * 600}
    alert = MempoolRiskScorer(alert_threshold=0.5).score_pending(tx, chain="base")

    assert alert.should_alert is True
    assert alert.chain == "base"
    assert alert.risk_score >= 0.5
