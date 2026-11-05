"""Synthetic counterexamples: observations are not verified exploit evidence."""
from types import SimpleNamespace
from pathlib import Path
from contextlib import nullcontext
import networkx as nx
import pytest
from faultseeker.forensics.signal_extractor import SignalExtractor
from faultseeker.forensics.rule_classifier import classify
from faultseeker.forensics.result import compute_priority_breakdown
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer

A, B = ["0x" + c * 40 for c in "12"]

def signals(tmp_path, calls, **analysis):
    extractor = SignalExtractor({}, {"flatten_trace": calls, **analysis}, "synthetic-evidence")
    extractor._cast_cache_path = str(tmp_path / "missing.txt")
    return extractor.run()

@pytest.mark.parametrize("calls", [
    [{"function": "pause", "address": A, "call_type": "call"}],
    [{"function": "implementation", "address": A, "call_type": "delegatecall"}],
    [{"function": "0x12345678", "address": A, "call_type": "call"}, {"function": "transfer", "address": B}],
    [{"function": "transfer", "address": "0x" + c * 40, "call_type": "call"} for c in "123"],
])
def test_common_calls_do_not_prove_access_bypass(tmp_path, calls):
    observed = signals(tmp_path, calls)
    assert observed.access_control_bypass is False
    assert classify(observed)[0] == "UNCERTAIN"


def test_flash_principal_and_tail_transfer_are_not_profit(tmp_path):
    observed = signals(tmp_path, [{"function": "flashLoan", "value": str(100 * 10**18)}, {"function": "executeOperation"}, {"function": "repay", "value": str(100 * 10**18)}])
    assert observed.flash_loan_detected
    assert observed.flash_profit_eth is None
    assert observed.profit_extraction_eth is None
    assert observed.raw["profit_measurement_status"] == "unavailable"
    assert classify(observed)[0] == "UNCERTAIN"


def test_price_sequences_do_not_invent_numeric_delta(tmp_path):
    observed = signals(tmp_path, [{"function": fn} for fn in ["getReserves", "swap", "getReserves", "swap", "getReserves"]])
    assert observed.price_read_write_sequences == 2
    assert observed.price_delta_ratio is None
    assert observed.raw["price_delta_measurement_status"] == "unavailable"
    assert classify(observed)[0] == "UNCERTAIN"
    assert compute_priority_breakdown(observed.raw)["liquidity_drain"] == 0


def test_token_amount_is_not_native_profit(tmp_path):
    observed = signals(tmp_path, [], potential_attacker=[A], balance_change={A: {"USDC": 1000000}})
    assert observed.profit_extraction_eth is None


def test_cast_delegatecall_and_selectors_are_not_bypass_evidence(tmp_path):
    extractor = SignalExtractor({}, {}, "synthetic-cast")
    cache = tmp_path / "trace.txt"
    cache.write_text("Proxy::12345678() [delegatecall]\nToken::transfer()", encoding="utf-8")
    extractor._cast_cache_path = str(cache)
    observed = extractor.run()
    assert observed.hashed_fn_count > 0
    assert observed.access_control_bypass is False
    assert classify(observed)[0] == "UNCERTAIN"


def test_deposit_transfer_borrow_pattern_is_not_confirmed_inflation(tmp_path):
    observed = signals(tmp_path, [{"function": fn} for fn in ["deposit", "transfer", "borrow"]])
    assert classify(observed)[0] == "UNCERTAIN"


def test_rule_hint_is_not_seeded_as_confirmed_finding(monkeypatch):
    # Exercise the real analyzer run through initialization. Deliberately stop at
    # source retrieval: no model, source, RPC or historical correctness claimed.
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)
    info = SimpleNamespace(transaction_hash="synthetic", chain="eth", rule_verdict="EXPLOIT", rule_confidence=.85, vuln_type_hint="Access Control", signals={}, trace={}, repeated_patterns={}, function_calls_to_expand_loc={}, address_calls_with_created_contract=[], flatten_trace=[], function_call_loc_memo={}, balance_change={}, address_memo={}, potential_attacker=[], potential_victim=[])
    ranking = SimpleNamespace(repeated_patterns=[], address_calls_with_created_contract_in_params={}, functions_to_be_inspected={}, address_list=[])
    class StopAtSource(Exception): pass
    def stop(*args, **kwargs): raise StopAtSource()
    from faultseeker.function_analysis import function_analyzer as module
    monkeypatch.setattr(module, "ContractDownloader", stop)
    txn_seq = {"address_relation": nx.node_link_data(nx.DiGraph(), edges="edges"), "address_calls": {}, "created_address": []}
    with pytest.raises(StopAtSource):
        analyzer.run(info, txn_seq, {"transaction_hash": "synthetic"}, ranking)
    assert analyzer.cheatsheet == []


def test_model_prompt_distinguishes_hypotheses_from_findings():
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)
    analyzer.potentially_vulnerable_functions = {}
    analyzer.vulnerability_prompts = SimpleNamespace(update_potentially_vulnerable_function="Analyze. ")
    analyzer.understanding_result = "controlled"
    analyzer.current_task = {}
    analyzer.processing_result = {}
    analyzer.cheatsheet = []
    analyzer.signals_raw = {"privileged_calls_count": 1}
    analyzer.rule_verdict = "EXPLOIT"
    analyzer.vuln_type_hint = "Access Control"
    captured = []
    analyzer.organization_agent = SimpleNamespace(query=lambda prompt: captured.append(prompt) or {})
    analyzer._update_potentially_vulnerable_function()
    assert "confirmed to be vulnerable" not in captured[0]
    assert "unverified" in captured[0].lower()
    assert "privileged_calls_count" in captured[0]


def test_created_contract_in_initializer_is_review_not_proven_exploit(tmp_path):
    extractor = SignalExtractor({"created_address": [B]}, {"flatten_trace": [{"function": "initialize", "address": A, "params": B, "call_type": "call"}]}, "synthetic-initialize")
    extractor._cast_cache_path = str(tmp_path / "absent")
    observed = extractor.run()
    assert observed.created_contract_in_privileged_call
    assert observed.privileged_calls
    assert classify(observed)[0] == "UNCERTAIN"


def test_gross_value_and_delegate_observations_remain_available(tmp_path):
    observed = signals(tmp_path, [{"function": "pause", "address": A, "call_type": "delegatecall", "value": str(3 * 10**18)}])
    assert observed.raw["delegatecall_observed"] is True
    assert observed.raw["privileged_calls_count"] > 0
    assert observed.raw["access_control_review_required"] is True
    assert observed.raw["largest_call_value_eth"] == 3
    assert "Access Control" in observed.top_vuln_hints
