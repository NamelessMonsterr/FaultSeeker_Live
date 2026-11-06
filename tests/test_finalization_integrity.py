"""Synthetic findings; retain/rank policy, not historical vulnerability evidence."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
from faultseeker.core.confidence_scorer import ConfidenceScorer

A, B = ["0x" + digit * 40 for digit in "12"]
ROOT, CHILD = "root_fn_" + A, "deep_fn_" + B

def analyzed():
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.potentially_vulnerable_functions = {
        ROOT: {"depth": 1, "confidence_score": [.95], "evidence": ["controlled evidence"]},
        CHILD: {"depth": 9, "confidence_score": [.1], "evidence": ["controlled evidence"]}}
    item.ranked_result = [ROOT, CHILD]
    return item


def test_finalization_retains_both_shallow_and_deep_findings_and_uses_rank():
    item = analyzed()
    original = deepcopy(item.potentially_vulnerable_functions)
    result = item._finalize_potentially_vulnerable_functions()
    assert [(row["function"], row["address"], row["depth"]) for row in result] == [("root_fn", A, 1), ("deep_fn", B, 9)]
    result[0]["evidence"].append("modified copy")
    assert item.potentially_vulnerable_functions == original


def test_model_ranking_does_not_drop_omitted_findings():
    item = analyzed()
    item.ranked_result = [CHILD, CHILD]
    result = item._finalize_potentially_vulnerable_functions()
    assert [row["function"] for row in result] == ["deep_fn", "root_fn"]


def test_depth_is_context_not_a_confidence_boost():
    scorer = ConfidenceScorer()
    base = {"function": "same", "address": A, "evidence": ["controlled"], "confidence_score": [.5]}
    shallow = scorer.score_function({**base, "depth": 1}, {})
    deep = scorer.score_function({**base, "depth": 100}, {})
    assert shallow.overall == deep.overall


@pytest.mark.parametrize("model", ["gpt-4o-mini", "llama3:8b"])
def test_ranking_supports_json_object_mode_without_losing_targets(model):
    from faultseeker.prompts.local_model_prompts import get_vuln_prompts
    item = analyzed()
    item.vulnerability_prompts = get_vuln_prompts(model)
    item.understanding_result = "controlled"
    item.agent = SimpleNamespace(query=lambda prompt: {"ranked_functions": [CHILD, ROOT]})
    item._rank_potentially_vulnerable_functions()
    assert item.ranked_result == [CHILD, ROOT]


def test_unknown_rank_target_is_not_accepted():
    item = analyzed()
    from faultseeker.prompts.function_analysis.vulnerability_analysis_prompts import VulnerabilityAnalysisPrompts
    item.vulnerability_prompts = VulnerabilityAnalysisPrompts()
    item.understanding_result = "controlled"
    item.agent = SimpleNamespace(query=lambda prompt: ["unknown_0xdead"])
    with pytest.raises(ValueError, match="ranking"):
        item._rank_potentially_vulnerable_functions()


@pytest.mark.parametrize('unavailable', [False, True])
def test_real_stage3_keeps_all_findings_and_ranks_by_evidence_confidence(monkeypatch, tmp_path, unavailable):
    from faultseeker.core import pipeline as module
    item = analyzed()
    configuration = SimpleNamespace(output_dir=str(tmp_path), calibration_model_path=str(tmp_path / "missing.json"), human_in_loop=False, track_cost=False)
    pipeline = module.FaultSeekerPipeline(configuration)
    monkeypatch.setattr(pipeline, "_initialize_agents", lambda: None)
    forensics = SimpleNamespace(transaction_hash="synthetic-finalization", chain="eth", trace={}, repeated_patterns={}, function_call_loc_memo={}, balance_change={}, potential_attacker=[], potential_victim=[], signals={}, rule_confidence=0, duration=0, get_function_count=lambda: 2)
    pipeline.forensics_orchestrator = SimpleNamespace(run=lambda *a: (forensics, {}, {}), txn_sequencer=SimpleNamespace(save_visualization=lambda *a: None))
    pipeline.function_ranker = SimpleNamespace(rank=lambda *a: SimpleNamespace(address_list=[]))
    pipeline.function_analyzer = SimpleNamespace(contract_info={}, run=lambda *a: {
        "finalized_vulnerable_functions": item._finalize_potentially_vulnerable_functions(),
        "ranked_result": [ROOT, CHILD], 'retrieval_unavailable_count': int(unavailable),
        'retrieval_diagnostics': [{'status': 'unavailable', 'reason': 'unobserved_target'}] if unavailable else [],
        'rejected_finding_observations': [{'status': 'unresolved' if unavailable else 'recovered', 'reason': 'unobserved_target'}]})
    report = pipeline.analyze_transaction(txn_hash="synthetic-finalization", chain="eth")
    assert [row["function"] for row in report["scored_functions"]] == ["root_fn", "deep_fn"]
    assert len(report["evidence_cards"]) == 2
    assert [row["depth"] for row in report["scored_functions"]] == [1, 9]
    assert report['analysis_integrity']['rejected_finding_observations'][0]['status'] == ('unresolved' if unavailable else 'recovered')
    if unavailable:
        assert report['analysis_status'] == 'partial'
        assert report['classification']['rule_verdict'] == 'INCONCLUSIVE'
        assert report['analysis_integrity']['retrieval_incomplete'] is True
        assert report['sections']['scoring'] == 'not_validated'
