"""Actual entrypoint and Stage-1 orchestration with controlled acquisition."""
import importlib
import json

import pytest


def test_deterministic_entrypoint_never_constructs_model_clients(monkeypatch, tmp_path):
    module = importlib.import_module('faultseeker.forensics.orchestrator')
    main = importlib.import_module('faultseeker.main')
    def forbidden(*args, **kwargs):
        pytest.fail('deterministic mode constructed model-dependent machinery')
    monkeypatch.setattr(module, 'build_agent', forbidden)
    monkeypatch.setattr(module, 'AddressClassifier', forbidden)
    monkeypatch.setattr('faultseeker.forensics.trace_analyzer.build_agent', forbidden)
    monkeypatch.setattr(main, 'interactive_model_selection', forbidden)
    monkeypatch.setattr(main, 'FaultSeekerPipeline', forbidden)
    tx = '0x' + 'a' * 64
    sequence = {'transaction_hash': tx, 'chain': 'eth',
                'trace': {'type': 'call', 'call_type': 'call', 'address': '0x' + 'b' * 40,
                          'function': '0x12345678', 'params': '', 'children': []},
                'address_relation': {}, 'created_address': [],
                'trace_coverage': {'complete': False}}
    monkeypatch.setattr(module.TransactionSequencer, 'run', lambda *a: sequence)
    monkeypatch.setattr(module.TransactionInfoCollector, 'run',
                        lambda *a: {'transaction_hash': tx, '_source': 'controlled_test'})
    # Synthetic acquisition data passes through real TraceAnalyzer and signal
    # extraction. This is offline integration, not verified on-chain provenance.
    output = tmp_path / 'result.json'
    result = main.main(txn_hash=tx, chain='eth', no_llm=True,
                       cache_dir=str(tmp_path / 'cache'), output_path=str(output))
    assert json.loads(output.read_text()) == result
    assert result['analysis_mode'] == 'no-llm'
    assert result['analysis_status'] == 'stage1_complete'
    assert result['sections']['function_analysis'] == 'skipped'
    assert result['sections']['address_classification'] == 'skipped'
    assert result['sections']['scoring'] == 'skipped'
    assert result['scored_functions'] == result['evidence_cards'] == []
    assert result['classification']['rule_verdict'] == 'INCONCLUSIVE'
    assert 'deterministic_rule_observation' in result


def test_no_llm_acquisition_failure_is_not_completed(monkeypatch, tmp_path):
    module = importlib.import_module('faultseeker.forensics.orchestrator')
    main = importlib.import_module('faultseeker.main')
    monkeypatch.setattr(module.TransactionSequencer, 'run', lambda *a: None)
    monkeypatch.setattr(module.TransactionInfoCollector, 'run', lambda *a: {})
    output = tmp_path / 'result.json'
    with pytest.raises(RuntimeError, match='Stage 1'):
        main.main(txn_hash='0x' + 'a' * 64, chain='eth', no_llm=True,
                  cache_dir=str(tmp_path / 'cache'), output_path=str(output))
    assert not output.exists()
