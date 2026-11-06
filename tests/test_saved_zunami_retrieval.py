"""Saved real trace regression; no fresh RPC, ABI or completeness verification."""
import json
from pathlib import Path
from types import SimpleNamespace

from faultseeker.forensics.trace_analyzer import TraceAnalyzer
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
from faultseeker.prompts.function_analysis.worker_prompts import WorkerPrompts


def saved_analyzer():
    fixture = json.loads((Path(__file__).parent/'fixtures/zunami_retrieval_trace.json').read_text())
    provenance = fixture['provenance']
    assert provenance['transaction_hash'] == '0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb'
    assert provenance['completeness_proven'] is False
    assert len(provenance['source_sha256']) == 64
    sequence = {'transaction_hash': provenance['transaction_hash'], 'chain': 'eth',
                'trace': fixture['trace'], 'address_relation': {}, 'created_address': []}
    analysis = TraceAnalyzer(sequence, {}, no_llm=True).run()
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.trace = [analysis['trace']]
    item.tx_analysis = analysis
    item.function_call_info_summary = {}
    item.function_prompts = WorkerPrompts()
    return item


def test_all_saved_memo_paths_bind_to_their_actual_address_and_function():
    item = saved_analyzer()
    paths = 0
    memo = item.tx_analysis['function_call_loc_memo']
    assert len(memo) == 243
    for key, calls in memo.items():
        function, address = key.rsplit('::', 1)
        for call in calls:
            node = item._resolve_trace_node(call['depth'], function, address)
            assert node['function'].lower() == function
            assert node['address'].lower() == address
            paths += 1
        result = item._retrieve_function_calls({'function': function, 'address': address})
        assert len(result) == len(calls)
        item._retrieve_children_calls(function, address)
    assert paths == 785


def test_corrupted_saved_target_path_is_explicitly_unavailable_not_other_call():
    item = saved_analyzer()
    function = '0xd341ea79'
    address = '0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c'
    # Controlled corruption of a copy, not a changed expected ground truth.
    item.tx_analysis['function_call_loc_memo'][function+'::'+address][0]['depth'] = [0]
    item.generation_agent = SimpleNamespace(query=lambda *args, **kwargs:
        {'function_call': [[address, function]]})
    result = item._retrieve_additional_info('controlled corrupt memo request')
    assert not result.get('function_call')
    diagnostic = result['retrieval_status'][0]
    assert diagnostic['status'] == 'unavailable'
    assert diagnostic['reason'] == 'trace_identity_mismatch'
    assert diagnostic['path'] == [0]
