"""Synthetic translation-boundary checks against the actual trace analyzer."""
from types import SimpleNamespace
import pytest
from faultseeker.forensics.trace_analyzer import TraceAnalyzer
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
from faultseeker.prompts.function_analysis.worker_prompts import WorkerPrompts

A, B = ['0x' + c * 40 for c in '12']
FUNCTION, CHILD = '0x12345678', '0x87654321'


@pytest.mark.parametrize('children_spec', [[A, FUNCTION], (A, FUNCTION),
                                   {'address': A, 'function': FUNCTION}])
def test_prompt_documented_children_request_reaches_real_trace(children_spec):
    child = {'type': 'call', 'call_type': 'call', 'address': B,
             'function': CHILD, 'params': '0xabcdef', 'children': []}
    root = {'type': 'call', 'call_type': 'call', 'address': A,
            'function': FUNCTION, 'params': '0x', 'children': [child]}
    seq = {'transaction_hash': '0x' + 'a' * 64, 'chain': 'eth', 'trace': root,
           'address_relation': {}, 'created_address': []}
    analysis = TraceAnalyzer(seq, {}, no_llm=True).run()
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.trace = [analysis['trace']]
    item.tx_analysis = analysis
    item.function_call_info_summary = {}
    item.function_prompts = WorkerPrompts()
    item.generation_agent = SimpleNamespace(query=lambda *a, **k: {'children_calls': [children_spec]})
    result = item._retrieve_additional_info('controlled child-call request')
    groups = result['children_calls (i.e., for {k:v}, v is the children calls of k)']
    calls = groups[f'{FUNCTION}::{A}']
    assert len(calls) == 1
    assert calls[0]['function'] == CHILD
    assert calls[0]['params'] == '0xabcdef'
    assert calls[0]['address'] == B


@pytest.mark.parametrize('bad_spec', [
    [], [A], ['not_an_address'], None, 12345, '',
    {'invalid': 'dict'}
])
def test_malformed_children_request_handled_defensively(bad_spec):
    child = {'type': 'call', 'call_type': 'call', 'address': B,
             'function': CHILD, 'params': '0xabcdef', 'children': []}
    root = {'type': 'call', 'call_type': 'call', 'address': A,
            'function': FUNCTION, 'params': '0x', 'children': [child]}
    seq = {'transaction_hash': '0x' + 'a' * 64, 'chain': 'eth', 'trace': root,
           'address_relation': {}, 'created_address': []}
    analysis = TraceAnalyzer(seq, {}, no_llm=True).run()
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.trace = [analysis['trace']]
    item.tx_analysis = analysis
    item.function_call_info_summary = {}
    item.function_prompts = WorkerPrompts()
    item.generation_agent = SimpleNamespace(query=lambda *a, **k: {'children_calls': [bad_spec]})
    result = item._retrieve_additional_info('malformed child-call request')
    assert 'children_calls (i.e., for {k:v}, v is the children calls of k)' not in result


@pytest.mark.parametrize('bad_depth', [
    [], [999], [0, 999], [-5], 'invalid', None, [None]
])
def test_retrieve_function_call_by_depth_bounds_checking(bad_depth):
    child = {'type': 'call', 'call_type': 'call', 'address': B,
             'function': CHILD, 'params': '0xabcdef', 'children': []}
    root = {'type': 'call', 'call_type': 'call', 'address': A,
            'function': FUNCTION, 'params': '0x', 'children': [child]}
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.trace = [root]
    with pytest.raises(ValueError, match='path'):
        item._retrieve_function_call_by_depth(bad_depth, FUNCTION)
    with pytest.raises(ValueError, match='path'):
        item._retrieve_function_call_by_depth(bad_depth, FUNCTION, get_children=True)


def test_trace_path_must_match_requested_function_identity():
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.trace = [{'function': FUNCTION, 'address': A, 'children': []}]
    with pytest.raises(ValueError, match='identity'):
        item._retrieve_function_call_by_depth([0], CHILD)


def test_invalid_path_is_not_indistinguishable_from_verified_leaf():
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.trace = [{'function': FUNCTION, 'address': A, 'children': []}]
    assert item._retrieve_function_call_by_depth([0], FUNCTION, get_children=True) == []
    with pytest.raises(ValueError, match='path'):
        item._retrieve_function_call_by_depth([99], FUNCTION, get_children=True)


@pytest.mark.parametrize('reply', [[], {'children_calls': [[A]]},
    {'source_code': 9}, {'status': 'ready'}, {'function_call': None}])
def test_invalid_generated_retrieval_request_is_explicitly_unavailable(reply):
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.function_call_info_summary = {}
    item.function_prompts = WorkerPrompts()
    item.generation_agent = SimpleNamespace(query=lambda *args, **kwargs: reply)
    result = item._retrieve_additional_info('controlled unavailable request')
    assert result['retrieval_status']
    assert any(record['status'] == 'unavailable' for record in result['retrieval_status'])
    assert item.retrieval_unavailable_count > 0


def test_same_selector_wrong_contract_is_not_returned_as_evidence():
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.trace = [{'function': FUNCTION, 'address': A, 'children': []}]
    item.function_call_info_summary = {}
    item.tx_analysis = {'function_call_loc_memo': {
        FUNCTION+'::'+B: [{'params': '0x', 'depth': [0]}]}}
    with pytest.raises(ValueError, match='identity'):
        item._retrieve_children_calls(FUNCTION, B)


def test_verified_leaf_retrieval_reports_available_empty():
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.trace = [{'function': FUNCTION, 'address': A, 'children': []}]
    item.function_call_info_summary = {}
    item.tx_analysis = {'function_call_loc_memo': {
        FUNCTION+'::'+A: [{'params': '0x', 'depth': [0]}]}}
    item.function_prompts = WorkerPrompts()
    item.generation_agent = SimpleNamespace(query=lambda *args, **kwargs: {'children_calls': [[A, FUNCTION]]})
    result = item._retrieve_additional_info('controlled verified leaf')
    assert result['children_calls (i.e., for {k:v}, v is the children calls of k)'][FUNCTION+'::'+A] == []
    assert result['retrieval_status'][0]['status'] == 'available_empty'
    assert not getattr(item, 'retrieval_unavailable_count', 0)


def test_generation_request_has_explicit_target_object_schema():
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.function_call_info_summary = {}
    item.function_prompts = WorkerPrompts()
    prompts = []
    item.generation_agent = SimpleNamespace(query=lambda prompt: prompts.append(prompt) or {})
    item._retrieve_additional_info('controlled schema request')
    assert '"function_call": [{"address"' in prompts[0]
    assert '"function"' in prompts[0]
