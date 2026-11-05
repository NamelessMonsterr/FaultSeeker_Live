"""Synthetic same-selector, different-contract retrieval regression."""
import pytest
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
A, B = '0x' + 'a' * 40, '0x' + 'b' * 40
F = '0x12345678'


def analyzer():
    result = FunctionAnalyzer.__new__(FunctionAnalyzer)
    result.function_call_info_summary = {'function': F, 'address': A, 'calls': [{'params': 'from-A', 'depth': [0]}]}
    result.current_task = {}
    result.tx_analysis = {'function_call_loc_memo': {F + '::' + B: [{'params': 'from-B', 'depth': [1]}]}}
    def node(address, params, children=()):
        return {'function': F, 'address': address, 'params': params,
                'call_type': 'call', 'type': 'call', 'children': list(children)}
    result.trace = [node(A, 'from-A', [node(A, 'child-A')]), node(B, 'from-B', [node(B, 'child-B')])]
    return result


def test_function_lookup_matches_address_as_well_as_selector():
    result = analyzer()._retrieve_function_calls({'function': F, 'address': B})
    assert result[0]['params'] == 'from-B'
    assert result[0]['address'] == B


def test_children_lookup_matches_address_as_well_as_selector():
    obj = analyzer()
    calls = obj._retrieve_children_calls(F, B)
    assert calls[0]['params'] == 'child-B'
    assert calls[0]['address'] == B


def test_same_contract_cached_summary_remains_available_case_insensitively():
    obj = analyzer()
    assert obj._retrieve_function_calls({'function': F, 'address': A.upper()})[0]['params'] == 'from-A'


def test_group_summary_without_address_uses_address_scoped_trace_memo():
    obj = analyzer()
    del obj.function_call_info_summary['address']
    assert obj._retrieve_function_calls({'function': F, 'address': B})[0]['params'] == 'from-B'
