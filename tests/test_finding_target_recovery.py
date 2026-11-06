"""Synthetic model replies against real analyzer/trace binding, offline only."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
from faultseeker.function_analysis.retrieval_contract import RetrievalContractError

A = '0x' + '1'*40
VALID, UNKNOWN = 'foo_' + A, 'invented_' + A


def analyzer(replies):
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.vulnerability_prompts = SimpleNamespace(update_potentially_vulnerable_function='synthetic finding task')
    item.understanding_result, item.current_task, item.processing_result, item.cheatsheet = '', {}, {}, []
    item.potentially_vulnerable_functions = {}
    item.trace = [{'function': 'foo', 'address': A, 'children': []}]
    item.tx_analysis = {'function_call_loc_memo': {'foo::'+A: [{'depth': [0]}]}}
    responses, prompts = iter(replies), []
    def query(prompt):
        prompts.append(prompt)
        reply = next(responses)
        if isinstance(reply, Exception):
            raise reply
        return deepcopy(reply)
    item.organization_agent = SimpleNamespace(query=query)
    return item, prompts


def test_unknown_target_repairs_once_against_observed_identity():
    item, prompts = analyzer([{UNKNOWN: ['unverified observation', .5]}, {VALID: ['controlled evidence', .6]}])
    original_query = item.organization_agent.query
    item._update_potentially_vulnerable_function()
    assert len(prompts) == 2 and VALID in prompts[1]
    assert set(item.potentially_vulnerable_functions) == {VALID}
    assert item.potentially_vulnerable_functions[VALID]['depth'] == 1
    assert item.rejected_finding_observations[-1]['status'] == 'recovered'
    assert getattr(item, 'retrieval_unavailable_count', 0) == 0
    assert item.organization_agent.query is original_query


def test_exhausted_target_repair_preserves_rejection_and_continues_independent_work():
    mixed = {VALID: ['must not partly accept this reply', .5], UNKNOWN: ['PRIVATE_SECRET', .7]}
    item, prompts = analyzer([mixed, mixed, {VALID: ['later independent analysis', .8]}])
    item._update_potentially_vulnerable_function()
    assert len(prompts) == 2
    assert item.potentially_vulnerable_functions == {}
    assert item.retrieval_unavailable_count == 1
    assert item.rejected_finding_observations[-1]['status'] == 'unresolved'
    assert 'PRIVATE_SECRET' not in str(item.rejected_finding_observations)
    item._update_potentially_vulnerable_function()
    assert len(prompts) == 3 and set(item.potentially_vulnerable_functions) == {VALID}
    assert item.retrieval_unavailable_count == 1


def test_corrupt_trace_is_not_treated_as_model_target_repair():
    item, prompts = analyzer([{VALID: ['controlled', .5]}])
    item.tx_analysis['function_call_loc_memo']['foo::'+A][0]['depth'] = [5]
    with pytest.raises(RetrievalContractError, match='trace_path_out_of_bounds'):
        item._update_potentially_vulnerable_function()
    assert len(prompts) == 1


def test_transport_loss_during_repair_propagates_without_swallowing():
    error = RuntimeError('synthetic transport failure')
    item, prompts = analyzer([{UNKNOWN: ['controlled', .5]}, error])
    original_query = item.organization_agent.query
    with pytest.raises(RuntimeError) as raised:
        item._update_potentially_vulnerable_function()
    assert raised.value is error and len(prompts) == 2
    assert item.organization_agent.query is original_query
    assert item.rejected_finding_observations[-1]['status'] == 'repair_failed'


def test_no_shared_repair_allowance_means_no_additional_query():
    item, prompts = analyzer([{UNKNOWN: ['controlled', .5]}])
    item._reserve_finding_repair = lambda: False
    item._update_potentially_vulnerable_function()
    assert len(prompts) == 1 and item.retrieval_unavailable_count == 1
    assert item.rejected_finding_observations[-1]['status'] == 'unresolved'
