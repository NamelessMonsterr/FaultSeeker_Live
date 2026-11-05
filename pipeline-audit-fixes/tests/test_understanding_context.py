"""Completed task context must reach subsequent reasoning; no live model calls."""
from types import SimpleNamespace
import pytest
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer

OBSERVATION = 'CONTROLLED_COMPLETED_TASK_OBSERVATION'


def test_understanding_update_carries_current_task_result_and_prior_state():
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.function_prompts = SimpleNamespace(function_call_organization_function_call='Call: {function_call_info_summary}')
    item.function_call_info_summary = {'function': '0x12345678'}
    item.understanding_result = 'prior uncertain observation'
    item.current_task = {'description': 'controlled source review'}
    item.processing_result = OBSERVATION
    prompts = []
    def query(prompt, **kwargs):
        prompts.append(prompt)
        return 'revised understanding'
    item.organization_agent = SimpleNamespace(query=query)
    item._update_current_understanding()
    assert OBSERVATION in prompts[0]
    assert 'controlled source review' in prompts[0]
    assert 'prior uncertain observation' in prompts[0]
    assert '0x12345678' in prompts[0]
    assert item.understanding_result == 'revised understanding'


@pytest.mark.parametrize('model', ['inception/mercury-3', 'itera/qwen3.8-27b'])
def test_completed_task_evidence_reaches_actual_loop_adequacy_check(model, monkeypatch):
    # Console registration classifies both approved aliases as cloud models.
    # Reproduce that classification without constructing network clients.
    monkeypatch.setattr('faultseeker.function_analysis.function_analyzer.is_local_model', lambda model: False)
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.txn_analyzer_model = model
    item.function_call_info_summary = {'function': '0x12345678'}
    item.function_prompts = SimpleNamespace(
        function_call_organization_function_call='Call: {function_call_info_summary}',
        function_analysis_init_prompt='{task_tree}{current_understanding}{function_call_info_summary}',
        check_analysis_adequacy='ADEQUATE?')
    item._temp_check = lambda: False
    item.reasoning_agent = SimpleNamespace(query=lambda *a, **k: 'controlled tree')
    def query(prompt, **kwargs):
        if prompt.startswith('ADEQUATE?'):
            return 'Yes.' if OBSERVATION in prompt else 'No.'
        return OBSERVATION if OBSERVATION in prompt else 'initial call summary only'
    item.organization_agent = SimpleNamespace(query=query)
    item._select_task = lambda: {'description': 'controlled task'}
    cycles = []
    def perform():
        cycles.append(1)
        item.current_task = {'description': 'controlled task'}
        item.processing_result = OBSERVATION
    item._perform_task = perform
    item._update_task_tree = lambda: None
    item._update_potentially_vulnerable_function = lambda: None
    item._function_analysis_init()
    assert len(cycles) == 2


def test_initial_understanding_does_not_require_a_completed_task():
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.function_prompts = SimpleNamespace(function_call_organization_function_call='{function_call_info_summary}')
    item.function_call_info_summary = {'function': '0x12345678'}
    item.organization_agent = SimpleNamespace(query=lambda *a, **k: 'initial')
    item._update_current_understanding(is_init=True)
    assert item.understanding_result == 'initial'
