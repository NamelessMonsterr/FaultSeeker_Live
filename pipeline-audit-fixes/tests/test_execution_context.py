"""Reported transaction status is context, not independently verified receipt proof."""
from types import SimpleNamespace
import pytest
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer


@pytest.mark.parametrize('status,outcome', [('Success', 'success'), ('Failed', 'reverted'),
    ('Reverted', 'reverted'), ('unknown', 'unknown'), (None, 'unknown'),
    ('PRIVATE_UNTRUSTED_STATUS', 'unknown')])
def test_execution_context_retains_reported_status_without_inventing_verification(status, outcome):
    context = FunctionAnalyzer._execution_context({'status': status, '_source': 'html_scrape'})
    assert context['reported_outcome'] == outcome
    assert context['source'] == 'html_scrape'
    assert context['receipt_binding'] == 'unverified'
    assert 'PRIVATE' not in str(context)


@pytest.mark.parametrize('method', ['_function_analysis_init', '_txn_analysis_init'])
def test_actual_loop_initial_understanding_receives_status_and_net_flow_caveat(method):
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.txn_info = {'status': 'Success', '_source': 'html_scrape'}
    item.function_call_info_summary = {'function': '0x12345678'}
    item._temp_check = lambda: False
    seen = []
    def capture(**kwargs):
        seen.append(dict(item.function_call_info_summary))
        raise RuntimeError('controlled stop before model')
    item._update_current_understanding = capture
    with pytest.raises(RuntimeError, match='controlled stop'):
        getattr(item, method)()
    context = seen[0]['transaction_execution']
    assert context['reported_outcome'] == 'success'
    assert context['receipt_binding'] == 'unverified'
    assert 'zero' in context['interpretation'].lower()
    assert 'revert' in context['interpretation'].lower()
