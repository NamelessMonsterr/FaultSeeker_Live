"""Offline regressions for confirmed audit defects; synthetic inputs only."""
import pytest
from faultseeker.utils.agent import GPTAgent, UniversalAgent
from faultseeker.function_analysis.retrieval_contract import RetrievalContractMixin, RetrievalContractError


@pytest.mark.parametrize('agent,turns', [(GPTAgent, 1), (UniversalAgent, 2)])
def test_history_preserves_complete_pairs_and_pending_user(agent, turns):
    history = [{'role': 'system', 'content': 'system'}]
    for i in range(4):
        history += [{'role': 'user', 'content': str(i)}, {'role': 'assistant', 'content': str(i)}]
    history.append({'role': 'user', 'content': 'pending'})
    result = agent._truncate_history(None, history, max_turns=turns)
    assert result[1]['role'] == 'user'
    assert result[-1] == history[-1]
    assert len(result) == 2 + 2 * turns
    for index in range(1, len(result)-1, 2):
        assert result[index]['role'] == 'user'
        assert result[index+1]['role'] == 'assistant'


def test_unobserved_finding_does_not_acquire_fabricated_depth():
    item = RetrievalContractMixin()
    item.tx_analysis = {'function_call_loc_memo': {}}
    with pytest.raises(RetrievalContractError, match='unobserved_target'):
        item._get_function_call_depth('0x12345678_0x' + '1'*40)


def test_ranking_normalizes_address_case_without_accepting_other_targets():
    from types import SimpleNamespace
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    key = 'foo_0x' + 'a'*40
    item.potentially_vulnerable_functions = {key: {}}
    item.understanding_result = 'synthetic'
    item.vulnerability_prompts = SimpleNamespace(rank_potentially_vulnerable_functions='{potentially_vulnerable_functions}')
    item.agent = SimpleNamespace(query=lambda *args: [key.upper()])
    item._rank_potentially_vulnerable_functions()
    assert item.ranked_result == [key]


def test_invalid_evidence_types_are_explicit_scoring_errors():
    from faultseeker.core.confidence_scorer import ConfidenceScorer
    scorer = ConfidenceScorer()
    for evidence in (None, 2, {'text': 'unverified'}):
        with pytest.raises(ValueError, match='evidence'):
            scorer.score_function({'function': 'f', 'address': '0x'+'1'*40,
                                   'evidence': evidence, 'confidence_score': [.5]}, {})


def test_invalid_ranking_gets_one_schema_repair_without_fabricating_ranks():
    from types import SimpleNamespace
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    key = 'f_0x'+'1'*40
    item.potentially_vulnerable_functions = {key: {}}
    item.understanding_result = 'synthetic'
    item.vulnerability_prompts = SimpleNamespace(rank_potentially_vulnerable_functions='{potentially_vulnerable_functions}')
    replies, prompts = iter([{'ranking': [key]}, {'ranked_functions': [key]}]), []
    def query(prompt):
        prompts.append(prompt)
        return next(replies)
    item.agent = SimpleNamespace(query=query)
    item._rank_potentially_vulnerable_functions()
    assert item.ranked_result == [key] and len(prompts) == 2
    assert key in prompts[1]


@pytest.mark.parametrize('reply', [{}, [], ['unknown'], None])
def test_invalid_shortlist_cannot_silently_erase_candidates(reply):
    from types import SimpleNamespace
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.functions_to_be_inspected = {f'f{i}_0x'+ '1'*40: {'count': 1, 'calls': []} for i in range(6)}
    item.function_prompts = SimpleNamespace(narrow_down_functions='{function_call_to_be_inspected}')
    item.fundflow_analysis = {'balance_change': {}}
    item.address_calls_with_created_contract_in_params = {}
    item._prepare_children_call_memo = lambda *args: pytest.fail('invalid selection reached analysis')
    item.agent = SimpleNamespace(query=lambda *args: reply)
    with pytest.raises(ValueError, match='selection'):
        item._review_function_calls()


def test_local_prompt_limit_rejects_without_truncation_or_request(monkeypatch):
    from faultseeker.utils import agent as module
    item = module.OllmaAgent.__new__(module.OllmaAgent)
    item.model = 'offline'
    item._record_router_query = lambda *args, **kwargs: None
    item.memory = [{'role': 'system', 'content': 'synthetic'}]
    monkeypatch.setattr(module, 'chat', lambda **kwargs: {'message': {'content': '{}'}})
    with pytest.raises(ValueError, match='input_budget_exceeded'):
        item._send_message('x' * (module.LOCAL_MODEL_MAX_PROMPT + 1))
    assert len(item.memory) == 1


@pytest.mark.parametrize('failure', [{'error': 'execution reverted'}, {'success': False}, {'status': '0x0'}])
def test_reverted_write_does_not_form_price_manipulation_sequence(failure):
    from faultseeker.forensics.signal_extractor import SignalExtractor
    calls = [{'function': 'getreserves', 'depth': [0, 0]},
             {'function': 'swap', 'depth': [0, 1], **failure},
             {'function': 'getreserves', 'depth': [0, 2]}]
    item = SignalExtractor({}, {'flatten_trace': calls})
    item._check_price_manipulation()
    assert item.signals.price_read_write_sequences == 0
    assert len(item.observed_flat) == 3


def test_reverted_parent_excludes_successful_child_effects():
    from faultseeker.forensics.signal_extractor import SignalExtractor
    calls = [{'function': 'getreserves', 'depth': [0, 0]},
             {'function': 'outer', 'depth': [0, 1], 'success': False},
             {'function': 'swap', 'depth': [0, 1, 0], 'success': True},
             {'function': 'getreserves', 'depth': [0, 2]}]
    item = SignalExtractor({}, {'flatten_trace': calls})
    item._check_price_manipulation()
    assert item.signals.price_read_write_sequences == 0
