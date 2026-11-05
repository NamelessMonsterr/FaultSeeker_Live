"""Real analyzer error propagation with controlled task/model boundaries."""
from types import SimpleNamespace
import pytest
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer

KEY = "foo_0x" + "1" * 40


def analyzer(reply):
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.vulnerability_prompts = SimpleNamespace(update_potentially_vulnerable_function="controlled")
    item.understanding_result = "controlled"
    item.current_task = {}
    item.processing_result = {}
    item.cheatsheet = []
    item.potentially_vulnerable_functions = {}
    item.organization_agent = SimpleNamespace(query=lambda prompt: reply)
    item._get_function_call_depth = lambda key: 1
    return item

@pytest.mark.parametrize("reply", [None, [], {KEY: []}, {KEY: {"evidence": "why"}}, {KEY: 4},
    {KEY: {"evidence": "why", "confidence_score": float("nan")}},
    {KEY: {"evidence": "why", "confidence_score": 2}},
    {KEY: {"evidence": "", "confidence_score": .5}}])
def test_invalid_findings_are_not_silently_dropped(reply):
    with pytest.raises(ValueError, match="finding"):
        analyzer(reply)._update_potentially_vulnerable_function()


def test_zero_confidence_is_valid_and_preserved():
    item = analyzer({KEY: {"evidence": "controlled", "confidence_score": 0}})
    item._update_potentially_vulnerable_function()
    assert item.potentially_vulnerable_functions[KEY]["confidence_score"] == [0]


def test_valid_empty_findings_remain_valid():
    item = analyzer({})
    item._update_potentially_vulnerable_function()
    assert item.potentially_vulnerable_functions == {}


def test_readiness_metadata_is_not_a_successful_empty_finding():
    with pytest.raises(ValueError, match='finding'):
        analyzer({'status': 'ready', 'analysis_pending': True})._update_potentially_vulnerable_function()


@pytest.mark.parametrize('observed', [[], ['0x12345678', '0x87654321']])
def test_address_only_finding_does_not_guess_from_task_text(observed):
    address = '0x'+'1'*40
    item = analyzer({address: {'evidence': 'controlled observation', 'confidence_score': 0.6}})
    item.current_task = {'description': 'Inspect 0x12345678 at ' + address}
    item.tx_analysis = {'function_call_loc_memo': {selector+'::'+address: [] for selector in observed}}
    with pytest.raises(ValueError, match='finding'):
        item._update_potentially_vulnerable_function()
    assert item.potentially_vulnerable_functions == {}


def test_address_only_finding_resolves_only_unique_observed_pair():
    address = '0x'+'1'*40
    item = analyzer({address: {'evidence': 'controlled observation', 'confidence_score': 0.6}})
    item.tx_analysis = {'function_call_loc_memo': {'0x12345678::'+address: []}}
    item._update_potentially_vulnerable_function()
    assert list(item.potentially_vulnerable_functions) == ['0x12345678_'+address]

@pytest.mark.parametrize("method", ["_function_analysis_init", "_txn_analysis_init"])
def test_task_exception_propagates_even_with_an_earlier_finding(method):
    item = analyzer({})
    item.potentially_vulnerable_functions = {KEY: {"evidence": ["earlier"]}}
    item._temp_check = lambda: False
    item._update_current_understanding = lambda **kwargs: None
    item.function_prompts = SimpleNamespace(function_analysis_init_prompt="controlled")
    item.function_call_info_summary = {}
    item.reasoning_agent = SimpleNamespace(query=lambda *a, **k: "controlled tree")
    item.txn_analyzer_model = "controlled-cloud"
    item._select_task = lambda: {"description": "controlled"}
    error = RuntimeError("controlled task failure")
    def fail(): raise error
    item._perform_task = fail
    with pytest.raises(RuntimeError) as raised:
        getattr(item, method)()
    assert raised.value is error



def loop_analyzer(answer):
    item = analyzer({})
    item._temp_check = lambda: False
    item._update_current_understanding = lambda **kwargs: None
    item.function_prompts = SimpleNamespace(function_analysis_init_prompt="controlled", check_analysis_adequacy="adequate?", check_analysis_adequacy_alt="adequate?")
    item.function_call_info_summary = {}
    item.reasoning_agent = SimpleNamespace(query=lambda *a, **k: "controlled tree")
    item.organization_agent = SimpleNamespace(query=lambda *a, **k: answer)
    item.txn_analyzer_model = "controlled-local"
    item._select_task = lambda: {"description": "controlled"}
    item._update_task_tree = lambda: None
    item._update_potentially_vulnerable_function = lambda: None
    item.cycles = []
    item._perform_task = lambda: item.cycles.append(1)
    return item


@pytest.mark.parametrize("method,ceiling", [("_function_analysis_init", 8), ("_txn_analysis_init", 3)])
@pytest.mark.parametrize("answer", ["No, not yes", "Yesterday is unrelated", "Yes."])
def test_adequacy_requires_an_explicit_affirmative_answer(method, ceiling, answer, monkeypatch):
    from faultseeker.function_analysis import function_analyzer as module
    monkeypatch.setattr(module, "is_local_model", lambda model: True)
    item = loop_analyzer(answer)
    getattr(item, method)()
    assert len(item.cycles) == (2 if answer == "Yes." else ceiling)


@pytest.mark.parametrize("method", ["_function_analysis_init", "_txn_analysis_init"])
def test_empty_selections_end_incomplete_instead_of_returning_normally(method):
    item = loop_analyzer("No")
    item._select_task = lambda: None
    with pytest.raises(RuntimeError, match="incomplete"):
        getattr(item, method)()


@pytest.mark.parametrize("method", ["_function_analysis_init", "_txn_analysis_init"])
@pytest.mark.parametrize("advance", [480, 481])
def test_loop_deadline_is_an_explicit_incomplete_exit(method, advance, monkeypatch):
    import time
    clock = [1000]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    item = loop_analyzer("No")
    def empty_after_elapsed():
        clock[0] += advance
        return None
    item._select_task = empty_after_elapsed
    with pytest.raises(RuntimeError, match="incomplete"):
        getattr(item, method)()


@pytest.mark.parametrize("method", ["_function_analysis_init", "_txn_analysis_init"])
@pytest.mark.parametrize("provided", [False, True])
def test_initial_task_tree_does_not_claim_missing_source_was_retrieved(method, provided):
    item = loop_analyzer("No")
    item.function_prompts.function_analysis_init_prompt = "{task_tree}"
    item.function_call_info_summary = ({"function_source_code": [{"source_code": "function foo() external {}"}]} if provided else {})
    prompts = []
    item.reasoning_agent = SimpleNamespace(query=lambda prompt, **kwargs: prompts.append(prompt) or "controlled tree")
    item._select_task = lambda: None
    with pytest.raises(RuntimeError, match="incomplete"):
        getattr(item, method)()
    assert len(prompts) == 1
    assert "unverified" in prompts[0] if provided else "unavailable" in prompts[0]
    assert "Retrieve the source code of the function call - (completed)" not in prompts[0]
