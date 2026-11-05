"""Opt-in candidate-pipeline contract, separate from immutable Docker-pin tests.

Only controlled HTTP replies are used. Set an explicit local checkout and its
expected SHA; this does not establish real provider or forensic correctness.
"""
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys

import httpx
from openai import OpenAI
import pytest

from app.model_endpoint import ModelEndpointFailure, ModelEndpointSession
from app.pipeline_guards import PipelineRuntime

MODEL = "itera/qwen3.8-27b"
TX = "0x" + "a" * 64


def test_real_candidate_review_checkpoints_before_mid_batch_failure(candidate, monkeypatch, tmp_path):
    from test_pinned_pipeline import exercise_interrupted_function_checkpoint
    exercise_interrupted_function_checkpoint(monkeypatch, tmp_path)


def exercise_unavailable_retrieval_contract():
    from types import SimpleNamespace
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    from faultseeker.prompts.function_analysis.worker_prompts import WorkerPrompts
    runtime = PipelineRuntime(TX, 'eth').install()
    runtime.partial = {'transaction': {'hash': TX, 'chain': 'eth'}}
    saved = []
    runtime.checkpoint_sink = lambda report: saved.append(report)
    item = FunctionAnalyzer.__new__(FunctionAnalyzer)
    item.function_call_info_summary = {}
    item.function_prompts = WorkerPrompts()
    item.generation_agent = SimpleNamespace(query=lambda *a, **kw: {'children_calls': [['DUMMY_PRIVATE_VALUE']]})
    try:
        result = item._retrieve_additional_info('controlled unavailable retrieval')
        assert result['retrieval_status'][0]['status'] == 'unavailable'
        report = runtime.annotate_result({'analysis_status': 'completed', 'scored_functions': [], 'evidence_cards': []})
        assert report['analysis_status'] == 'partial'
        assert report['classification']['rule_verdict'] == 'INCONCLUSIVE'
        assert report['sections']['function_analysis'] == 'partial_missing_evidence'
        assert saved, 'Retrieval diagnostic was not persisted before unit completion'
        assert saved[-1]['analysis_integrity']['retrieval_diagnostics']
        assert 'DUMMY_PRIVATE_VALUE' not in json.dumps(saved)
    finally:
        runtime.close()


def test_candidate_unavailable_retrieval_is_checkpointed_and_cannot_look_complete(candidate):
    exercise_unavailable_retrieval_contract()


def test_standalone_and_console_retrieval_contracts_match(candidate):
    source = Path(candidate.__file__).resolve().parents[1]/'function_analysis/retrieval_contract.py'
    console = Path(__file__).resolve().parents[1]/'app/retrieval_contract.py'
    assert source.read_bytes() == console.read_bytes()


@pytest.mark.parametrize("kind,cycles", [("function", 3), ("transaction", 2)])
@pytest.mark.parametrize("model", ["inception/mercury-3", "itera/qwen3.8-27b"])
def test_candidate_actual_cloud_loop_ceiling_matches_completion_guard(candidate, monkeypatch, kind, cycles, model):
    from types import SimpleNamespace
    module = importlib.import_module("faultseeker.function_analysis.function_analyzer")
    cls = module.FunctionAnalyzer
    runtime = PipelineRuntime(TX, "eth", session=ModelEndpointSession(retry_limit=0)).install()
    try:
        analyzer = object.__new__(cls)
        analyzer.txn_analyzer_model = model
        analyzer.function_call_info_summary = {"function": "0x12345678", "address": "0x" + "b" * 40}
        analyzer.function_prompts = SimpleNamespace(
            function_analysis_init_prompt="{task_tree}{current_understanding}{function_call_info_summary}",
            check_analysis_adequacy="ADEQUATE?", check_analysis_adequacy_alt="ADEQUATE-ALT?")
        class Agent:
            def query(self, *args, **kwargs):
                return "No"
        analyzer.reasoning_agent = analyzer.organization_agent = Agent()
        analyzer.understanding_result = "controlled test"
        analyzer.potentially_vulnerable_functions = {}
        analyzer._temp_check = lambda: False
        analyzer._update_current_understanding = lambda **kwargs: None
        analyzer._update_task_tree = lambda: None
        analyzer._select_task = lambda: "controlled task"
        analyzer._perform_task = lambda: None
        monkeypatch.setattr(cls, "_update_potentially_vulnerable_function",
                            runtime.wall_cap.wrap_update(lambda self: None))
        getattr(analyzer, "_function_analysis_init" if kind == "function" else "_txn_analysis_init")()
        record = runtime.wall_cap.summary()["functions"][0]
        assert record["completed_cycles"] == cycles
        assert (record["ceiling"], record["outcome"], record["detail"]) == (cycles, "normal", "iteration_ceiling")
    finally:
        runtime.close()


def test_candidate_inception_agents_use_registered_cloud_policy_and_shared_transport(candidate, monkeypatch):
    model = "inception/mercury-3"
    monkeypatch.setenv("INCEPTION_API_KEY", "dummy-inception-key")
    monkeypatch.setenv("INCEPTION_BASE_URL", "https://inception-fixture.invalid/v1")
    requests = []
    def respond(request):
        assert str(request.url) == "https://inception-fixture.invalid/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer dummy-inception-key"
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"id": "mock", "object": "chat.completion", "created": 0,
            "model": "mercury-3", "choices": [{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "OK"}}]})
    def factory(**kwargs):
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(respond)))
    monkeypatch.setattr(candidate, "OpenAI", factory)
    monkeypatch.setattr(candidate, "chat", lambda **kwargs: pytest.fail("Inception was sent to Ollama"))
    runtime = PipelineRuntime(TX, "eth", session=ModelEndpointSession(retry_limit=0)).install()
    runtime.model_keys = {model: ["dummy-inception-key"]}
    try:
        runtime.preflight([model])
        analyzer = importlib.import_module("faultseeker.function_analysis.function_analyzer").FunctionAnalyzer(model=model)
        prompts = importlib.import_module("faultseeker.prompts.local_model_prompts")
        assert not prompts.is_local_model(model)
        assert type(analyzer.function_prompts) is prompts.WorkerPrompts
        for name in ("reasoning_agent", "generation_agent", "processing_agent", "organization_agent",
                     "children_call_filtering_agent", "agent"):
            instance = getattr(analyzer, name)
            assert isinstance(instance, candidate.UniversalAgent)
            assert instance.query("Controlled routing contract", format="str") == "OK"
        assert len(requests) == 7
        assert requests[0]["reasoning_effort"] == "instant"
        assert all(row["model"] == "mercury-3" and row["temperature"] == 0.5 for row in requests)
        assert all(row["reasoning_effort"] == "low" and row["max_completion_tokens"] == 24576 for row in requests[1:])
        assert runtime.session.summary()["calls"]["analysis"] == {"ok": 6, "failed": 0}
    finally:
        runtime.close()


@pytest.fixture
def candidate(monkeypatch, tmp_path):
    location = os.getenv("FAULTSEEKER_TEST_CANDIDATE_REPO")
    expected = os.getenv("FAULTSEEKER_TEST_CANDIDATE_SHA")
    if not location or not expected:
        pytest.skip("Candidate checkout/SHA not supplied; Docker-pin verification is a separate suite")
    actual = subprocess.check_output(["git", "-C", location, "rev-parse", "HEAD"], text=True).strip()
    assert actual == expected, "Candidate pipeline revision does not match the explicitly requested SHA"
    saved = {name: module for name, module in sys.modules.items()
             if name == "faultseeker" or name.startswith("faultseeker.")}
    for name in saved:
        sys.modules.pop(name)
    monkeypatch.syspath_prepend(str(Path(location).resolve()))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "true")
    monkeypatch.setenv("ITERA_API_KEY", "dummy-first,dummy-second")
    monkeypatch.setenv("OPENAI_API_KEY", "dummy-placeholder")
    monkeypatch.setenv("ITERA_BASE_URL", "https://candidate-model.invalid/v1")
    try:
        yield importlib.import_module("faultseeker.utils.agent")
    finally:
        for name in list(sys.modules):
            if name == "faultseeker" or name.startswith("faultseeker."):
                sys.modules.pop(name)
        sys.modules.update(saved)


def configured_runtime(agents, monkeypatch, statuses, *, supplied_keys=True, retry_limit=1, model=MODEL):
    seen, options, events = [], [], []
    statuses = iter(statuses)
    def respond(request):
        seen.append({"auth": request.headers["authorization"], "body": json.loads(request.content)})
        status = next(statuses, 200)
        if status != 200:
            return httpx.Response(status, text="PRIVATE_PROVIDER_BODY")
        return httpx.Response(200, json={"id": "mock", "object": "chat.completion", "created": 0,
            "model": "qwen/qwen3.8-27b" if model == MODEL else model, "choices": [{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "Ready"}}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}})
    def factory(**kwargs):
        options.append(kwargs.copy())
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(respond)))
    monkeypatch.setattr(agents, "OpenAI", factory)
    monkeypatch.setattr(agents, "chat", lambda **kwargs: pytest.fail("Cloud model was sent to Ollama"))
    session = ModelEndpointSession(retry_limit=retry_limit, time_budget=30, call_timeout=5,
                                   sleep=lambda _seconds: None, emit=events.append)
    runtime = PipelineRuntime(TX, "eth", session=session).install()
    if supplied_keys:
        # This is the actual worker path; it bypasses upstream key-list parsing.
        runtime.model_keys = {model: ["dummy-first", "dummy-second"]}
    return runtime, seen, options, events


def test_candidate_real_analyzer_analysis_uses_shared_transport(candidate, monkeypatch):
    runtime, seen, options, _events = configured_runtime(candidate, monkeypatch, [200, 200])
    try:
        runtime.preflight([MODEL], timeout=5)
        analyzer = importlib.import_module("faultseeker.function_analysis.function_analyzer").FunctionAnalyzer(model=MODEL)
        recorded = []
        analyzer.reasoning_agent._record_router_query = lambda *args, **kwargs: recorded.append((args, kwargs))
        assert analyzer.reasoning_agent.query("Controlled analysis", format="str") == "Ready"
        assert runtime.session.summary()["calls"] == {"preflight": {"ok": 1, "failed": 0},
                                                       "analysis": {"ok": 1, "failed": 0}}
        assert runtime.session.summary()["tokens"] == {"prompt": 4, "completion": 6, "reasoning": 0}
        assert len(seen) == 2
        assert all(row["body"]["model"] == "qwen/qwen3.8-27b" and row["body"]["reasoning"] is False for row in seen)
        assert all(row["auth"] == "Bearer dummy-first" for row in seen)
        assert all(option.get("max_retries") == 0 for option in options)
        assert recorded and recorded[0][1] == {"input_tokens": 2, "output_tokens": 3}
        assert analyzer.reasoning_agent.memory[-1] == {"role": "assistant", "content": "Ready"}
    finally:
        runtime.close()


@pytest.mark.parametrize("model,setting,endpoint,json_mode", [
    ("gpt-6.1-sol-low", "CODEX_PROXY_BASE_URL", "https://codex-fixture.invalid/v1", False),
    ("gpt-4o-mini", "OPENAI_DIRECT_BASE_URL", "https://direct-fixture.invalid/v1", True)])
def test_candidate_legacy_gpt_uses_selected_route_and_preserves_json_mode(candidate, monkeypatch, model, setting, endpoint, json_mode):
    monkeypatch.setenv(setting, endpoint)
    runtime, seen, options, _events = configured_runtime(candidate, monkeypatch, [200, 200], model=model)
    try:
        runtime.preflight([model], timeout=5)
        analyzer = importlib.import_module("faultseeker.function_analysis.function_analyzer").FunctionAnalyzer(model=model)
        assert analyzer.reasoning_agent.query("Controlled GPT analysis", format="str") == "Ready"
        assert runtime.session.summary()["calls"]["analysis"]["ok"] == 1
        assert all(option["base_url"] == endpoint and option["max_retries"] == 0 for option in options)
        assert seen[-1]["body"]["model"] == model
        assert seen[-1]["body"].get("response_format") == ({"type": "json_object"} if json_mode else None)
        assert "reasoning" not in seen[-1]["body"]
    finally:
        runtime.close()


@pytest.mark.parametrize("raw", ["dummy-first,dummy-second", "dummy-first\ndummy-second",
    "dummy-first;dummy-second", "ITERA_API_KEY=dummy-first ITERA_API_KEY_2=dummy-second",
    "IGNORED=not-a-key dummy-first dummy-second"])
def test_candidate_missing_upstream_key_parser_preserves_supported_key_lists(candidate, monkeypatch, raw):
    monkeypatch.setenv("ITERA_API_KEY", raw)
    runtime, seen, _options, _events = configured_runtime(candidate, monkeypatch, [401, 200], supplied_keys=False)
    try:
        runtime.preflight([MODEL], timeout=5)
        assert [row["auth"] for row in seen] == ["Bearer dummy-first", "Bearer dummy-second"]
    finally:
        runtime.close()


@pytest.mark.parametrize("supplied_keys", [False, True])
def test_candidate_preflight_rotation_survives_into_analysis(candidate, monkeypatch, supplied_keys):
    runtime, seen, _options, _events = configured_runtime(candidate, monkeypatch, [401, 200, 200], supplied_keys=supplied_keys)
    try:
        runtime.preflight([MODEL], timeout=5)
        analyzer = importlib.import_module("faultseeker.function_analysis.function_analyzer").FunctionAnalyzer(model=MODEL)
        assert analyzer.reasoning_agent.query("Controlled analysis", format="str") == "Ready"
        assert [row["auth"] for row in seen] == ["Bearer dummy-first", "Bearer dummy-second", "Bearer dummy-second"]
        assert runtime.session.summary()["calls"]["analysis"]["ok"] == 1
    finally:
        runtime.close()


@pytest.mark.parametrize("status,kind,analysis_attempts", [(502, "upstream_http", 2), (429, "rate_limited", 1)])
@pytest.mark.parametrize("output_format", ["str", "json"])
def test_candidate_mid_run_failure_is_latched_not_swallowed(candidate, monkeypatch, status, kind, analysis_attempts, output_format):
    runtime, seen, _options, events = configured_runtime(candidate, monkeypatch, [200, status, status])
    try:
        runtime.preflight([MODEL], timeout=5)
        analyzer = importlib.import_module("faultseeker.function_analysis.function_analyzer").FunctionAnalyzer(model=MODEL)
        with pytest.raises(ModelEndpointFailure) as failure:
            analyzer.reasoning_agent.query("Controlled analysis", format=output_format)
        assert failure.value.kind == kind
        assert runtime.session.summary()["calls"]["analysis"] == {"ok": 0, "failed": analysis_attempts}
        count = len(seen)
        with pytest.raises(ModelEndpointFailure):
            analyzer.generation_agent.query("No fresh retry ladder", format="str")
        assert len(seen) == count == 1 + analysis_attempts
        assert "PRIVATE_PROVIDER_BODY" not in str(failure.value)
        assert "dummy-first" not in json.dumps(events)
    finally:
        runtime.close()


def test_verified_abi_context_reaches_real_function_summary(candidate, monkeypatch):
    import types
    import networkx as nx
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    address, selector = '0x' + '1' * 40, '0xa9059cbb'
    runtime = PipelineRuntime('0x' + 'a' * 64, 'eth').install()
    runtime.sequence = {'trace': {'function': selector, 'address': address, 'children': []}}
    seen=[]
    def lookup(addr, fn):
        seen.append((addr,fn))
        return {'status':'verified','signature':'transfer(address,uint256)','scope':'block_end_state'}
    runtime.abi_context=types.SimpleNamespace(lookup=lookup)
    try:
        obj=FunctionAnalyzer.__new__(FunctionAnalyzer)
        obj.fundflow_analysis={'balance_change':{}}
        obj.txn_seq={'address_calls':{address:[selector]}}
        obj.address_relation=nx.DiGraph()
        obj._retrieve_source_code=lambda *args: []
        result=obj._retrieve_related_info(address,selector)
        assert result['verified_abi_context']['signature']=='transfer(address,uint256)'
        assert result['address_calls']==[selector]
        obj._retrieve_related_info('0x'+'2'*40,selector)
        assert seen==[(address,selector)]  # unobserved target cannot consume lookup budget
    finally:
        runtime.close()


def test_function_selection_receives_verified_interface_facts(candidate, monkeypatch):
    import types
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    from faultseeker.prompts.function_analysis.worker_prompts import WorkerPrompts
    addresses=['0x'+str(i)*40 for i in range(1,7)]
    selector='0xa9059cbb'
    nodes=[{'function':selector,'address':address,'children':[]} for address in addresses]
    nodes[0]['children']=nodes[1:]
    runtime=PipelineRuntime('0x'+'a'*64,'eth').install()
    runtime.sequence={'trace':nodes[0]}
    runtime.abi_context=types.SimpleNamespace(lookup=lambda address,fn: ({'status':'verified','abi':{'name':'transfer'},'scope':'block_end_state'} if address==addresses[-1] else {'status':'selector_not_found'}))
    class Captured(Exception): pass
    prompts=[]
    def query(prompt,*args,**kwargs):
        prompts.append(prompt)
        raise Captured()
    obj=FunctionAnalyzer.__new__(FunctionAnalyzer)
    obj.function_prompts=WorkerPrompts()
    original=obj.function_prompts
    obj.fundflow_analysis={"balance_change":{}}
    obj.agent=types.SimpleNamespace(query=query)
    obj.functions_to_be_inspected={selector+'_'+address:{'count':1,'calls':[]} for address in addresses}
    obj.address_calls_with_created_contract_in_params={}
    obj.repeated_patterns=[]
    try:
        with pytest.raises(Captured):obj._review_function_calls()
        assert '"function_name": "transfer"' in prompts[0]
        assert '"unverified_target_count": 5' in prompts[0]
        assert all(selector+'_'+address in prompts[0] for address in addresses)
        assert obj.function_prompts is original
    finally:runtime.close()


@pytest.mark.parametrize("model", ["inception/mercury-3", "itera/qwen3.8-27b"])
def test_candidate_mercury_preserves_complete_structured_prompt(candidate, monkeypatch, model):
    monkeypatch.setenv('INCEPTION_API_KEY','dummy-inception-key')
    monkeypatch.setenv('ITERA_API_KEY','dummy-itera-key')
    monkeypatch.setenv('ITERA_BASE_URL','https://itera-fixture.invalid/v1')
    seen=[]
    def respond(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200,json={'id':'mock','object':'chat.completion','created':0,'model':json.loads(request.content)['model'],
            'choices':[{'index':0,'finish_reason':'stop','message':{'role':'assistant','content':'OK'}}]})
    monkeypatch.setattr(candidate,'OpenAI',lambda **kwargs:OpenAI(**kwargs,http_client=httpx.Client(transport=httpx.MockTransport(respond))))
    runtime=PipelineRuntime(TX,'eth',session=ModelEndpointSession(retry_limit=0)).install()
    try:
        agent=candidate.UniversalAgent('',model)
        prompt='{"data":"'+'x'*11000+'","required_tail":true}'
        agent._send_message(prompt)
        assert seen[0]['messages'][-1]['content']==prompt
    finally:runtime.close()


def test_detailed_worker_receives_verified_child_interface_context(candidate):
    import types
    from copy import deepcopy
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    root_address, child_address = '0x'+'1'*40, '0x'+'2'*40
    root_selector, child_selector = '0x12345678', '0xa9059cbb'
    runtime=PipelineRuntime('0x'+'a'*64,'eth').install()
    runtime.sequence={'trace':{'function':root_selector,'address':root_address,'children':[{'function':child_selector,'address':child_address,'children':[]}]}}
    runtime.abi_observations={(child_address,child_selector):{'status':'verified','abi':{'name':'transfer'},'scope':'block_end_state'}}
    obj=FunctionAnalyzer.__new__(FunctionAnalyzer)
    obj.function_call_info_summary={'function':root_selector,'address':root_address,'calls':[{'params':'original calldata'}]}
    obj._temp_check=lambda:False
    seen=[]
    class Captured(Exception):pass
    def understand(*args,**kwargs):
        seen.append(deepcopy(obj.function_call_info_summary))
        raise Captured()
    obj._update_current_understanding=understand
    try:
        with pytest.raises(Captured):obj._function_analysis_init()
        facts=seen[0]['verified_interfaces']['facts']
        assert facts[0]['function_name']=='transfer'
        assert facts[0]['target']==child_selector+'_'+child_address
        assert seen[0]['function']==root_selector
        assert seen[0]['calls']==[{'params':'original calldata'}]
    finally:runtime.close()


def test_verified_source_is_retrieved_for_canonical_selector(candidate):
    import types
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    address,selector='0x'+'1'*40,'0xa9059cbb'
    runtime=PipelineRuntime('0x'+'a'*64,'eth').install()
    runtime.sequence={'trace':{'function':selector,'address':address,'children':[]}}
    source=[{'path':'Contract.sol','source_code':'function transfer(address,uint256) external nonReentrant {}'}]
    calls=[]
    runtime.abi_context=types.SimpleNamespace(
        lookup=lambda *args:{'status':'verified','abi':{'name':'transfer'},'scope':'block_end_state'},
        source_for=lambda *args:(calls.append(args) or {'status':'verified','sources':source}))
    obj=FunctionAnalyzer.__new__(FunctionAnalyzer)
    obj.contract_info={address:{'transfer':[{'start_line':1,'end_line':2,'content':source[0]['source_code'],'path':'Contract.sol'}]}}
    try:
        result=obj._retrieve_source_code(address,selector)
        assert result==source
        assert calls==[(address,selector)]
    finally:runtime.close()


@pytest.mark.parametrize("method", ["_function_analysis_init", "_txn_analysis_init"])
def test_candidate_empty_task_exit_produces_inconclusive_partial_report(candidate, method):
    """Real candidate loop/runtime report; controlled prior-stage snapshot only."""
    from types import SimpleNamespace
    module = importlib.import_module("faultseeker.function_analysis.function_analyzer")
    cls = module.FunctionAnalyzer
    runtime = PipelineRuntime(TX, "eth", session=ModelEndpointSession(retry_limit=0)).install()
    try:
        runtime.partial = {"transaction": {"hash": TX, "chain": "eth"}, "sections": {"deterministic_checks": "completed"}}
        analyzer = object.__new__(cls)
        analyzer.txn_analyzer_model = "inception/mercury-3"
        analyzer.function_call_info_summary = {}
        analyzer.function_prompts = SimpleNamespace(function_analysis_init_prompt="controlled", check_analysis_adequacy="adequate?", check_analysis_adequacy_alt="adequate?")
        class Agent:
            def query(self, *args, **kwargs): return "controlled tree"
        analyzer.reasoning_agent = analyzer.organization_agent = Agent()
        analyzer.understanding_result = "controlled"
        analyzer.potentially_vulnerable_functions = {}
        analyzer._temp_check = lambda: False
        analyzer._update_current_understanding = lambda **kwargs: None
        analyzer._select_task = lambda: None
        with pytest.raises(module.AnalysisIncompleteError) as raised:
            getattr(analyzer, method)()
        report = runtime.failure_report(raised.value)
        assert report["analysis_status"] == "partial"
        assert report["classification"] == {"rule_verdict": "INCONCLUSIVE"}
        assert report["failure"] == {"kind": "analysis_incomplete"}
        assert report["sections"]["function_analysis"] == "failed"
        assert report["sections"]["scoring"] == "skipped"
        assert report["analysis_integrity"]["function_analysis_complete"] is False
        assert runtime.wall_cap.summary()["error"] == 1
    finally:
        runtime.close()
def test_candidate_finding_recovery_uses_shared_budget_and_preserves_partial_checkpoint(candidate, monkeypatch):
    from copy import deepcopy
    from app.model_endpoint import ModelEndpointFailure
    address = '0x' + '1'*40
    valid, invalid = 'foo_'+address, 'invented_'+address
    replies = iter([{invalid: ['PRIVATE_SECRET', .5]}, {invalid: ['PRIVATE_SECRET', .5]},
                    {valid: ['controlled independent evidence', .7]}])
    requests = []
    def respond(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={'id': 'mock', 'object': 'chat.completion', 'created': 0,
            'model': MODEL, 'choices': [{'index': 0, 'finish_reason': 'stop',
            'message': {'role': 'assistant', 'content': json.dumps(next(replies))}}]})
    def factory(**kwargs):
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(respond)))
    monkeypatch.setattr(candidate, 'OpenAI', factory)
    session = ModelEndpointSession(retry_limit=1, time_budget=30, call_timeout=5)
    runtime = PipelineRuntime(TX, 'eth', session=session).install()
    checkpoints = []
    runtime.checkpoint_sink = lambda report: checkpoints.append(deepcopy(report))
    try:
        analyzer = importlib.import_module('faultseeker.function_analysis.function_analyzer').FunctionAnalyzer(model=MODEL)
        analyzer.trace = [{'function': 'foo', 'address': address, 'children': []}]
        analyzer.tx_analysis = {'function_call_loc_memo': {'foo::'+address: [{'depth': [0]}]}}
        analyzer.current_task, analyzer.processing_result, analyzer.cheatsheet = {}, {}, []
        analyzer.understanding_result = 'controlled'
        analyzer.function_call_info_summary = {'function': 'foo', 'address': address}
        analyzer._update_potentially_vulnerable_function()
        assert len(requests) == 2 and session.retries_left == 0
        assert analyzer.potentially_vulnerable_functions == {} and session.failure is None
        analyzer._update_potentially_vulnerable_function()
        assert len(requests) == 3 and set(analyzer.potentially_vulnerable_functions) == {valid}
        runtime.checkpoint_analysis(analyzer, 'function')
        report = checkpoints[-1]
        assert report['analysis_status'] == 'partial'
        assert report['classification']['rule_verdict'] == 'INCONCLUSIVE'
        assert report['sections']['scoring'] == 'skipped'
        assert report['analysis_integrity']['retrieval_incomplete'] is True
        assert report['analysis_integrity']['rejected_finding_observations'][-1]['status'] == 'unresolved'
        assert 'PRIVATE_SECRET' not in json.dumps(report['analysis_integrity']['rejected_finding_observations'])
        assert set(report['potentially_vulnerable_functions']) == {valid}
        # Once consumed, response repair cannot restart the run-wide allowance.
        assert runtime.reserve_finding_repair() is False
        session.failure = ModelEndpointFailure('connection')
        with pytest.raises(ModelEndpointFailure):
            runtime.reserve_finding_repair()
    finally:
        runtime.close()
