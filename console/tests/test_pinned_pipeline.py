"""Opt-in offline integration against the exact Docker-pinned external checkout.

Set FAULTSEEKER_TEST_PIPELINE_REPO to a checkout at the pinned SHA. HTTPX model
requests are mocked; RPC responses come only from the verified trace fixture.
"""
import copy
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys

import httpx
import pytest
from openai import OpenAI

from app.model_endpoint import ModelEndpointFailure, ModelEndpointSession
from app.pipeline_guards import PipelineRuntime
from app.trace_identity import TraceIdentityError, sequence_from_parity

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/fixtures/hedgey_verified_trace.json").read_text())
TX = FIXTURE["provenance"]["transaction_hash"]
MODEL = "gpt-6.1-sol-low"
PIN = "monorepo"  # The separately pinned fork checkout no longer exists in this layout.


@pytest.fixture
def pinned(monkeypatch, tmp_path):
    pytest.skip("Retired: the old pinned-fork suite does not apply to the unified repository; "
                "pipeline integration runs through test_candidate_pipeline_transport.py")
    location = None
    saved = {name: module for name, module in sys.modules.items()
             if name == 'faultseeker' or name.startswith('faultseeker.')}
    for name in saved:
        sys.modules.pop(name)
    monkeypatch.syspath_prepend(location)
    monkeypatch.chdir(tmp_path)  # The upstream logger opens ./logs with filemode=w.
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "true")
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://model.invalid/v1")
    monkeypatch.setenv("FAULTSEEKER_LLM_FALLBACK_MODEL", "")
    def blocked(*args, **kwargs):
        raise AssertionError("Unmocked network access is forbidden")
    import urllib.request
    import requests
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(requests.sessions.Session, "request", blocked)
    try:
        loaded = importlib.import_module('faultseeker.utils.agent')
        assert Path(loaded.__file__).resolve().is_relative_to(Path(location).resolve())
        yield location
    finally:
        for name in list(sys.modules):
            if name == 'faultseeker' or name.startswith('faultseeker.'):
                sys.modules.pop(name)
        sys.modules.update(saved)


def test_real_agents_share_one_failure_budget_and_cannot_swallow_502(pinned, monkeypatch):
    agents = importlib.import_module("faultseeker.utils.agent")
    calls = []
    def factory(**kwargs):
        def reply(request):
            calls.append(json.loads(request.content))
            return httpx.Response(502, text="<html>PRIVATE_SERVER_BODY</html>")
        return OpenAI(api_key="test-only-key", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    monkeypatch.setattr(agents, "OpenAI", factory)
    session = ModelEndpointSession(retry_limit=1, sleep=lambda seconds: None)
    runtime = PipelineRuntime(TX, "eth", session=session).install()
    try:
        one = agents.GPTAgent("test", MODEL)
        two = agents.UniversalAgent("test", MODEL)
        for instance in [one, two]:
            with pytest.raises(ModelEndpointFailure) as failure:
                instance._send_message("No real provider is called")
            assert "PRIVATE_SERVER_BODY" not in str(failure.value)
        assert len(calls) == 2  # second agent does NOT start its own seven attempts
        assert all(row["model"] == MODEL for row in calls)
    finally:
        runtime.close()


def test_function_analyzer_itera_agents_use_shared_transport(pinned, monkeypatch):
    agents = importlib.import_module("faultseeker.utils.agent")
    analyzer_module = importlib.import_module("faultseeker.function_analysis.function_analyzer")
    model = "itera/qwen3.8-27b"
    monkeypatch.setenv("ITERA_API_KEY", "dummy-only-itera-key")
    calls = []
    def reply(request):
        calls.append((str(request.url), json.loads(request.content)))
        assert request.headers["authorization"] == "Bearer dummy-only-itera-key"
        return httpx.Response(200, json={"id": "offline", "object": "chat.completion", "created": 0,
            "model": model, "choices": [{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "OK"}}]})
    def factory(**kwargs):
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    monkeypatch.setattr(agents, "OpenAI", factory)
    def forbidden_local(**kwargs):
        raise AssertionError("Cloud model must not invoke local Ollama")
    monkeypatch.setattr(agents, "chat", forbidden_local)
    session = ModelEndpointSession(retry_limit=0)
    runtime = PipelineRuntime(TX, "eth", session=session).install()
    try:
        runtime.preflight([model])
        analyzer = analyzer_module.FunctionAnalyzer(model=model)
        for name in ("reasoning_agent", "generation_agent", "processing_agent",
                     "organization_agent", "children_call_filtering_agent", "agent"):
            instance = getattr(analyzer, name)
            assert isinstance(instance, agents.UniversalAgent)
            assert instance.query("Offline routing contract", format="str") == "OK"
        assert session.summary()["calls"]["analysis"]["ok"] == 6
        assert len(calls) == 7  # one preflight and all six actual analyzer agents
        assert all(url == "https://api.iteracompute.com/v1/chat/completions" for url, body in calls)
        assert all(body["model"] == "qwen/qwen3.8-27b" and body["reasoning"] is False
                   and "reasoning_effort" not in body for url, body in calls)
    finally:
        runtime.close()


def test_real_sequence_and_ranker_use_verified_calldata_not_cast_label(pinned, monkeypatch):
    seq_module = importlib.import_module("faultseeker.data_collection.txn_sequencer")
    replay_module = importlib.import_module("faultseeker.data_collection.txn_replayer")
    rpc = importlib.import_module("faultseeker.utils.rpc_provider")
    identity = sequence_from_parity(FIXTURE["responses"]["trace_transaction"], TX, "eth")
    structured = {"transaction_hash": TX, "chain": "eth", "trace": identity["canonical_trace"]}
    monkeypatch.setattr(replay_module.TransactionReplayer, "get_structured_trace", lambda *args: copy.deepcopy(structured))
    monkeypatch.setattr(replay_module.TransactionReplayer, "run", lambda *args: "untrusted decoder boundary")
    old = json.loads((ROOT / "app/samples/hedgey_e7c04c6fb037.result.json").read_text())
    legacy = copy.deepcopy(identity["trace"])
    legacy["function"] = old["scored_functions"][0]["function"]  # actual observed bad label
    monkeypatch.setattr(seq_module.TransactionSequencer, "analyze_trace", lambda *args: copy.deepcopy(legacy))
    monkeypatch.setattr(rpc, "rpc_call", lambda chain, method, params, **kwargs: "0x1" if method == "eth_chainId" else FIXTURE["responses"]["eth_getTransactionByHash"])
    runtime = PipelineRuntime(TX, "eth").install()
    try:
        sequence = seq_module.TransactionSequencer().run(TX, "eth")
        assert sequence["trace"]["function"] == "0xe32a9a37"
        assert "updateGhoBorrowRate" not in json.dumps(sequence)
        trace_module = importlib.import_module("faultseeker.forensics.trace_analyzer")
        monkeypatch.setattr(trace_module, "build_agent", lambda *args: None)  # flattening never queries this agent
        analysis = trace_module.TraceAnalyzer(sequence, {}, model="offline-no-llm").run()
        result_cls = importlib.import_module("faultseeker.forensics.result").ForensicsResult
        forensics = result_cls(transaction_hash=TX, chain="eth", functions_to_be_inspected={"function_name_with_hash": [analysis["flatten_trace"][0]]})
        ranker = importlib.import_module("faultseeker.function_analysis.function_ranker").FunctionRanker()
        ranked = ranker.rank(forensics, analysis)
        assert list(ranked.functions_to_be_inspected) == ["0xe32a9a37_0xc793113f1548b97e37c409f39244ee44241bf2b3"]
    finally:
        runtime.close()


def test_real_cache_identity_guard_rejects_wrong_chain(pinned, monkeypatch):
    replay = importlib.import_module("faultseeker.data_collection.txn_replayer").TransactionReplayer
    monkeypatch.setattr(replay, "get_structured_trace", lambda *args: {"transaction_hash": TX, "chain": "bsc", "trace": {}})
    runtime = PipelineRuntime(TX, "eth").install()
    try:
        with pytest.raises(TraceIdentityError):
            replay().get_structured_trace(TX, "eth")
    finally:
        runtime.close()


@pytest.mark.parametrize("statuses,expected", [
    ([401, 200, 200, 200], ["first", "second", "second", "second"]),
    ([403, 200, 200, 200], ["first", "second", "second", "second"]),
    ([200, 401, 200, 200], ["first", "first", "second", "second"]),
])
def test_real_agents_keep_preflight_rotation_and_rotate_mid_run(pinned, monkeypatch, statuses, expected):
    agents = importlib.import_module("faultseeker.utils.agent")
    monkeypatch.setenv("OPENAI_API_KEY", "test-first,test-second")
    calls, events = [], []
    statuses_initial = statuses
    statuses = iter(statuses)
    def factory(**kwargs):
        def reply(request):
            calls.append(request.headers["authorization"])
            status = next(statuses)
            if status != 200:
                return httpx.Response(status, text="PRIVATE_PROVIDER_BODY")
            return httpx.Response(200, json={"id": "offline", "object": "chat.completion", "created": 0,
                "model": MODEL, "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "OK"}}]})
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    monkeypatch.setattr(agents, "OpenAI", factory)
    session = ModelEndpointSession(retry_limit=2, emit=events.append)
    runtime = PipelineRuntime(TX, "eth", session=session).install()
    try:
        runtime.preflight([MODEL])
        for agent_class in (agents.GPTAgent, agents.UniversalAgent):
            assert agent_class("offline", MODEL)._send_message("Mocked request") == "OK"
        assert calls == ["Bearer test-"+key for key in expected]
        assert session.retries_left == (1 if statuses_initial[0] == 200 else 2)
        assert session.failure is None
        assert "test-first" not in json.dumps(events)
        assert "PRIVATE_PROVIDER_BODY" not in json.dumps(events)
    finally:
        runtime.close()

@pytest.mark.parametrize("phase,retry_after", [
    ("preflight", "1"),
    ("preflight", "99999"),
    ("analysis", "1"),
    ("analysis", "99999"),
])
def test_real_agents_stop_on_429_without_rotation_or_retry(pinned, monkeypatch, phase, retry_after):
    agents = importlib.import_module("faultseeker.utils.agent")
    monkeypatch.setenv("OPENAI_API_KEY", "test-first,test-second")
    calls, events = [], []
    statuses = iter([429, 200] if phase == "preflight" else [200, 429, 200])
    def factory(**kwargs):
        def reply(request):
            calls.append(request.headers["authorization"])
            status = next(statuses, 200)
            if status != 200:
                return httpx.Response(status, headers={"Retry-After": retry_after}, text="PRIVATE_PROVIDER_BODY")
            return httpx.Response(200, json={"id": "offline", "object": "chat.completion", "created": 0,
                "model": MODEL, "choices": [{"index": 0, "finish_reason": "stop",
                "message": {"role": "assistant", "content": "OK"}}]})
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    monkeypatch.setattr(agents, "OpenAI", factory)
    session = ModelEndpointSession(retry_limit=2, emit=events.append)
    runtime = PipelineRuntime(TX, "eth", session=session).install()
    try:
        if phase == "preflight":
            with pytest.raises(ModelEndpointFailure) as failure:
                runtime.preflight([MODEL])
        else:
            runtime.preflight([MODEL])
            with pytest.raises(ModelEndpointFailure) as failure:
                agents.GPTAgent("offline", MODEL)._send_message("Mocked request")
        assert failure.value.kind == "rate_limited"
        assert failure.value.phase == phase
        assert len(calls) == (1 if phase == "preflight" else 2)
        assert calls == ["Bearer test-first"] * len(calls)
        assert session.retries_left == 2
        assert not any(event.get("key_rotation") for event in events)
        assert not any(event.get("retry_in_seconds", 0) > 0 for event in events)
        assert "PRIVATE_PROVIDER_BODY" not in json.dumps(events)
        with pytest.raises(ModelEndpointFailure) as sticky:
            agents.GPTAgent("offline", MODEL)._send_message("Must not issue another request")
        assert sticky.value.kind == "rate_limited"
        assert len(calls) == (1 if phase == "preflight" else 2)
    finally:
        runtime.close()


def test_verified_abi_context_reaches_real_function_summary(pinned, monkeypatch):
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


def test_selection_batches_preserve_rare_candidates_patterns_and_results(pinned, monkeypatch):
    from types import SimpleNamespace
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    seen = []
    def review(obj):
        seen.append((list(obj.functions_to_be_inspected), list(obj.repeated_patterns),
                     list(obj.address_calls_with_created_contract_in_params)))
        for value in obj.functions_to_be_inspected.values():
            value['analysis_result'] = {'observed': True}
    monkeypatch.setattr(FunctionAnalyzer, '_review_function_calls', review)
    runtime = PipelineRuntime(TX, 'eth').install()
    runtime.selection_abi_context = lambda targets: ''
    funcs = {f'0x{i:08x}_0x' + '1'*40: {'count': 200-i, 'calls': [{'params': 'x'*1800}]*3}
             for i in range(145)}
    patterns = [{'pattern_id': i} for i in range(12)]
    created = {str(i): {'count': 1, 'calls': []} for i in range(12)}
    obj = FunctionAnalyzer.__new__(FunctionAnalyzer)
    obj.functions_to_be_inspected, obj.repeated_patterns = funcs, patterns
    obj.address_calls_with_created_contract_in_params = created
    obj.function_prompts = SimpleNamespace()
    try:
        obj._review_function_calls()
        assert [key for batch, _, _ in seen for key in batch] == list(funcs)
        assert [p for _, batch, _ in seen for p in batch] == patterns
        assert [key for _, _, batch in seen for key in batch] == list(created)
        assert all(value.get('analysis_result') for value in funcs.values())
        assert obj.functions_to_be_inspected is funcs
        assert obj.repeated_patterns is patterns
        assert obj.address_calls_with_created_contract_in_params is created
        assert runtime.selection_coverage[-1]['status'] == 'completed'
        assert runtime.selection_coverage[-1]['completed']['functions'] == 145
        import json
        assert all(len(json.dumps({k: {'count_of_appearance': funcs[k]['count'],
                         'example_calls': funcs[k]['calls'][:3]} for k in batch}).encode()) <= 16000
                   for batch, _, _ in seen)
    finally:
        runtime.close()


def test_selection_batch_failure_restores_inputs_and_records_partial_coverage(pinned, monkeypatch):
    from types import SimpleNamespace
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    calls = []
    def review(obj):
        calls.append(list(obj.functions_to_be_inspected))
        if len(calls) == 2:
            raise RuntimeError('offline simulated interruption')
    monkeypatch.setattr(FunctionAnalyzer, '_review_function_calls', review)
    runtime = PipelineRuntime(TX, 'eth').install()
    runtime.selection_abi_context = lambda targets: ''
    funcs = {f'0x{i:08x}_0x' + '1'*40: {'count': 1, 'calls': []} for i in range(60)}
    obj = FunctionAnalyzer.__new__(FunctionAnalyzer)
    obj.functions_to_be_inspected = funcs
    obj.repeated_patterns = []
    obj.address_calls_with_created_contract_in_params = {}
    obj.function_prompts = SimpleNamespace()
    try:
        with pytest.raises(RuntimeError, match='offline simulated'):
            obj._review_function_calls()
        assert obj.functions_to_be_inspected is funcs
        coverage = runtime.selection_coverage[-1]
        assert coverage['status'] == 'partial'
        assert coverage['available']['functions'] == 60
        assert coverage['completed']['functions'] == 25
        assert runtime.failure_report()['analysis_integrity']['selection_coverage'] == runtime.selection_coverage
    finally:
        runtime.close()


def test_batched_selection_uses_real_pinned_review_and_keeps_last_rare_target(pinned, monkeypatch):
    from types import SimpleNamespace
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    monkeypatch.setenv('FAULTSEEKER_STAGE2_WORKERS', '1')
    monkeypatch.setenv('FAULTSEEKER_MAX_FUNCTIONS', '0')
    monkeypatch.setattr(FunctionAnalyzer, '__init__', lambda self, **kwargs: None)
    monkeypatch.setattr(FunctionAnalyzer, '_prepare_children_call_memo', lambda *args: None)
    monkeypatch.setattr(FunctionAnalyzer, '_retrieve_related_info', lambda *args: {})
    monkeypatch.setattr(FunctionAnalyzer, '_retrieve_chidlren_calls_memo_single', lambda *args: None)
    monkeypatch.setattr(FunctionAnalyzer, 'select_high_appearance_count_children_calls', lambda *args: {})
    analysed = []
    def analyse(obj):
        analysed.append(obj.function_call_info_summary['function'])
        obj.task_tree = obj.understanding_result = ''
        obj.potentially_vulnerable_functions = {}
    monkeypatch.setattr(FunctionAnalyzer, '_function_analysis_init', analyse)
    obj = FunctionAnalyzer.__new__(FunctionAnalyzer)
    funcs = {f'0x{i:08x}_0x'+'1'*40: {'count': 200-i, 'calls': []} for i in range(145)}
    obj.functions_to_be_inspected = funcs
    obj.address_calls_with_created_contract_in_params = {}
    obj.repeated_patterns = []
    obj.function_prompts = SimpleNamespace(narrow_down_functions='{function_call_to_be_inspected}')
    obj.fundflow_analysis = {'balance_change': {}}
    obj.txn_analyzer_model, obj.router, obj.cost_tracker = 'offline', None, None
    obj.children_call_memo, obj.children_call_memo_single = {}, {}
    reviewed = []
    def select(prompt):
        import json
        candidates = json.loads(prompt)
        reviewed.extend(candidates)
        return [next(reversed(candidates))]
    obj.agent = SimpleNamespace(query=select)
    runtime = PipelineRuntime(TX, 'eth').install()
    runtime.selection_abi_context = lambda targets: ''
    try:
        obj._review_function_calls()
        assert reviewed == list(funcs)
        assert analysed[-1] == '0x00000090'
        assert funcs[next(reversed(funcs))]['analysis_result']['function_call_info_summary']['function'] == '0x00000090'
        assert len(analysed) == 6
    finally:
        runtime.close()


def test_oversized_single_selection_candidate_fails_without_dropping_evidence(pinned, monkeypatch):
    from types import SimpleNamespace
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    seen = []
    monkeypatch.setattr(FunctionAnalyzer, '_review_function_calls', lambda obj: seen.append(True))
    runtime = PipelineRuntime(TX, 'eth').install()
    obj = FunctionAnalyzer.__new__(FunctionAnalyzer)
    funcs = {'0x12345678_0x'+'1'*40: {'count': 1, 'calls': [{'params': 'x'*17000}]}}
    obj.functions_to_be_inspected = funcs
    obj.address_calls_with_created_contract_in_params = {}
    obj.repeated_patterns = []
    obj.function_prompts = SimpleNamespace()
    try:
        with pytest.raises(ModelEndpointFailure) as error:
            obj._review_function_calls()
        assert error.value.kind == 'input_budget_exceeded'
        assert not seen
        assert obj.functions_to_be_inspected is funcs
        assert runtime.selection_coverage[-1]['completed']['functions'] == 0
        assert runtime.selection_coverage[-1]['status'] == 'partial'
    finally:
        runtime.close()


def test_function_selection_receives_verified_interface_facts(pinned, monkeypatch):
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


def exercise_interrupted_function_checkpoint(monkeypatch, tmp_path):
    """Real upstream review loop: one complete function, then a mid-batch failure."""
    from types import SimpleNamespace
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    monkeypatch.setenv('FAULTSEEKER_STAGE2_WORKERS', '1')
    monkeypatch.setenv('FAULTSEEKER_MAX_FUNCTIONS', '0')
    monkeypatch.setattr(FunctionAnalyzer, '__init__', lambda self, **kwargs: None)
    for name in ('_prepare_children_call_memo', '_retrieve_chidlren_calls_memo_single'):
        monkeypatch.setattr(FunctionAnalyzer, name, lambda *args: None)
    monkeypatch.setattr(FunctionAnalyzer, '_retrieve_related_info', lambda *args: {})
    monkeypatch.setattr(FunctionAnalyzer, 'select_high_appearance_count_children_calls', lambda *args: {})
    target = '0x12345678_0x' + '1'*40
    calls = []
    def analyse(obj):
        calls.append(obj.function_call_info_summary['function'])
        if len(calls) == 2:
            raise ModelEndpointFailure('invalid_response', completion_problem='non_text_content')
        obj.task_tree = obj.understanding_result = ''
        obj.potentially_vulnerable_functions = {
            target: {'evidence': ['offline test observation SECRET_FOR_TEST'], 'confidence_score': [0.6], 'depth': 1}}
    monkeypatch.setattr(FunctionAnalyzer, '_function_analysis_init', analyse)
    runtime = PipelineRuntime(TX, 'eth').install()
    runtime.selection_abi_context = lambda targets: ''
    from app import server
    from app.analysis_checkpoint import recover_checkpoint
    monkeypatch.setattr(server, 'RUNS_DIR', str(tmp_path))
    server._configure_analysis_checkpoint(runtime, 'checkpointcase', ['SECRET_FOR_TEST'])
    persist = runtime.checkpoint_sink
    saved = []
    def save(report):
        persist(report)
        saved.append(report)
    runtime.checkpoint_sink = save
    obj = FunctionAnalyzer.__new__(FunctionAnalyzer)
    obj.functions_to_be_inspected = {target: {'count': 1, 'calls': []},
        '0x87654321_0x'+'2'*40: {'count': 1, 'calls': []}}
    obj.address_calls_with_created_contract_in_params = {}
    obj.repeated_patterns = []
    obj.function_prompts = SimpleNamespace()
    obj.txn_analyzer_model, obj.router, obj.cost_tracker = 'offline', None, None
    obj.children_call_memo, obj.children_call_memo_single = {}, {}
    try:
        with pytest.raises(ModelEndpointFailure):
            obj._review_function_calls()
        assert len(calls) == 2
        assert saved, 'Completed function was not checkpointed before the next failed'
        report = runtime.failure_report(ModelEndpointFailure('invalid_response'))
        assert report['analysis_status'] == 'partial'
        assert report['sections']['scoring'] == 'skipped'
        assert report['preliminary_findings'][0]['target'] == target
        assert report['preliminary_findings'][0]['status'] == 'unranked/unverified'
        assert report['analysis_integrity']['selection_coverage'][0]['batches_completed'] == 0
        assert len(report['analysis_integrity']['completed_analysis_units']) == 1
        assert saved[0]['preliminary_findings'][0]['target'] == target
        assert not report.get('scored_functions')
        assert 'SECRET_FOR_TEST' not in (tmp_path/'checkpointcase.checkpoint.json').read_text()
        assert recover_checkpoint(tmp_path, 'checkpointcase')
        recovered = json.loads((tmp_path/'checkpointcase.json').read_text())
        assert recovered['preliminary_findings'][0]['target'] == target
        assert recovered['analysis_status'] == 'partial'
        assert recovered['failure']['kind'] == 'interrupted'
    finally:
        runtime.close()


def test_real_pinned_review_checkpoints_before_mid_batch_failure(pinned, monkeypatch, tmp_path):
    exercise_interrupted_function_checkpoint(monkeypatch, tmp_path)


def test_pinned_retrieval_has_same_unavailable_evidence_contract(pinned):
    from test_candidate_pipeline_transport import exercise_unavailable_retrieval_contract
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    assert not hasattr(FunctionAnalyzer, '_resolve_trace_node')
    exercise_unavailable_retrieval_contract()
    assert not hasattr(FunctionAnalyzer, '_resolve_trace_node'), 'Temporary pin hooks leaked after close'


@pytest.mark.parametrize('choice', [
    {'index': 0, 'finish_reason': 'stop', 'message': {'role': 'user', 'content': '{}'}},
    {'index': 0, 'finish_reason': 'stop', 'message': None},
])
def test_pinned_agent_cannot_swallow_nonretryable_invalid_completion(pinned, monkeypatch, choice):
    agents = importlib.import_module('faultseeker.utils.agent')
    calls = []
    def reply(request):
        calls.append(True)
        return httpx.Response(200, json={'id': 'offline', 'object': 'chat.completion', 'created': 0,
            'model': 'mercury-3', 'choices': [choice]})
    def factory(**kwargs):
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    monkeypatch.setattr(agents, 'OpenAI', factory)
    monkeypatch.setenv('INCEPTION_API_KEY', 'dummy-only-key')
    monkeypatch.setenv('INCEPTION_BASE_URL', 'https://model.invalid/v1')
    session = ModelEndpointSession(retry_limit=3, sleep=lambda _: None)
    runtime = PipelineRuntime(TX, 'eth', session=session).install()
    try:
        agent = agents.UniversalAgent('offline role', 'inception/mercury-3')
        with pytest.raises(ModelEndpointFailure) as error:
            agent.query('Return a valid finding object')
        assert error.value.kind == 'invalid_response'
        assert session.failure is error.value
        assert len(calls) == 1
        with pytest.raises(ModelEndpointFailure):
            agent.query('Do not turn the prior failure into empty success')
        assert len(calls) == 1
    finally:
        runtime.close()


@pytest.mark.parametrize("model", ["inception/mercury-3", "itera/qwen3.8-27b"])
def test_pinned_mercury_preserves_complete_structured_prompt(pinned, monkeypatch, model):
    candidate=importlib.import_module("faultseeker.utils.agent")
    monkeypatch.setenv('INCEPTION_API_KEY','dummy-inception-key')
    monkeypatch.setenv('ITERA_API_KEY','dummy-itera-key')
    monkeypatch.setenv('ITERA_BASE_URL','https://itera-fixture.invalid/v1')
    seen=[]
    def respond(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200,json={'id':'mock','object':'chat.completion','created':0,'model':json.loads(request.content)['model'],
            'choices':[{'index':0,'finish_reason':'stop','message':{'role':'assistant','content':'OK'}}]})
    monkeypatch.setattr(candidate,'OpenAI',lambda **kwargs:OpenAI(**kwargs,http_client=httpx.Client(transport=httpx.MockTransport(respond))))
    runtime=PipelineRuntime("0x"+"a"*64,'eth',session=ModelEndpointSession(retry_limit=0)).install()
    try:
        agent=candidate.UniversalAgent('',model)
        prompt='{"data":"'+'x'*11000+'","required_tail":true}'
        agent._send_message(prompt)
        assert seen[0]['messages'][-1]['content']==prompt
        agent._memory_max_pairs=1
        agent._send_message(prompt,force_json=False)
        agent._send_message(prompt,force_json=False)
        assert len(agent.memory)<=3
    finally:runtime.close()


def test_detailed_worker_receives_verified_child_interface_context(pinned):
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


def test_verified_source_is_retrieved_for_canonical_selector(pinned):
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
def test_runtime_repairs_pinned_history_pairs_and_restores_method(pinned):
    from faultseeker.utils import agent
    original = agent.UniversalAgent._truncate_history
    runtime = PipelineRuntime(TX, 'eth', session=ModelEndpointSession()).install()
    try:
        instance = agent.UniversalAgent.__new__(agent.UniversalAgent)
        history = [{'role': 'system', 'content': 'dummy'}]
        for i in range(4):
            history.extend([{'role': 'user', 'content': str(i)}, {'role': 'assistant', 'content': str(i)}])
        history.append({'role': 'user', 'content': 'pending'})
        result = instance._truncate_history(history)
        assert [row['role'] for row in result] == ['system', 'user', 'assistant', 'user']
        assert result[-1]['content'] == 'pending'
    finally:
        runtime.close()
    assert agent.UniversalAgent._truncate_history is original
