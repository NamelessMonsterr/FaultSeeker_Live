"""Offline regressions for three-pillar faultseeker fixes.

Validates:
(a) Shared-budget retry recovery and explicit failure propagation on invalid completion.
(b) Checkpoint recovery and preliminary finding preservation ('unranked/unverified').
(c) Complete-input preservation without silent truncation or message dropping.
(d) Memory reset between function analyses in FunctionAnalyzer.
"""
import copy
import json
import sys
from pathlib import Path

import pytest
import httpx
from unittest.mock import MagicMock
from openai import OpenAI

from app.model_endpoint import ModelEndpointSession, ModelEndpointFailure, classify
from app.pipeline_guards import PipelineRuntime
from test_candidate_pipeline_transport import candidate


class MockClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def test_invalid_completion_shared_budget_retry_and_recovery():
    """Verify transient invalid responses consume shared retries and succeed on recovery."""
    clock = MockClock()
    calls = []
    responses = [
        httpx.Response(200, json={
            "id": "gen-1", "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": None}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        }),
        httpx.Response(200, json={
            "id": "gen-2", "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": '{"analysis": "ok"}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}
        }),
    ]
    resp_iter = iter(responses)

    def handle(req):
        calls.append(req)
        return next(resp_iter)

    def factory():
        return OpenAI(api_key="test-key", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(handle)))

    session = ModelEndpointSession(clock=clock.monotonic, sleep=clock.sleep, retry_limit=3, time_budget=300)
    result = session.call(factory, {"model": "test-model", "messages": [{"role": "user", "content": "hi"}]}, "test-model")

    assert result.choices[0].message.content == '{"analysis": "ok"}'
    assert len(calls) == 2
    assert session.retries_left == 2  # Consumed exactly 1 retry out of 3
    assert session.failure is None


def test_invalid_completion_exhaustion_propagates_explicit_failure():
    """When retries are exhausted, ModelEndpointFailure must propagate and set session.failure."""
    clock = MockClock()
    calls = []
    responses = [
        httpx.Response(200, json={
            "id": f"gen-{i}", "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "   "}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}
        }) for i in range(4)
    ]
    resp_iter = iter(responses)

    def handle(req):
        calls.append(req)
        return next(resp_iter)

    def factory():
        return OpenAI(api_key="test-key", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(handle)))

    session = ModelEndpointSession(clock=clock.monotonic, sleep=clock.sleep, retry_limit=3, time_budget=300)
    with pytest.raises(ModelEndpointFailure) as exc_info:
        session.call(factory, {"model": "test-model", "messages": [{"role": "user", "content": "hi"}]}, "test-model")

    assert exc_info.value.kind == "invalid_response"
    assert exc_info.value.completion_problem == "empty_content"
    assert len(calls) == 4
    assert session.retries_left == 0
    assert session.failure is not None
    assert session.failure.kind == "invalid_response"


def test_universal_agent_query_does_not_swallow_transport_failures(candidate):
    """UniversalAgent.query() must propagate transport exceptions rather than returning {}."""
    class FailingAgent(candidate.AbstractAgent):
        def _send_message(self, user_message: str, temperature=0) -> str:
            raise ModelEndpointFailure("invalid_response", completion_problem="non_text_content")

    agent = FailingAgent("sys_prompt", "test-model")
    with pytest.raises(ModelEndpointFailure) as exc_info:
        agent.query("test query", format="json")

    assert exc_info.value.kind == "invalid_response"


def test_incremental_checkpoints_labeled_unranked_unverified():
    """Checkpoint preliminary findings after batches and surface them labeled unranked/unverified on failure."""
    tx = "0x" + "a" * 64
    runtime = PipelineRuntime(tx, "eth")
    runtime.partial = {"transaction": {"hash": tx, "chain": "eth"}}

    mock_analyzer = MagicMock()
    mock_analyzer.potentially_vulnerable_functions = {
        "0xd341ea79_0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c": {
            "confidence_score": [0.85, 0.90],
            "evidence": ["price manipulation via curve balance inflation"],
            "depth": 2,
        },
        "0x12345678_0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef": {
            "confidence_score": [0.60],
            "evidence": ["unchecked call return"],
            "depth": 1,
        }
    }
    mock_analyzer.functions_to_be_inspected = {"func1": {"count": 1, "calls": []}}
    mock_analyzer.address_calls_with_created_contract_in_params = {}
    mock_analyzer.repeated_patterns = []

    runtime.selection_coverage.append({
        "status": "partial",
        "available": {"functions": 10, "created_contracts": 0, "patterns": 0},
        "completed": {"functions": 5, "created_contracts": 0, "patterns": 0},
        "batches_completed": 2,
    })

    preliminary = {}
    for key, val in mock_analyzer.potentially_vulnerable_functions.items():
        preliminary[key] = {
            **copy.deepcopy(val),
            "status": "unranked/unverified",
            "ranking_status": "unranked",
        }
    runtime.partial["potentially_vulnerable_functions"] = preliminary
    runtime.partial["preliminary_findings"] = [{"target": k, **v} for k, v in preliminary.items()]

    err = ModelEndpointFailure("budget_exhausted")
    report = runtime.failure_report(err)

    assert report["analysis_status"] == "partial"
    assert report["stage_completed"] == "function-analysis-partial"
    assert report["sections"]["function_analysis"] == "partial_interrupted"
    assert report["sections"]["scoring"] == "skipped"

    findings = report.get("preliminary_findings")
    assert findings is not None
    assert len(findings) == 2
    for f in findings:
        assert f["status"] == "unranked/unverified"
        assert f["ranking_status"] == "unranked"

    assert len(report["analysis_integrity"]["preliminary_findings"]) == 2
    assert report["analysis_integrity"]["selection_coverage"][0]["batches_completed"] == 2
    assert any("unranked and unverified" in lim for lim in report["limitations"])


def test_complete_input_preservation_no_truncation():
    """Verify full prompt including tail schemas is preserved without string slicing or turn dropping."""
    tx = "0x" + "a" * 64

    class MockAgent:
        def __init__(self):
            self.model = "inception/mercury-3"
            self.memory = [{"role": "system", "content": "You are a vulnerability analyst."}]

        def _truncate_history(self, history):
            return history

        def _record_router_query(self, *args, **kwargs):
            pass

    mock_agent = MockAgent()

    prompt_head = "Instructions for candidate analysis: " * 3500
    prompt_tail = "\nREQUIRED SCHEMA AT TAIL: {\"vulnerable\": bool, \"confidence\": float}"
    large_user_message = prompt_head + prompt_tail

    mock_session = MagicMock()
    mock_session.call.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content='{"vulnerable": true, "confidence": 0.9}'))],
        usage=MagicMock(prompt_tokens=100, completion_tokens=20)
    )

    runtime = PipelineRuntime(tx, "eth", session=mock_session)
    runtime.model_keys = {"inception/mercury-3": ["test-key"]}

    send_fn = runtime._legacy_shared_send(MagicMock(JSON_MODE_MODELS=[]), is_gpt=False)
    reply = send_fn(mock_agent, large_user_message)

    assert reply == '{"vulnerable": true, "confidence": 0.9}'
    call_args = mock_session.call.call_args[0]
    sent_request = call_args[1]
    sent_messages = sent_request["messages"]

    assert len(sent_messages) == 2
    assert sent_messages[0]["role"] == "system"
    assert sent_messages[1]["role"] == "user"
    assert sent_messages[1]["content"] == large_user_message
    assert prompt_tail in sent_messages[1]["content"]


def test_large_multibyte_history_rejects_complete_input_instead_of_dropping_active_query():
    from types import SimpleNamespace
    requests = []
    def reply(request):
        requests.append(request)
        return httpx.Response(200, json={'choices': [{'finish_reason': 'stop',
            'message': {'role': 'assistant', 'content': '{}'}}]})
    def factory(**kwargs):
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    agent = SimpleNamespace(model='inception/mercury-3',
        memory=[{'role': 'system', 'content': 'role'}, {'role': 'user', 'content': 'old'},
                {'role': 'assistant', 'content': '\u6f22'*100000}],
        _truncate_history=lambda messages: messages,
        _record_router_query=lambda *args, **kwargs: None)
    runtime = PipelineRuntime('0x'+'a'*64, 'eth', session=ModelEndpointSession(retry_limit=0))
    runtime._model_config = lambda model: ('https://model.invalid/v1', ['dummy-only-key'])
    module = SimpleNamespace(OpenAI=factory, JSON_MODE_MODELS=set())
    active = 'FULL_ACTIVE_REQUEST_REQUIRED_SCHEMA'
    with pytest.raises(ModelEndpointFailure) as error:
        runtime._legacy_shared_send(module, False)(agent, active)
    assert error.value.kind == 'input_budget_exceeded'
    assert requests == []
    assert agent.memory[-1] == {'role': 'user', 'content': active}


def test_function_analyzer_resets_agent_memory_across_functions(candidate):
    """FunctionAnalyzer._reset_agent_memories() must clear agent history to system prompt only."""
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    AbstractAgent = candidate.AbstractAgent
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)

    agent1 = AbstractAgent.__new__(AbstractAgent)
    agent1.memory = [
        {"role": "system", "content": "System prompt 1"},
        {"role": "user", "content": "Old function call 1"},
        {"role": "assistant", "content": "Old answer 1"},
    ]

    agent2 = AbstractAgent.__new__(AbstractAgent)
    agent2.memory = [
        {"role": "system", "content": "System prompt 2"},
        {"role": "user", "content": "Old function call 2"},
        {"role": "assistant", "content": "Old answer 2"},
    ]

    analyzer.reasoning_agent = agent1
    analyzer.generation_agent = agent2
    analyzer.processing_agent = None
    analyzer.organization_agent = None
    analyzer.children_call_filtering_agent = None

    analyzer._reset_agent_memories()

    assert len(analyzer.reasoning_agent.memory) == 1
    assert analyzer.reasoning_agent.memory[0]["role"] == "system"
    assert len(analyzer.generation_agent.memory) == 1
    assert analyzer.generation_agent.memory[0]["role"] == "system"


def test_batch_boundary_does_not_overwrite_prior_unit_observations(candidate, monkeypatch):
    from types import SimpleNamespace
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    observations = []
    target = '0x12345678_0x'+'1'*40
    def review(obj):
        evidence = 'observation '+str(len(observations))
        observations.append(evidence)
        obj.potentially_vulnerable_functions = {
            target: {'evidence': [evidence], 'confidence_score': [0.5], 'depth': 1}}
        runtime.checkpoint_analysis(obj, 'function')
    monkeypatch.setattr(FunctionAnalyzer, '_review_function_calls', review)
    runtime = PipelineRuntime('0x'+'a'*64, 'eth').install()
    runtime.selection_abi_context = lambda targets: ''
    obj = FunctionAnalyzer.__new__(FunctionAnalyzer)
    obj.functions_to_be_inspected = {f'0x{i:08x}_0x'+'1'*40: {'count': 1, 'calls': []} for i in range(26)}
    obj.repeated_patterns = []
    obj.address_calls_with_created_contract_in_params = {}
    obj.function_prompts = SimpleNamespace()
    obj.function_call_info_summary = {}
    try:
        obj._review_function_calls()
        assert len(observations) == 2
        assert runtime.failure_report()['preliminary_findings'][0]['evidence'] == observations
    finally:
        runtime.close()
