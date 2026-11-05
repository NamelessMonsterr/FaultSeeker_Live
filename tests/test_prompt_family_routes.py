"""Route-aware prompt-family + production dispatch tests (parent directive
2026-11-05 18:00): exercise the ACTUAL mercury-3 and itera/qwen3.8-27b
dispatch paths and BOTH prompt families - no gpt-4o stand-in.

Root cause under test: the engine's is_local_model() predates the fork's
routes, so mercury-3 and itera/qwen3.8-27b were silently classed "local"
and analyzed with the simplified weak-model prompt family; the abstention
contract (which targets the cloud template) never fired in production.
The fork's install hook now registers its routes as cloud-capable at the
authorized boundary; the pinned engine checkout is never edited.
"""
import importlib
import os
import sys

import httpx
import pytest
from openai import OpenAI

me = importlib.import_module("app.model_endpoint")
pg = importlib.import_module("app.pipeline_guards")

TX = "0x" + "ab" * 32
OK = {"id": "mock", "object": "chat.completion", "created": 0, "model": "m",
      "choices": [{"index": 0, "message": {"role": "assistant", "content": "{}"},
                   "finish_reason": "stop"}]}


def _pinned_root():
    import os
    import pathlib
    location = os.getenv("FAULTSEEKER_TEST_PIPELINE_REPO")
    assert location, "pinned engine checkout required: set FAULTSEEKER_TEST_PIPELINE_REPO"
    return pathlib.Path(location)


@pytest.fixture()
def engine_modules():
    root = str(_pinned_root())
    os.environ["OPENAI_API_KEY"] = "test-only-key"
    os.environ["INCEPTION_API_KEY"] = "test-only-mercury-key"
    os.environ["ITERA_API_KEY"] = "test-only-itera-key"
    saved = {n: sys.modules[n] for n in list(sys.modules)
             if n == "faultseeker" or n.startswith("faultseeker.")}
    for n in saved:
        del sys.modules[n]
    original_path = sys.path[:]
    sys.path.insert(0, root)
    try:
        yield
    finally:
        sys.path[:] = original_path
        for n in [n for n in list(sys.modules)
                  if n == "faultseeker" or n.startswith("faultseeker.")]:
            del sys.modules[n]
        sys.modules.update(saved)


def _installed_runtime(session=None):
    # install_model_hooks is gated on a session (production always has one);
    # a sessionless runtime would silently skip the hook boundary.
    if session is None:
        session = me.ModelEndpointSession(retry_limit=0, time_budget=60, call_timeout=10)
    agent_module = importlib.import_module("faultseeker.utils.agent")
    runtime = pg.PipelineRuntime(TX, "eth", session=session)
    runtime.install_model_hooks(agent_module)
    return runtime, agent_module


def test_hook_classes_fork_routes_cloud_and_leaves_others_unchanged(engine_modules):
    runtime, _ = _installed_runtime()
    try:
        lmp = importlib.import_module("faultseeker.prompts.local_model_prompts")
        # fork routes now cloud-capable
        assert not lmp.is_local_model("mercury-3")
        assert not lmp.is_local_model("itera/qwen3.8-27b")
        # unchanged classifications
        assert not lmp.is_local_model("gpt-4o")
        assert lmp.is_local_model("qwen3.8-27b")  # bare qwen3 lacks the engine's
        # 'qwen-' (dashed) prefix: pre-existing engine behavior, unchanged
        assert lmp.is_local_model("phi3:mini")
        assert lmp.is_local_model("deepseek-r1:14b")
        # prompt families follow the classification
        cloud = lmp.get_vuln_prompts("mercury-3").update_potentially_vulnerable_function
        assert cloud.startswith("Based on the current understanding of the transaction")
        assert lmp.get_vuln_prompts("itera/qwen3.8-27b").update_potentially_vulnerable_function \
            .startswith("Based on the current understanding of the transaction")
        local = lmp.get_vuln_prompts("phi3:mini").update_potentially_vulnerable_function
        assert local.startswith("Identify any vulnerable functions")
    finally:
        runtime.close()
    # close() restores the engine module boundary
    lmp = importlib.import_module("faultseeker.prompts.local_model_prompts")
    assert lmp.is_local_model("mercury-3")


def _drive_production_dispatch(model):
    """Real analyzer prompt construction -> real agent message build ->
    captured kwargs -> REAL session.call (mock transport). Asserts the
    abstention contract activates on the actual production dispatch shape."""
    session = me.ModelEndpointSession(retry_limit=0, time_budget=60, call_timeout=10)
    runtime, agent_module = _installed_runtime(session)
    sent = []
    def reply(request):
        sent.append(__import__("json").loads(request.content))
        return httpx.Response(200, json=OK)
    try:
        fa_mod = importlib.import_module("faultseeker.function_analysis.function_analyzer")
        analyzer = fa_mod.FunctionAnalyzer(model=model)
        # prompt family actually loaded for this route
        template = analyzer.vulnerability_prompts.update_potentially_vulnerable_function
        assert template.startswith("Based on the current understanding of the transaction"), (
            f"{model}: analyzer did not load the cloud prompt family")
        # stage 1: capture the engine-dispatched kwargs at the fork's install point
        captured = []
        class _Msg: content = "{}"
        class _Choice: message = _Msg()
        class _Completion: choices = [_Choice()]
        original_hook = agent_module._llm_call_with_retry  # session.call (installed above)
        def spy(create_client, kwargs, m):
            captured.append(dict(kwargs, messages=[dict(x) for x in kwargs["messages"]]))
            return _Completion()
        agent_module._llm_call_with_retry = spy
        try:
            analyzer.cheatsheet = []
            analyzer.understanding_result = "understanding"
            analyzer.current_task = {}
            analyzer.processing_result = {}
            analyzer.functions_to_be_inspected = {}
            analyzer.tx_analysis = {}
            analyzer.rejected_findings = []
            analyzer._update_potentially_vulnerable_function()
        finally:
            agent_module._llm_call_with_retry = original_hook
        assert captured, f"{model}: analyzer never dispatched a vuln-update call"
        kwargs = captured[-1]
        assert kwargs["messages"][-1]["role"] == "user"
        assert kwargs["messages"][-1]["content"].startswith(
            "Based on the current understanding of the transaction")
        # stage 2: the captured production-shaped kwargs through the REAL session.call
        session.register_keys("https://model.invalid/v1", ["k"], model=model)
        session.model_routes[model] = "https://model.invalid/v1"
        def factory():
            return OpenAI(api_key="test-secret-never-output",
                          base_url="https://model.invalid/v1",
                          http_client=httpx.Client(transport=httpx.MockTransport(reply)))
        original_hook(factory, kwargs, model)  # == session.call, the installed hook
        summary = session.summary()
        assert summary["abstention_augmented_calls"] == 1, (
            f"{model}: contract did not activate on the production dispatch shape")
        entry = summary["abstention_calls"][-1]
        assert entry["augmented"] is True and entry["targeting_mismatch"] is False
        assert entry["contract_in_adapted_payload"] is True
        assert me.ABSTENTION_CONTRACT.strip()[-40:] in sent[-1]["messages"][-1]["content"]
        return summary
    finally:
        runtime.close()


def test_mercury3_production_dispatch_activates_contract(engine_modules):
    _drive_production_dispatch("mercury-3")


def test_itera_qwen_production_dispatch_activates_contract(engine_modules):
    _drive_production_dispatch("itera/qwen3.8-27b")


def test_local_family_prompt_flags_mismatch_never_augmented(engine_modules):
    # The simplified weak-model family must NEVER be silently augmented:
    # prefix authority rejects it and the drift detector flags it loudly.
    runtime, _ = _installed_runtime()
    sent = []
    def reply(request):
        sent.append(__import__("json").loads(request.content))
        return httpx.Response(200, json=OK)
    try:
        lmp = importlib.import_module("faultseeker.prompts.local_model_prompts")
        local_prompt = lmp.get_vuln_prompts("phi3:mini").update_potentially_vulnerable_function
        session = me.ModelEndpointSession(retry_limit=0, time_budget=60, call_timeout=10)
        session.register_keys("https://model.invalid/v1", ["k"], model="m")
        session.model_routes["m"] = "https://model.invalid/v1"
        def factory():
            return OpenAI(api_key="test-secret-never-output",
                          base_url="https://model.invalid/v1",
                          http_client=httpx.Client(transport=httpx.MockTransport(reply)))
        session.call(factory, {"model": "m", "messages": [
            {"role": "user", "content": local_prompt.format("u", "t", "r")}]}, "m")
        summary = session.summary()
        assert summary["abstention_augmented_calls"] == 0
        assert summary["abstention_targeting_mismatches"] == 1
        assert me.ABSTENTION_CONTRACT.strip()[-40:] not in sent[-1]["messages"][-1]["content"]
    finally:
        runtime.close()
