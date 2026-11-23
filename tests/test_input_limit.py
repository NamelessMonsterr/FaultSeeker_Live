"""Model/provider-aware input budgeting (OFFLINE: fake transports and fake models only; no provider or RPC request).

Replaces the old universal 10,000-character cap. The BEGO swap request (10,237 characters) is reproduced under a restrictive and under
a genuinely sufficient configured budget. Budget units are estimated tokens (see faultseeker/budget.py), never characters.
"""
import json
import math
import os
from types import SimpleNamespace

import pytest

try:
    import faultseeker.utils.agent as agent_module
    from faultseeker import budget as B
    from faultseeker.function_analysis.function_analyzer import CandidateIncomplete, FunctionAnalyzer
    from faultseeker.providers import ProviderConfigError, load_registry
    from faultseeker.prompts.function_analysis import VulnerabilityAnalysisPrompts, WorkerPrompts
    from faultseeker.utils.agent import AbstractAgent, GPTAgent, InputLimitExceeded, OllmaAgent, ProviderFailure
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

TAIL = "REQUIRED-TAIL-MARKER-7f3a"
A1 = "0x" + "1" * 40
BEGO_SIZE = 10_237


class FakeClient:
    def __init__(self, *script):
        self.script, self.calls, self.kwargs = list(script) or ["{}"], [], []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, messages, model=None, **kw):
        self.calls.append([dict(m) for m in messages])
        self.kwargs.append(dict(kw, model=model))
        item = self.script[min(len(self.calls) - 1, len(self.script) - 1)]
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=item))])


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setattr(agent_module, "CONTENT_RETRY_DELAYS", (0, 0))
    for name in list(os.environ):
        if name.startswith("FAULTSEEKER_CONTEXT_TOKENS") or name.startswith("FAULTSEEKER_OUTPUT_RESERVE") or name.startswith("FAULTSEEKER_BYTES_PER") \
                or name == "FAULTSEEKER_DEFAULT_CONTEXT_TOKENS":
            monkeypatch.delenv(name)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-" + "x" * 30)
    monkeypatch.setenv("MERCURY_API_KEY", "m-test-" + "x" * 30)
    monkeypatch.setenv("MERCURY_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("MERCURY_MODEL", "some-unlisted-model")


def gpt(model_id="gpt-4o-mini", *script, system="system prompt"):
    agent = GPTAgent(system, load_registry().resolve(model_id))
    agent._client = FakeClient(*script)
    return agent


def sent(agent, n=0):
    return agent._client.calls[n][-1]["content"]


def bego_prompt():
    return "x" * (BEGO_SIZE - len(TAIL)) + TAIL


# ------------------------------------------------------------------------------------------------ the BEGO-sized request

def test_the_10237_character_request_fails_closed_under_a_restrictive_budget(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "4096")
    monkeypatch.setenv("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", "512")
    a = gpt("gpt-4o-mini", "ok")
    prompt = bego_prompt()
    assert len(prompt) == BEGO_SIZE
    with pytest.raises(InputLimitExceeded) as err:
        a.query_text(prompt)
    assert a._client.calls == [], "nothing is sent"
    d = err.value.detail
    assert d["input_limit_tokens"] == 4096 - 512 - 256 and d["needed_tokens"] > d["input_limit_tokens"]
    assert d["budget"]["sources"]["context_tokens"].startswith("env FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI")
    assert "estimated tokens" in d["budget"]["unit"] and TAIL not in str(err.value)
    assert a.memory == [{"role": "system", "content": "system prompt"}]


def test_the_same_request_is_sent_whole_under_a_sufficient_configured_budget(monkeypatch):
    a = gpt("gpt-4o-mini", "ok")                 # registry: 128,000 context, 16,384 max output (documented)
    prompt = bego_prompt()
    assert a.query_text(prompt) == "ok"
    assert sent(a) == prompt and len(sent(a)) == BEGO_SIZE and sent(a).endswith(TAIL)


def test_a_model_without_a_verified_limit_uses_a_conservative_fallback_and_an_override_lifts_it(monkeypatch):
    a = gpt("mercury", "ok")                     # model id from the environment: no registry limits
    b = a.budget
    assert b.context_tokens == 8192 and b.sources["context_tokens"].startswith("built-in conservative fallback")
    with pytest.raises(InputLimitExceeded):
        a.query_text(bego_prompt())
    monkeypatch.setenv("FAULTSEEKER_CONTEXT_TOKENS_MERCURY", "128000")
    monkeypatch.setenv("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_MERCURY", "8192")
    a = gpt("mercury", "ok")
    assert a.budget.sources["context_tokens"].startswith("env FAULTSEEKER_CONTEXT_TOKENS_MERCURY")
    assert a.query_text(bego_prompt()) == "ok" and sent(a) == bego_prompt()


# ------------------------------------------------------------------------------------------------ configuration and precedence

def resolve(model_id="gpt-4o-mini", **env):
    return load_registry().resolve(model_id, {**{k: v for k, v in os.environ.items()}, **env}).budget


def test_documented_registry_limits_and_their_sources():
    reg = load_registry()
    expected = {"gpt-4o-mini": (128_000, 16_384), "gpt-4o": (128_000, 16_384), "gpt-4.1-mini": (1_047_576, 32_768), "gpt-4.1": (1_047_576, 32_768)}
    for model_id, (ctx, out) in expected.items():
        spec = reg.find(model_id)
        assert spec.limits["context_tokens"] == ctx and spec.limits["max_output_tokens"] == out
        assert spec.limits["source"].startswith("https://developers.openai.com/api/docs/models/") and spec.limits["verified"]
        b = reg.resolve(model_id, os.environ).budget
        assert b.context_tokens == ctx and b.output_reserve_tokens == out and b.bytes_per_token == 1.0
    for model_id in ("codex-proxy", "mercury"):
        assert reg.find(model_id).limits is None, "an environment-chosen model has no verifiable limit"


def test_budget_precedence_override_over_registry_over_default_over_fallback():
    assert resolve("gpt-4o-mini").context_tokens == 128_000                                            # registry
    assert resolve("gpt-4o-mini", FAULTSEEKER_DEFAULT_CONTEXT_TOKENS="50000").context_tokens == 128_000  # default never beats the registry
    b = resolve("gpt-4o-mini", FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI="64000")                        # per-model override beats the registry
    assert b.context_tokens == 64_000 and b.sources["context_tokens"].startswith("env FAULTSEEKER_CONTEXT_TOKENS_")
    assert resolve("mercury", FAULTSEEKER_DEFAULT_CONTEXT_TOKENS="50000").context_tokens == 50_000   # default applies to unlisted models
    assert resolve("mercury", FAULTSEEKER_DEFAULT_CONTEXT_TOKENS="50000", FAULTSEEKER_CONTEXT_TOKENS_MERCURY="20000").context_tokens == 20_000
    assert resolve("mercury").context_tokens == 8192                                                   # built-in fallback
    assert resolve("gpt-4o-mini", FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI="2000").output_reserve_tokens == 2000
    assert resolve("gpt-4o-mini", FAULTSEEKER_BYTES_PER_TOKEN_GPT_4O_MINI="3.5").bytes_per_token == 3.5


def test_the_output_reserve_follows_what_the_request_actually_sends(monkeypatch):
    reg = load_registry()
    spec = reg.find("gpt-4o-mini")
    from faultseeker.budget import resolve_budget
    b = resolve_budget("gpt-4o-mini", spec.limits, "openai_compatible", {"max_tokens": 1000}, {})
    assert b.output_reserve_tokens == 1000 and "request sends" in b.sources["output_reserve_tokens"]
    with pytest.raises(B.BudgetConfigError):
        resolve_budget("gpt-4o-mini", spec.limits, "openai_compatible", {"max_tokens": 1000}, {"FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI": "500"})


@pytest.mark.parametrize("name,value", [
    ("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "abc"), ("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "0"), ("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "-5"),
    ("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "12.5"), ("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "512"),
    ("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "99999999999"), ("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", "x"),
    ("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", "0"), ("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", "200000"),
    ("FAULTSEEKER_BYTES_PER_TOKEN_GPT_4O_MINI", "0.5"), ("FAULTSEEKER_BYTES_PER_TOKEN_GPT_4O_MINI", "nan"), ("FAULTSEEKER_BYTES_PER_TOKEN_GPT_4O_MINI", "inf"),
    ("FAULTSEEKER_BYTES_PER_TOKEN_GPT_4O_MINI", "9"), ("FAULTSEEKER_DEFAULT_CONTEXT_TOKENS", "tiny")])
def test_invalid_overrides_are_rejected_not_clamped(name, value):
    environ = {**os.environ, name: value}
    model = "mercury" if name == "FAULTSEEKER_DEFAULT_CONTEXT_TOKENS" else "gpt-4o-mini"
    with pytest.raises(ProviderConfigError) as err:
        load_registry().resolve(model, environ)
    assert "token" in str(err.value).lower() or "number" in str(err.value).lower()


def test_an_override_that_leaves_no_usable_input_is_rejected():
    with pytest.raises(ProviderConfigError, match="no usable input"):
        resolve("gpt-4o-mini", FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI="2000")        # reserve 16,384 > context


@pytest.mark.parametrize("limits", [{"context_tokens": "big"}, {"context_tokens": 100}, {"context_tokens": 5000, "max_output_tokens": 5000},
                                    {"max_output_tokens": 10}, {"context_tokens": 5000, "bytes_per_token": 0.2}, {"context_tokens": 5000, "bogus": 1}, "x"])
def test_invalid_registry_limits_blocks_are_rejected(tmp_path, limits):
    from faultseeker.providers import DEFAULT_MODELS_FILE
    cfg = json.load(open(DEFAULT_MODELS_FILE))
    for m in cfg["models"]:
        if m["id"] == "gpt-4o-mini":
            m["limits"] = limits
    path = tmp_path / "models.json"
    path.write_text(json.dumps(cfg))
    with pytest.raises(ProviderConfigError):
        from faultseeker.providers import Registry
        Registry.load(path, os.environ)


def test_an_unknown_model_is_a_conservative_fallback_for_each_provider_type():
    ollama = load_registry().resolve("ollama:llama3", {"OLLAMA_HOST": "http://127.0.0.1:1", "FAULTSEEKER_OLLAMA_MODELS": "llama3"}).budget
    assert ollama.context_tokens == 4096 and ollama.output_reserve_tokens == 1024
    assert resolve("mercury").context_tokens == 8192 and resolve("mercury").output_reserve_tokens == 2048


# ------------------------------------------------------------------------------------------------ enforcement on every request path

@pytest.mark.parametrize("call", ["query_text", "query_json", "query_json_once", "legacy"])
def test_every_client_entry_point_obeys_the_budget(monkeypatch, call):
    monkeypatch.setenv("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "4096")
    monkeypatch.setenv("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", "512")
    a = gpt("gpt-4o-mini", "{}")
    prompt = "y" * 5000
    if call == "legacy":
        assert a._send_message(prompt) == agent_module.PROVIDER_ERROR_TEXT
        with pytest.raises(InputLimitExceeded):
            a._send_message_strict(prompt)
    else:
        with pytest.raises(InputLimitExceeded):
            getattr(a, call)(prompt)
    assert a._client.calls == []


def test_a_request_just_inside_the_budget_is_sent_and_one_byte_over_is_not(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "4096")
    monkeypatch.setenv("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", "512")
    a = gpt("gpt-4o-mini", "ok")
    room = a.input_room_bytes()
    assert room == 4096 - 512 - 256 - 16 * 2 - len("system prompt")          # system + new message overhead and the system text
    assert a.query_text("z" * room) == "ok"
    b = gpt("gpt-4o-mini", "ok")
    with pytest.raises(InputLimitExceeded):
        b.query_text("z" * (room + 1))
    assert b._client.calls == []


def test_multibyte_text_is_counted_in_bytes_not_characters(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "4096")
    monkeypatch.setenv("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", "512")
    a = gpt("gpt-4o-mini", "ok")
    room = a.input_room_bytes()
    text = "é" * (room // 2 + 10)                        # fewer characters than room, more bytes than room
    assert len(text) < room < len(text.encode())
    with pytest.raises(InputLimitExceeded):
        a.query_text(text)


def test_the_system_message_the_retained_history_and_tool_messages_all_count(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "4096")
    monkeypatch.setenv("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", "512")
    short = "short question"
    assert gpt("gpt-4o-mini", "ok").query_text(short) == "ok"
    big_system = gpt("gpt-4o-mini", "ok", system="s" * 3300)
    with pytest.raises(InputLimitExceeded):
        big_system.query_text(short)
    a = gpt("gpt-4o-mini", "ok")
    a.memory.extend([{"role": "user", "content": "u" * 100}, {"role": "assistant", "content": "a" * 3400}])
    with pytest.raises(InputLimitExceeded) as err:
        a.query_text(short)
    assert err.value.detail["needed_tokens"] > err.value.detail["input_limit_tokens"]
    t = gpt("gpt-4o-mini", "ok")
    t.memory.extend([{"role": "assistant", "content": "calling"}, {"role": "tool", "content": "t" * 3400}])
    with pytest.raises(InputLimitExceeded):
        t.query_text(short)
    assert big_system._client.calls == [] and a._client.calls == [] and t._client.calls == []


def test_the_output_allowance_is_part_of_the_budget(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "4096")
    monkeypatch.setenv("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", "512")
    small = gpt("gpt-4o-mini", "ok").input_room_bytes()
    monkeypatch.setenv("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", "2048")
    large_reserve = gpt("gpt-4o-mini", "ok").input_room_bytes()
    assert small - large_reserve == 2048 - 512


def test_bytes_per_token_calibration_widens_the_room_by_exactly_that_ratio(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", "4096")
    monkeypatch.setenv("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", "512")
    base = gpt("gpt-4o-mini").input_room_bytes()
    monkeypatch.setenv("FAULTSEEKER_BYTES_PER_TOKEN_GPT_4O_MINI", "2.0")
    assert abs(gpt("gpt-4o-mini").input_room_bytes() - 2 * (base + 13) + 13) <= 40


def test_routing_parameters_and_retry_limits_are_unchanged(monkeypatch):
    a = gpt("gpt-4o-mini", "{}")
    assert a.query_json_once("short") == {}
    assert len(a._client.calls) == 1, "query_json_once remains exactly one request"
    assert a._client.kwargs[0]["model"] == "gpt-4o-mini" and a._client.kwargs[0]["temperature"] == 0
    assert a._client.calls[0][0] == {"role": "system", "content": "system prompt"}
    b = gpt("gpt-4o-mini", None, None, None, "late")
    with pytest.raises(ProviderFailure):
        b.query_text("short")
    assert len(b._client.calls) == 3, "ordinary content retries keep their budget (1 + len(CONTENT_RETRY_DELAYS))"


def test_the_ollama_path_is_budgeted_states_its_window_and_sends_only_retained_history(monkeypatch):
    calls = []

    def fake_chat(model, messages, options):
        calls.append({"model": model, "messages": list(messages), "options": dict(options)})
        return {"message": {"content": "ok"}}
    monkeypatch.setattr(agent_module, "chat", fake_chat)
    budget = load_registry().resolve("ollama:llama3", {"OLLAMA_HOST": "http://127.0.0.1:1", "FAULTSEEKER_OLLAMA_MODELS": "llama3"}).budget
    a = OllmaAgent("sys", "llama3", budget=budget)
    assert a.query_text("hello") == "ok" and calls[0]["options"]["num_ctx"] == 4096
    a.query_text("second")
    a.query_text("third")
    assert len(calls[-1]["messages"]) == 3, "system + the last assistant reply + the new user message, as for the other providers"
    with pytest.raises(InputLimitExceeded):
        a.query_text("q" * 3000)
    assert len(calls) == 3
    legacy = OllmaAgent("sys", "llama3")                     # direct construction without a budget keeps the old behaviour
    legacy.query_text("a")
    legacy.query_text("b")
    assert len(calls[-1]["messages"]) == 4 and "num_ctx" not in calls[-1]["options"]


# ------------------------------------------------------------------------------------------------ the reduction policy

def parts(history=2000, context=2000, source=2000, trace=2000):
    return [B.Part("instructions", "I" * 300), B.Part("history", "h" * history, "history"), B.Part("context", "c" * context, "context"),
            B.Part("source", "s" * source, "source"), B.Part("trace", "t" * trace, "trace"), B.Part("contract", "TAIL" * 25)]


def kept(fitted, section):
    return next((r for r in fitted.reductions if r["section"] == section), None)


def test_reduction_order_is_history_then_context_then_source_then_trace():
    total = sum(len(p.text) for p in parts())
    one = B.fit_parts(parts(), total - 500)
    assert [r["tier"] for r in one.reductions] == ["history"], "a small excess touches only the least valuable tier"
    two = B.fit_parts(parts(), total - 3000)
    assert {r["tier"] for r in two.reductions} == {"history", "context"} and kept(two, "history")["action"] == "omitted"
    three = B.fit_parts(parts(), total - 5500)
    assert {r["tier"] for r in three.reductions} == {"history", "context", "source"}
    assert kept(three, "history")["action"] == kept(three, "context")["action"] == "omitted"
    four = B.fit_parts(parts(), total - 7500)
    assert {r["tier"] for r in four.reductions} == {"history", "context", "source", "trace"}
    for fitted, room in ((one, total - 500), (two, total - 3000), (three, total - 5500), (four, total - 7500)):
        assert len(fitted.text.encode()) <= room


def test_required_text_is_never_reduced_and_reductions_keep_head_tail_and_a_marker():
    total = sum(len(p.text) for p in parts())
    fitted = B.fit_parts(parts(), total - 700)
    assert "I" * 300 in fitted.text and "TAIL" * 25 in fitted.text
    r = kept(fitted, "history")
    assert r["action"] == "shortened" and 0 < r["kept_bytes"] < r["original_bytes"] == 2000
    assert "bytes omitted" in fitted.text and fitted.text.count("h") > 100            # head and tail survive around the marker


def test_a_request_that_fits_is_not_touched_and_reports_nothing():
    fitted = B.fit_parts(parts(), 100_000)
    assert fitted.reductions == [] and "omitted" not in fitted.text


def test_when_the_required_text_alone_exceeds_the_budget_it_fails_closed():
    with pytest.raises(B.BudgetExceeded) as err:
        B.fit_parts(parts(), 400)
    assert err.value.detail["required_bytes"] == 300 + 100 and err.value.detail["room_bytes"] == 400
    a = gpt("gpt-4o-mini", "ok")
    monkey = a.budget
    a.budget = B.resolve_budget("gpt-4o-mini", {"context_tokens": 2048, "max_output_tokens": 256}, "openai_compatible", {}, {})
    required_only = [B.Part("instructions", "I" * 3000), B.Part("evidence", "e" * 9000, "trace")]
    with pytest.raises(InputLimitExceeded) as err2:
        a.fit(required_only)
    assert "required part" in str(err2.value) and err2.value.detail["required_bytes"] == 3000
    assert a._client.calls == []


# ------------------------------------------------------------------------------------------------ analyzer: reduced evidence, no false negatives

def analyzer(agent, summary=None, task=None, understanding="UNDERSTANDING " * 30, processing="PROCESSING-RESULT " * 20):
    a = object.__new__(FunctionAnalyzer)
    a.vulnerability_prompts, a.function_prompts = VulnerabilityAnalysisPrompts(), WorkerPrompts()
    a.understanding_result, a.processing_result, a.cheatsheet = understanding, processing, []
    a.current_task = task or {"task_description": "Inspect withdraw for a missing balance update",
                              "additional_information": {"function_call": "TRACE-CALL " * 40, "source_code": "contract Vault {" + "x" * 800 + "}",
                                                         "children_calls": "CHILD " * 100, "balance_change": "BAL " * 100}}
    a.potentially_vulnerable_functions, a.evidence_gaps, a.verdict_rejections, a.reduction_log = {}, {}, {}, {}
    a.function_call_info_summary = summary or {"function": "withdraw", "address": A1, "calls": ["c"] * 5}
    a.organization_agent = agent
    a.tx_analysis = {"function_call_loc_memo": {}}
    a._current_identities = [f"withdraw@{A1}"]
    return a


def verdict_agent(monkeypatch, budget_ctx, reserve):
    monkeypatch.setenv("FAULTSEEKER_CONTEXT_TOKENS_GPT_4O_MINI", str(budget_ctx))
    monkeypatch.setenv("FAULTSEEKER_OUTPUT_RESERVE_TOKENS_GPT_4O_MINI", str(reserve))
    return gpt("gpt-4o-mini", json.dumps({f"withdraw_{A1}": ["Observed: " + TAIL, 0.8]}))


def test_oversized_verdict_evidence_keeps_required_text_discloses_reductions_and_is_never_clean(monkeypatch):
    agent = verdict_agent(monkeypatch, 9000, 600)
    a = analyzer(agent, understanding="U-HEAD " + "u" * 9000 + " U-TAIL", processing="P-HEAD " + "p" * 9000 + " " + TAIL)
    a._update_potentially_vulnerable_function()
    prompt = sent(agent)
    assert agent.budget.message_tokens(agent._client.calls[0]) <= agent.budget.input_limit_tokens
    for required in (f"withdraw_{A1}", "RETURN CONTRACT", "Inspect withdraw for a missing balance update", "Analysis result of current task:"):
        assert required in prompt, f"required text {required!r} was lost"
    log = a.reduction_log[f"withdraw@{A1}"]
    assert log and all(r["step"] == "verdict" for r in log) and all(r["kept_bytes"] < r["original_bytes"] for r in log)
    tiers = [r["tier"] for r in log]
    assert "history" in tiers, "the least valuable tier is reduced first"
    assert list(a.potentially_vulnerable_functions) == [f"withdraw_{A1}"]
    a._record_evidence_gaps = FunctionAnalyzer._record_evidence_gaps.__get__(a)
    a.function_call_info_summary = {"function": "withdraw", "address": A1}
    a._record_evidence_gaps()
    assert "evidence reduced to fit the model input budget" in a.evidence_gaps[f"withdraw@{A1}"]


def test_reduced_evidence_with_no_finding_is_not_reported_as_clean():
    from faultseeker.server import results
    raw = {"transaction_hash": "0x" + "1" * 64, "chain": "bsc", "ranked_suspicious_functions": [], "potentially_vulnerable_functions": {},
           "transaction_understanding": "t",
           "coverage": {"status": "complete", "limited": False, "evidence_limited": True, "reduced_count": 1, "source_missing_count": 0,
                        "candidates": 1, "selected": 1, "analyzed": 1, "omitted": [], "failed": [], "selection_rejected": 0,
                        "selection_replies_ignored": 0},
           "evidence_gaps": {f"withdraw@{A1}": ["evidence reduced to fit the model input budget"]},
           "function_results": [{"identity": f"withdraw@{A1}", "function": "withdraw", "address": A1, "execution": "completed",
                                 "evidence": "reduced", "reductions": [{"step": "verdict", "section": "analysis result", "tier": "trace",
                                                                       "action": "shortened", "original_bytes": 9000, "kept_bytes": 3000}]}]}
    out = results.normalize(raw)
    text = " ".join(out["warnings"])
    assert "not a clean result" in text and "reduced to fit the model input budget" in text and "not evidence that they are safe" in text
    assert "No potentially vulnerable functions were identified for this transaction." not in out["warnings"]
    assert out["coverage"]["status"] == "complete" and out["coverage"]["evidence_limited"] is True, "execution and evidence are separate axes"
    f = out["functions"][0]
    assert f["execution"] == "completed" and f["evidence"] == "reduced" and f["reductions"][0]["kept_bytes"] == 3000


def test_essential_content_alone_over_budget_fails_the_step_closed_without_a_verdict(monkeypatch):
    agent = verdict_agent(monkeypatch, 2048, 256)
    a = analyzer(agent)
    with pytest.raises(InputLimitExceeded) as err:
        a._update_potentially_vulnerable_function()
    assert "required part" in str(err.value) and agent._client.calls == []
    assert a.potentially_vulnerable_functions == {}


def test_a_candidate_whose_required_content_does_not_fit_is_a_recorded_failure_not_a_clean_pass(monkeypatch):
    agent = verdict_agent(monkeypatch, 2048, 256)
    a = analyzer(agent)
    a.function_prompts = SimpleNamespace(function_analysis_init_prompt="{task_tree}{current_understanding}{function_call_info_summary}",
                                         check_analysis_adequacy="adequacy?")
    a.reasoning_agent = agent
    for field in ("task_tree", "children_call_memo_single", "children_call_memo"):
        setattr(a, field, "")
    a.repeated_patterns = []
    a.examined_function_memo, a.attempted_function_memo, a.failed_function_memo, a.unresolved_failures = [], [], {}, {}
    a._temp_check = lambda: False
    a._update_current_understanding = lambda **kw: None
    a.function_call_info_summary = {"function": "withdraw", "address": A1, "note": "N" * 6000}
    detail = a._run_candidate([f"withdraw@{A1}"], "withdraw")
    assert "InputLimitExceeded" in detail and a.unresolved_failures and a.examined_function_memo == []
    assert agent._client.calls == [], "nothing was sent"


def test_reductions_are_recorded_per_step_with_original_and_kept_sizes_and_roll_back_with_a_failed_attempt(monkeypatch):
    a = analyzer(gpt("gpt-4o-mini"))
    a._note_reductions("verdict", [{"section": "x", "tier": "history", "original_bytes": 100, "kept_bytes": 40, "action": "shortened"}])
    a._note_reductions("verdict", [{"section": "x", "tier": "history", "original_bytes": 100, "kept_bytes": 10, "action": "shortened"}])
    assert a.reduction_log[f"withdraw@{A1}"] == [{"section": "x", "tier": "history", "original_bytes": 100, "kept_bytes": 10,
                                                 "action": "shortened", "step": "verdict"}], "the worst reduction per step and section is kept"
    for field in ("task_tree", "children_call_memo_single", "children_call_memo", "repeated_patterns"):
        setattr(a, field, [] if field == "repeated_patterns" else "")
    state = a._capture_candidate_attempt_state()
    a.reduction_log = {"other": [1]}
    a._restore_candidate_attempt_state(state)
    assert list(a.reduction_log) == [f"withdraw@{A1}"]


def test_the_prompts_of_every_analysis_step_respect_the_budget_or_fail_closed(monkeypatch):
    """Each fitted request site under a restrictive budget: the transport never sees more than the budget allows."""
    tight = verdict_agent(monkeypatch, 6000, 600)
    a = analyzer(tight, understanding="U" * 4000, processing="P" * 4000)
    a.task_tree = "T" * 4000
    a.generation_agent = a.processing_agent = a.reasoning_agent = tight
    a.task_prompts = SimpleNamespace(update_task_tree="{task_tree}{current_understanding}{task_completed}")
    a.function_prompts = SimpleNamespace(function_call_organization_function_call="Organize:{function_call_info_summary}",
                                         function_call_info_processing="Process:{selected_task}",
                                         function_call_task_selection="Select:{task_tree}{function_call_info_summary}{current_understanding}",
                                         retrieve_additional_info="Retrieve.", check_analysis_adequacy="adequacy?")
    a.function_call_info_summary = {"function": "withdraw", "address": A1, "calls": ["c" * 500] * 8, "function_source_code": "s" * 4000,
                                    "related_balance_change": "b" * 3000}
    steps = {"understanding": lambda: a._fit_prompt(tight, a._template_parts(a.function_prompts.function_call_organization_function_call,
                                                                           {"function_call_info_summary": a._dict_parts(a.function_call_info_summary, "e")}), "understanding"),
             "processing": lambda: a._fit_prompt(tight, a._template_parts(a.function_prompts.function_call_info_processing,
                                                                          {"selected_task": a._dict_parts(a.current_task, "t")}), "processing"),
             "selection": lambda: a._fit_prompt(tight, a._template_parts(a.function_prompts.function_call_task_selection, {
                 "task_tree": (a.task_tree, "history"), "function_call_info_summary": a._dict_parts(a.function_call_info_summary, "e", fmt="repr"),
                 "current_understanding": (a.understanding_result, "history")}), "selection")}
    for name, build in steps.items():
        text = build()
        assert len(text.encode()) <= tight.input_room_bytes(), name
        assert "withdraw" in text or "Inspect withdraw" in text, f"{name}: identity/task preserved"
    assert a.reduction_log[f"withdraw@{A1}"], "the reductions that were needed are recorded"
    assert {r["step"] for r in a.reduction_log[f"withdraw@{A1}"]} <= {"understanding", "processing", "selection"}
    with pytest.raises(InputLimitExceeded):
        a._fit_prompt(tight, [B.Part("instructions", "I" * 6000), B.Part("evidence", "e" * 100, "trace")], "processing")


# ------------------------------------------------------------------------------------------------ coverage and per-function propagation

def test_function_results_and_coverage_separate_execution_from_evidence():
    from tests.test_function_analysis_state import analyzer as make_analyzer, entry
    keys = {f"f{i}_{'0x' + 'aa' * 20}": entry() for i in range(3)}
    a = make_analyzer(inspected=keys)
    a.reduction_log = {}
    a._review_function_calls()
    ids = sorted(a.examined_function_memo)
    a.reduction_log = {ids[0]: [{"step": "verdict", "section": "s", "tier": "trace", "original_bytes": 9, "kept_bytes": 3, "action": "shortened"}]}
    a.evidence_gaps = {ids[1]: ["no function source code"], ids[0]: ["evidence reduced to fit the model input budget"]}
    a._compute_coverage(list(keys), [])
    cov = a.coverage_report()
    assert cov["status"] == "complete" and cov["limited"] is False, "execution completed"
    assert cov["evidence_limited"] is True and cov["reduced_count"] == 1 and cov["source_missing_count"] == 1
    by = {f["identity"]: f for f in a.function_results()}
    assert by[ids[0]]["execution"] == "completed" and by[ids[0]]["evidence"] == "reduced" and by[ids[0]]["reductions"][0]["kept_bytes"] == 3
    assert by[ids[1]]["evidence"] == "source_missing" and by[ids[2]]["evidence"] == "complete"
    json.dumps(a.function_results())


def test_the_pipeline_result_carries_function_results_and_the_report_lists_them(tmp_path, monkeypatch):
    from faultseeker.core.config import FaultSeekerConfig
    from faultseeker.core.pipeline import FaultSeekerPipeline
    from faultseeker.server import results
    from tests import pipeline_fakes as fakes
    from tests.conftest import USER_KEY
    fakes.install("ok", monkeypatch.setattr)
    monkeypatch.setenv("OPENAI_API_KEY", USER_KEY)
    raw = FaultSeekerPipeline(FaultSeekerConfig(cache_dir=str(tmp_path / "cache"))).analyze_transaction(txn_hash="0x" + "c5c5" + "0" * 60, chain="bsc")
    assert raw["function_results"] and {f["execution"] for f in raw["function_results"]} == {"completed"}
    out = results.normalize(raw)
    assert [f["execution"] for f in out["functions"]] == ["completed"] * len(raw["function_results"])
    assert out["coverage"]["evidence_limited"] in (True, False)


def test_the_report_sanitizes_per_function_records():
    from faultseeker.server import results
    base = {"transaction_hash": "0x" + "1" * 64, "chain": "eth", "ranked_suspicious_functions": [], "potentially_vulnerable_functions": {},
            "transaction_understanding": ""}
    bad = [None, 5, {"execution": "weird", "evidence": "complete", "function": "f", "address": A1}, {"execution": "completed", "evidence": "complete"},
           {"execution": "failed", "evidence": "not_analyzed", "function": "ok", "address": A1, "failure": "x" * 5000,
            "reductions": [{"step": "s", "section": "c", "tier": "t", "action": "weird", "original_bytes": "NaN", "kept_bytes": -3}, 7]}]
    out = results.normalize(dict(base, function_results=bad))
    assert len(out["functions"]) == 1 and out["functions"][0]["function"] == "ok"
    assert len(out["functions"][0]["failure"]) <= 241 and out["functions"][0]["reductions"][0]["original_bytes"] == 0
    assert results.normalize(dict(base, function_results="junk"))["functions"] == []


def test_an_input_budget_refusal_at_the_adequacy_check_is_named_as_such_not_as_a_provider_failure(monkeypatch):
    agent = verdict_agent(monkeypatch, 2048, 256)
    a = object.__new__(FunctionAnalyzer)
    a.function_prompts = SimpleNamespace(function_analysis_init_prompt="init", check_analysis_adequacy="A" * 6000)    # required text over the budget
    a.function_call_info_summary, a.understanding_result = {}, "U" * 6000
    a.reasoning_agent = agent
    a.organization_agent = agent
    a.potentially_vulnerable_functions = {}
    a._temp_check = lambda: False
    a._update_current_understanding = lambda **kw: None
    a._select_task = a._perform_task = a._update_task_tree = a._update_potentially_vulnerable_function = lambda: None
    with pytest.raises(CandidateIncomplete) as err:
        a._function_analysis_init()
    assert "input budget" in str(err.value) and "not a provider outage" in str(err.value) and err.value.retryable is False
    assert len(agent._client.calls) == 1, "only the (fitting) init request was sent; the oversized adequacy check was not"
