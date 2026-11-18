"""Explicit input-limit policy of the real GPTAgent client path (OFFLINE, fake transport only).

A prompt over the limit is never silently cut: it is either fitted by an explicit, reported compaction that keeps the required
identifiers/instructions/evidence head and tail, or it ends as the typed InputLimitExceeded before any request is sent.
Routing (model id), request parameters and retry limits are unchanged.
"""
import json
from types import SimpleNamespace

import pytest

try:
    import faultseeker.utils.agent as agent_module
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    from faultseeker.utils.agent import AbstractAgent, GPTAgent, ProviderFailure
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

try:
    from faultseeker.utils.agent import InputLimitExceeded
except ImportError:                                   # reported by the first test as the real failure
    InputLimitExceeded = None

LIMIT = 10_000
TAIL = "REQUIRED-TAIL-MARKER-7f3a"
A1 = "0x" + "1" * 40


class FakeClient:
    """Fake OpenAI-style transport: records the keyword arguments and messages of every request."""

    def __init__(self, *script):
        self.script, self.calls, self.kwargs = list(script) or ["{}"], [], []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, messages, model=None, **kw):
        self.calls.append([dict(m) for m in messages])
        self.kwargs.append(dict(kw, model=model))
        item = self.script[min(len(self.calls) - 1, len(self.script) - 1)]
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=item))])


def gpt(monkeypatch, *script, extra=None, mode="pass"):
    monkeypatch.setattr(agent_module, "CONTENT_RETRY_DELAYS", (0, 0))
    a = object.__new__(GPTAgent)
    AbstractAgent.__init__(a, "system prompt", "fake-model-id")
    a.resolved = SimpleNamespace(extra_params=dict(extra or {}), temperature_mode=mode, temperature_value=0.2)
    a._client = FakeClient(*script)
    return a


def sent(agent, n=0):
    return agent._client.calls[n][-1]["content"]


def test_the_limit_is_an_explicit_named_policy():
    assert GPTAgent.MAX_PROMPT_CHARS == LIMIT
    assert InputLimitExceeded is not None and issubclass(InputLimitExceeded, ProviderFailure)


def test_a_prompt_at_the_limit_is_sent_whole(monkeypatch):
    a = gpt(monkeypatch, "ok")
    prompt = "x" * (LIMIT - len(TAIL)) + TAIL
    assert len(prompt) == LIMIT and a.query_text(prompt) == "ok"
    assert sent(a) == prompt and sent(a).endswith(TAIL)


def test_a_longer_prompt_is_never_silently_cut_and_nothing_is_sent(monkeypatch):
    a = gpt(monkeypatch, "ok")
    prompt = "x" * (LIMIT + 2000) + TAIL
    with pytest.raises(InputLimitExceeded) as err:
        a.query_text(prompt)
    assert a._client.calls == [], "no request is made with a cut prompt"
    assert err.value.kind == "input_limit" and TAIL not in str(err.value) and str(len(prompt)) in str(err.value)
    assert a.memory == [{"role": "system", "content": "system prompt"}], "nothing partial is remembered"


@pytest.mark.parametrize("call", ["query_text", "query_json", "query_json_once", "query"])
def test_every_client_entry_point_obeys_the_policy(monkeypatch, call):
    a = gpt(monkeypatch, "{}")
    prompt = "y" * LIMIT + TAIL
    if call == "query":
        with pytest.raises(InputLimitExceeded):
            a._send_message_strict(prompt)
        assert a._send_message(prompt) == agent_module.PROVIDER_ERROR_TEXT, "the legacy contract still reports a failure sentinel"
    else:
        with pytest.raises(InputLimitExceeded):
            getattr(a, call)(prompt)
    assert a._client.calls == []


def test_routing_parameters_and_retry_limits_are_unchanged(monkeypatch):
    a = gpt(monkeypatch, "{}", extra={"max_tokens": 321})
    assert a.query_json_once("short") == {}
    assert len(a._client.calls) == 1, "query_json_once remains exactly one request"
    assert a._client.kwargs[0] == {"max_tokens": 321, "temperature": 0, "model": "fake-model-id"}
    assert a._client.calls[0][0] == {"role": "system", "content": "system prompt"}
    b = gpt(monkeypatch, None, None, None, "late")
    with pytest.raises(ProviderFailure):
        b.query_text("short")
    assert len(b._client.calls) == 3, "ordinary content retries keep their budget (1 + len(CONTENT_RETRY_DELAYS))"
    c = gpt(monkeypatch, None, "{}")
    assert c.query_json_once.__name__ and len(c._client.calls) == 0


def test_fit_prompt_keeps_required_parts_and_reports_the_shortening():
    from faultseeker.utils.agent import fit_prompt
    head, tail = "HEAD-INSTRUCTIONS " + A1, "TAIL-INSTRUCTIONS " + TAIL
    body = "B" * 30_000
    fitted = fit_prompt(head, [("analysis", body)], tail, limit=LIMIT)
    assert len(fitted.text) <= LIMIT and fitted.text.startswith(head) and fitted.text.endswith(tail)
    assert fitted.shortened == ["analysis"] and "characters omitted" in fitted.text
    assert fit_prompt(head, [("analysis", "short")], tail, limit=LIMIT).shortened == []
    with pytest.raises(InputLimitExceeded):
        fit_prompt("H" * LIMIT, [("a", "b")], "T", limit=LIMIT)                    # the required parts alone do not fit


def test_fit_prompt_keeps_both_ends_of_each_shortened_section_and_shares_the_budget():
    from faultseeker.utils.agent import fit_prompt
    one = "ONE-HEAD " + "1" * 20_000 + " ONE-TAIL"
    two = "TWO-HEAD " + "2" * 20_000 + " TWO-TAIL"
    fitted = fit_prompt("H", [("one", one), ("two", two)], "T", limit=LIMIT)
    for marker in ("ONE-HEAD", "ONE-TAIL", "TWO-HEAD", "TWO-TAIL"):
        assert marker in fitted.text, marker
    assert sorted(fitted.shortened) == ["one", "two"] and len(fitted.text) <= LIMIT


# ----------------------------------------------------------------------------------------- the verdict step end to end

def verdict_analyzer(monkeypatch, understanding, processing):
    from faultseeker.prompts.function_analysis import VulnerabilityAnalysisPrompts
    a = object.__new__(FunctionAnalyzer)
    a.vulnerability_prompts = VulnerabilityAnalysisPrompts()
    a.understanding_result, a.processing_result, a.cheatsheet = understanding, processing, []
    a.current_task, a.potentially_vulnerable_functions = {"task_description": "inspect"}, {}
    a.function_call_info_summary = {"function": "withdraw", "address": A1}
    a.tx_analysis = {"function_call_loc_memo": {}}
    a.evidence_gaps = {}
    client_agent = gpt(monkeypatch, json.dumps({f"withdraw_{A1}": ["Observed: " + TAIL, 0.8]}))
    a.organization_agent = client_agent
    return a, client_agent


def test_the_verdict_prompt_keeps_identifiers_and_evidence_ends_when_the_analysis_is_long(monkeypatch):
    evidence = "EVIDENCE-HEAD-MARK " + "trace line; " * 3000 + TAIL
    a, agent = verdict_analyzer(monkeypatch, "UNDERSTANDING-HEAD " + "u" * 15_000 + " UNDERSTANDING-TAIL", evidence)
    a._update_potentially_vulnerable_function()
    prompt = sent(agent)
    assert len(prompt) <= LIMIT, len(prompt)
    for required in (f"withdraw_{A1}", "RETURN CONTRACT", "EVIDENCE-HEAD-MARK", TAIL, "UNDERSTANDING-HEAD", "UNDERSTANDING-TAIL",
                     "characters omitted"):
        assert required in prompt, f"{required!r} was lost"
    assert list(a.potentially_vulnerable_functions) == [f"withdraw_{A1}"]
    gap = a.evidence_gaps.get(f"withdraw@{A1}")
    assert gap and any("model input limit" in g for g in gap), "limited coverage is recorded for the candidate"


def test_a_short_verdict_prompt_is_untouched_and_records_no_gap(monkeypatch):
    a, agent = verdict_analyzer(monkeypatch, "short understanding", "short processing")
    a._update_potentially_vulnerable_function()
    assert "characters omitted" not in sent(agent) and "short processing" in sent(agent)
    assert not a.evidence_gaps


def test_another_step_with_an_oversized_prompt_fails_closed_and_is_not_retried(monkeypatch):
    a = object.__new__(FunctionAnalyzer)
    a.function_prompts = SimpleNamespace(function_analysis_init_prompt="{task_tree}{current_understanding}{function_call_info_summary}",
                                         check_analysis_adequacy="adequacy?")
    a.function_call_info_summary, a.understanding_result = {}, "u" * 20_000
    a.reasoning_agent = gpt(monkeypatch, "tree")
    a.organization_agent = gpt(monkeypatch, "Yes")
    for field in ("task_tree", "current_task", "processing_result", "children_call_memo_single", "children_call_memo"):
        setattr(a, field, "")
    a.potentially_vulnerable_functions, a.repeated_patterns = {}, []
    a.examined_function_memo, a.attempted_function_memo, a.failed_function_memo, a.unresolved_failures, a.evidence_gaps = [], [], {}, {}, {}
    a._temp_check = lambda: False
    a._update_current_understanding = lambda **kw: None
    detail = a._run_candidate([f"withdraw@{A1}"], "withdraw")
    assert "InputLimitExceeded" in detail and a.failed_function_memo == {f"withdraw@{A1}": 1}, "terminal: one attempt, no retry"
    assert a.examined_function_memo == [] and a.reasoning_agent._client.calls == []
