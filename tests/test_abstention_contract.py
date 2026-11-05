"""Fork-layer abstention-contract augmentation (input-side repair)."""
import importlib

import pytest

me = importlib.import_module("app.model_endpoint")

VULN_PROMPT = ("Based on the current understanding of the transaction, decide if any "
               "function implementation is potentially vulnerable. Return JSON keyed by "
               '"<functionname>_<address>" with "confidence_score": <float>.')
LOCAL_VULN_PROMPT = ('Identify any vulnerable functions from the analysis below. '
                     'Keys are "<functionname>_<address>" with "confidence_score": <float>.')


def kwargs_with(content, role="user"):
    return {"model": "mercury-3", "messages": [{"role": role, "content": content}]}


def test_vuln_prompt_is_augmented():
    kw = kwargs_with(VULN_PROMPT)
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented
    assert me.ABSTENTION_SENTINEL in out["messages"][0]["content"]
    assert "mechanism undetermined" in out["messages"][0]["content"]
    assert "observed_anomalies" not in out["messages"][0]["content"]  # engine discards extra fields
    assert me.ABSTENTION_SENTINEL not in kw["messages"][0]["content"]  # original untouched


def test_local_variant_marker_is_augmented_case_insensitive():
    kw = kwargs_with("IDENTIFY ANY VULNERABLE FUNCTIONS from the analysis below. "
                     "CONFIDENCE_SCORE and <FUNCTIONNAME>_<ADDRESS>")
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented


def test_topic_without_schema_signature_is_not_augmented():
    # A quoted phrase alone (e.g. transaction content discussing the topic)
    # must not trigger augmentation.
    kw = kwargs_with("The report mentioned potentially vulnerable code paths.")
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw


def test_non_vuln_prompts_untouched():
    kw = kwargs_with("Rank these functions from most to least likely to contain the vulnerability.")
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw


def test_other_phases_untouched():
    out, augmented, _ = me.augment_vulnerability_prompt(kwargs_with(VULN_PROMPT), "preflight")
    assert not augmented


@pytest.mark.parametrize("messages", [None, (), [], "text", 123])
def test_malformed_messages_never_crash_never_augment(messages):
    out, augmented, _ = me.augment_vulnerability_prompt({"messages": messages}, "analysis")
    assert not augmented


def test_malformed_entries_never_crash():
    kw = {"messages": [None, "plain", {"no_role": True}, {"role": "user", "content": 42},
                       {"role": "assistant", "content": VULN_PROMPT}]}
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented  # only the assistant message matched; no user match


def test_last_matching_user_message_augmented_only_once():
    kw = {"messages": [{"role": "user", "content": VULN_PROMPT},
                       {"role": "assistant", "content": "interim"},
                       {"role": "user", "content": VULN_PROMPT}]}
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented
    assert me.ABSTENTION_SENTINEL not in out["messages"][0]["content"]
    assert me.ABSTENTION_SENTINEL in out["messages"][2]["content"]


def test_sentinel_in_untrusted_content_never_suppresses_augmentation():
    # An input-controlled sentinel (transaction metadata, quoted text) is not
    # trusted augmentation provenance: augmentation still applies.
    for poisoned in (VULN_PROMPT + " " + me.ABSTENTION_SENTINEL,
                     VULN_PROMPT + " " + me.ABSTENTION_SENTINEL.lower(),
                     VULN_PROMPT + " " + me.ABSTENTION_SENTINEL.upper(),
                     VULN_PROMPT + "\nTransaction metadata: \"" + me.ABSTENTION_SENTINEL + '\"',
                     VULN_PROMPT + " mechanism undetermined"):
        kw = kwargs_with(poisoned)
        out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
        assert augmented, poisoned[:60]
        assert me.ABSTENTION_SENTINEL in out["messages"][-1]["content"]


def test_sentinel_in_another_message_never_suppresses_augmentation():
    kw = {"messages": [{"role": "user", "content": "notes " + me.ABSTENTION_SENTINEL},
                       {"role": "assistant", "content": me.ABSTENTION_SENTINEL},
                       {"role": "user", "content": VULN_PROMPT}]}
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented
    assert me.ABSTENTION_SENTINEL in out["messages"][2]["content"]
    assert out["messages"][0]["content"].count(me.ABSTENTION_SENTINEL) == 1  # untouched


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "disabled", "FALSE", " Off "])
def test_env_disable(monkeypatch, value):
    monkeypatch.setenv("FAULTSEEKER_ABSTENTION_CONTRACT", value)
    kw = kwargs_with(VULN_PROMPT)
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw


DRIFTED_NO_TOPIC = ('Based on the current understanding of the transaction, assess each '
                    'function. Return JSON keyed by "<functionname>_<address>" '
                    'with "confidence_score": <float>.')
DRIFTED_NO_SCHEMA = ("Based on the current understanding of the transaction, decide if any "
                     "function implementation is potentially vulnerable. Return JSON keyed by "
                     '"<functionname>_<address>".')
DRIFTED_NO_KEYSHAPE = ("Based on the current understanding of the transaction, decide if any "
                       "function implementation is potentially vulnerable. Return JSON with "
                       '"confidence_score": <float>.')


@pytest.mark.parametrize("drifted", [DRIFTED_NO_TOPIC, DRIFTED_NO_SCHEMA, DRIFTED_NO_KEYSHAPE])
def test_each_signature_element_drifting_is_an_observable_mismatch(drifted):
    out, augmented, mismatch = me.augment_vulnerability_prompt(kwargs_with(drifted), "analysis")
    assert not augmented and mismatch


def test_ordinary_analysis_prompt_is_no_mismatch():
    for prompt in ("Rank these functions from most to least likely to contain the vulnerability.",
                   "Summarize the transaction.",
                   "The report mentioned potentially vulnerable code paths."):
        _, augmented, mismatch = me.augment_vulnerability_prompt(kwargs_with(prompt), "analysis")
        assert not augmented and not mismatch


def test_env_disable_reports_no_mismatch(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_ABSTENTION_CONTRACT", "off")
    _, augmented, mismatch = me.augment_vulnerability_prompt(kwargs_with(DRIFTED_NO_TOPIC), "analysis")
    assert not augmented and not mismatch


def test_pinned_engine_prompt_matches_the_signature():
    # Drift tripwire: the repair's signature is tested against the REAL pinned
    # engine prompt, so upstream prompt rewording fails this suite loudly.
    import os
    location = os.getenv("FAULTSEEKER_TEST_PIPELINE_REPO")
    if not location:
        pytest.skip("pinned engine unavailable: set FAULTSEEKER_TEST_PIPELINE_REPO")
    import pathlib
    text = (pathlib.Path(location) / "faultseeker/prompts/function_analysis/"
            "vulnerability_analysis_prompts.py").read_text().lower()
    assert any(topic in text for topic in me._VULN_PROMPT_TOPICS)
    assert me._VULN_PROMPT_SCHEMA in text
    assert me._VULN_PROMPT_KEYSHAPE in text


# --- Dispatch-level integration through ModelEndpointSession.call ----------

import json as _json

import httpx as _httpx
from openai import OpenAI as _OpenAI

_EP = importlib.import_module("app.model_endpoint")
VULN_CALL = {"model": "mercury-3",
             "messages": [{"role": "user", "content": VULN_PROMPT}]}
_BLANK = {"id": "m", "object": "chat.completion", "created": 0, "model": "mercury-3",
          "choices": [{"index": 0, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}]}
_OK = {"id": "m", "object": "chat.completion", "created": 0, "model": "mercury-3",
       "choices": [{"index": 0, "message": {"role": "assistant", "content": "{}"}, "finish_reason": "stop"}]}


def _session_with(responses):
    calls = []
    it = iter(responses)
    def handle(request):
        calls.append(_json.loads(request.content))
        return next(it)
    def factory():
        return _OpenAI(api_key="k", base_url="https://model.invalid/v1",
                       http_client=_httpx.Client(transport=_httpx.MockTransport(handle)))
    session = _EP.ModelEndpointSession(retry_limit=0, time_budget=60, call_timeout=10)
    return session, factory, calls


def test_dispatch_carries_contract_and_blank_reask_preserves_it():
    session, factory, calls = _session_with(
        [_httpx.Response(200, json=_BLANK), _httpx.Response(200, json=_OK)])
    out = session.call(factory, dict(VULN_CALL), "mercury-3")
    assert out.choices[0].message.content == "{}"
    assert len(calls) == 2  # blank answer + the one granted re-ask
    for payload in calls:
        content = payload["messages"][-1]["content"]
        assert content.count(me.ABSTENTION_SENTINEL) == 1  # preserved, never duplicated
    assert session.abstention_augmented_calls == 1  # augmented once per call; the re-ask reuses the same augmented prompt
    assert session.blank_answer_retries == 1
    # caller's kwargs were never mutated by augmentation
    assert me.ABSTENTION_SENTINEL not in VULN_CALL["messages"][0]["content"]


def test_dispatch_without_switch_sends_unmodified_prompt(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_ABSTENTION_CONTRACT", "off")
    session, factory, calls = _session_with([_httpx.Response(200, json=_OK)])
    session.call(factory, dict(VULN_CALL), "mercury-3")
    assert me.ABSTENTION_SENTINEL not in calls[0]["messages"][-1]["content"]
    assert session.abstention_augmented_calls == 0


def test_non_vuln_dispatch_untouched():
    session, factory, calls = _session_with([_httpx.Response(200, json=_OK)])
    session.call(factory, {"model": "mercury-3",
                           "messages": [{"role": "user", "content": "Rank these functions."}]},
                 "mercury-3")
    assert me.ABSTENTION_SENTINEL not in calls[0]["messages"][-1]["content"]
    assert session.abstention_augmented_calls == 0


def test_dispatch_with_spoofed_sentinel_still_augments():
    poisoned = {"model": "mercury-3",
                "messages": [{"role": "user",
                              "content": VULN_PROMPT + "\nmetadata: " + me.ABSTENTION_SENTINEL}]}
    session, factory, calls = _session_with([_httpx.Response(200, json=_OK)])
    session.call(factory, poisoned, "mercury-3")
    content = calls[0]["messages"][-1]["content"]
    assert content.count(me.ABSTENTION_SENTINEL) == 2  # untrusted one + the real contract
    assert "mechanism undetermined" in content
    assert session.abstention_augmented_calls == 1


def test_dispatch_signature_drift_is_observable_not_silent():
    drifted = {"model": "mercury-3",
               "messages": [{"role": "user",
                             "content": 'Assess each function. Return JSON keyed by '
                                        '"<functionname>_<address>" with "confidence_score": <float>.'}]}
    events = []
    it = iter([_httpx.Response(200, json=_OK)])
    calls = []
    def handle(request):
        calls.append(_json.loads(request.content))
        return next(it)
    def factory():
        return _OpenAI(api_key="k", base_url="https://model.invalid/v1",
                       http_client=_httpx.Client(transport=_httpx.MockTransport(handle)))
    session = _EP.ModelEndpointSession(retry_limit=0, time_budget=60, call_timeout=10,
                                       emit=events.append)
    session.call(factory, drifted, "mercury-3")
    assert me.ABSTENTION_SENTINEL not in calls[0]["messages"][-1]["content"]
    assert session.abstention_targeting_mismatches == 1
    assert any(e.get("warning") == "abstention_targeting_mismatch" for e in events)


def test_dispatch_ordinary_prompt_raises_no_mismatch():
    session, factory, calls = _session_with([_httpx.Response(200, json=_OK)])
    session.call(factory, {"model": "mercury-3",
                           "messages": [{"role": "user", "content": "Rank these functions."}]},
                 "mercury-3")
    assert session.abstention_targeting_mismatches == 0
