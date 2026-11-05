"""Fork-layer abstention-contract augmentation (input-side repair)."""
import importlib

import pytest

me = importlib.import_module("app.model_endpoint")

VULN_PROMPT = ("Based on the current understanding of the transaction, decide if any "
               "function implementation is potentially vulnerable. Return JSON with "
               '"confidence_score": <float>.')
LOCAL_VULN_PROMPT = ('Identify any vulnerable functions from the analysis below. '
                     '"confidence_score": <float 0.0-1.0>')


def kwargs_with(content, role="user"):
    return {"model": "mercury-3", "messages": [{"role": role, "content": content}]}


def test_vuln_prompt_is_augmented():
    kw = kwargs_with(VULN_PROMPT)
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented
    assert me.ABSTENTION_SENTINEL in out["messages"][0]["content"]
    assert "mechanism undetermined" in out["messages"][0]["content"]
    assert "observed_anomalies" not in out["messages"][0]["content"]  # engine discards extra fields
    assert me.ABSTENTION_SENTINEL not in kw["messages"][0]["content"]  # original untouched


def test_local_variant_marker_is_augmented_case_insensitive():
    kw = kwargs_with("IDENTIFY ANY VULNERABLE FUNCTIONS from the analysis below. confidence_score")
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented


def test_topic_without_schema_signature_is_not_augmented():
    # A quoted phrase alone (e.g. transaction content discussing the topic)
    # must not trigger augmentation.
    kw = kwargs_with("The report mentioned potentially vulnerable code paths.")
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw


def test_non_vuln_prompts_untouched():
    kw = kwargs_with("Rank these functions from most to least likely to contain the vulnerability.")
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw


def test_other_phases_untouched():
    out, augmented = me.augment_vulnerability_prompt(kwargs_with(VULN_PROMPT), "preflight")
    assert not augmented


@pytest.mark.parametrize("messages", [None, (), [], "text", 123])
def test_malformed_messages_never_crash_never_augment(messages):
    out, augmented = me.augment_vulnerability_prompt({"messages": messages}, "analysis")
    assert not augmented


def test_malformed_entries_never_crash():
    kw = {"messages": [None, "plain", {"no_role": True}, {"role": "user", "content": 42},
                       {"role": "assistant", "content": VULN_PROMPT}]}
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented  # only the assistant message matched; no user match


def test_last_matching_user_message_augmented_only_once():
    kw = {"messages": [{"role": "user", "content": VULN_PROMPT},
                       {"role": "assistant", "content": "interim"},
                       {"role": "user", "content": VULN_PROMPT}]}
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented
    assert me.ABSTENTION_SENTINEL not in out["messages"][0]["content"]
    assert me.ABSTENTION_SENTINEL in out["messages"][2]["content"]


def test_idempotent_via_sentinel():
    kw = kwargs_with(VULN_PROMPT + " " + me.ABSTENTION_SENTINEL)
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw
    # natural-language mention alone does NOT suppress augmentation
    kw2 = kwargs_with(VULN_PROMPT + " mechanism undetermined")
    out2, augmented2 = me.augment_vulnerability_prompt(kw2, "analysis")
    assert augmented2


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "disabled", "FALSE", " Off "])
def test_env_disable(monkeypatch, value):
    monkeypatch.setenv("FAULTSEEKER_ABSTENTION_CONTRACT", value)
    kw = kwargs_with(VULN_PROMPT)
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw
