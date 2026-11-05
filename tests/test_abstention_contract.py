"""Fork-layer abstention-contract augmentation (input-side repair)."""
import importlib
import os

import pytest

me = importlib.import_module("app.model_endpoint")


def kwargs_with(content, role="user"):
    return {"model": "mercury-3", "messages": [{"role": role, "content": content}]}


def test_vuln_prompt_is_augmented():
    kw = kwargs_with("Based on the current understanding of the transaction, decide if any function implementation is potentially vulnerable.")
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented
    assert "mechanism undetermined" in out["messages"][0]["content"]
    assert "observed_anomalies" in out["messages"][0]["content"]
    # original untouched
    assert "mechanism undetermined" not in kw["messages"][0]["content"]


def test_local_variant_marker_is_augmented():
    kw = kwargs_with("Identify any vulnerable functions from the analysis below.")
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented and "mechanism undetermined" in out["messages"][0]["content"]


def test_non_vuln_prompts_untouched():
    kw = kwargs_with("Rank these functions from most to least likely to contain the vulnerability.")
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw


def test_other_phases_untouched():
    kw = kwargs_with("decide if any function implementation is potentially vulnerable.")
    out, augmented = me.augment_vulnerability_prompt(kw, "preflight")
    assert not augmented and out is kw


def test_idempotent_no_double_augmentation():
    kw = kwargs_with("decide if any function implementation is potentially vulnerable. mechanism undetermined")
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw


def test_env_disable(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_ABSTENTION_CONTRACT", "0")
    kw = kwargs_with("decide if any function implementation is potentially vulnerable.")
    out, augmented = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw
