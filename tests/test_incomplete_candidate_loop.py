"""Partial progress is not completion (fail-closed, loop level).

A candidate's task loop may only mark the candidate examined when it ended with an explicit completion signal (the
adequacy check). Iteration exhaustion, or termination by an exception, stays incomplete even after earlier steps
succeeded or a finding was recorded. Incomplete candidates use the normal failure machinery (max 2 total attempts per candidate, redacted bounded detail, per-attempt mutable state rollback, cleared by a completed retry, Stage 2 raises
FunctionAnalysisIncomplete). Findings and other mutable state produced by a failed attempt must not leak into later
candidates or the final analyzer state.
OFFLINE: the model provider and Stage 1 are fakes (tests/pipeline_fakes.py); everything else is production code.
"""


import os

import pytest

try:
    from faultseeker.core.config import FaultSeekerConfig
    from faultseeker.core.pipeline import FaultSeekerPipeline
    from tests import pipeline_fakes as fakes
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

from tests.conftest import USER_KEY, start_run, wait_final

HASH = "0x" + "c1c1" + "0" * 60
ID_FOO = f"foo@{fakes.A}"
ID_BAR = f"bar@{fakes.B}"


def pipeline(tmp_path, monkeypatch, scenario):
    state = fakes.install(scenario, monkeypatch.setattr)
    monkeypatch.setenv("OPENAI_API_KEY", USER_KEY)
    return FaultSeekerPipeline(FaultSeekerConfig(cache_dir=str(tmp_path / "cache"))), state


def analyze(p):
    return p.analyze_transaction(txn_hash=HASH, chain="bsc")


def assert_no_secrets(text):
    for secret in fakes.DECOYS + [USER_KEY]:
        assert secret not in text, f"secret decoy leaked: {secret[:12]}..."


# --------------------------------------------------------------------------- A: iteration cap after one good step

def test_A_iteration_cap_after_one_successful_step_is_incomplete(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "capped")
    with pytest.raises(RuntimeError) as err:
        analyze(p)
    message = str(err.value)
    assert "Stage 2 (Function Analysis) incomplete" in message and ID_FOO in message
    assert "iteration limit" in message
    assert_no_secrets(message)
    assert state.proc_failed >= 30, "reproduction check: the provider really failed ~30 times after the one good step"
    a = p.function_analyzer
    assert a.examined_function_memo == [], "iteration exhaustion must not mark the candidate examined"
    assert list(a.unresolved_failures) == [ID_FOO]
    assert state.attempts["foo"] == 2, "bounded: the pattern pass and one retry, never a third attempt"


# --------------------------------------------------------------------------- B: a finding, then the next step raises

def test_B_exception_after_a_recorded_finding_is_incomplete(tmp_path, monkeypatch):
    # The "finding" fixture records a finding during step 1, then raises ProviderDown
    # during the next step. The failed candidate attempt must roll that finding back.
    p, state = pipeline(tmp_path, monkeypatch, "finding")
    with pytest.raises(RuntimeError) as err:
        analyze(p)

    message = str(err.value)
    assert "Stage 2 (Function Analysis) incomplete" in message and ID_FOO in message
    assert "stopped by an error" in message
    assert_no_secrets(message)

    a = p.function_analyzer
    assert a.potentially_vulnerable_functions == {}, (
        "the finding recorded during the failed attempt must be rolled back"
    )
    assert a.examined_function_memo == []
    assert list(a.unresolved_failures) == [ID_FOO]
    assert state.attempts["foo"] == 1
    assert state.proc_failed == 1, "ProviderDown is terminal; the candidate must not be retried"


# --------------------------------------------------------------------------- retry / mixed / legitimate outcomes

def test_a_completed_retry_clears_the_unresolved_failure(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "cappedretry")
    result = analyze(p)                                         # first attempt hit the cap; the retry completed
    assert result["transaction_hash"] == HASH
    a = p.function_analyzer
    assert state.attempts["foo"] == 2
    assert a.unresolved_failures == {}, "no stale failure after a completed retry"
    assert a.failed_function_memo == {ID_FOO: 1} and ID_FOO in a.examined_function_memo


def test_mixed_complete_and_incomplete_candidates_fail_the_stage_naming_only_the_incomplete_one(tmp_path, monkeypatch):
    p, state = pipeline(tmp_path, monkeypatch, "mixedcap")
    with pytest.raises(RuntimeError) as err:
        analyze(p)
    assert ID_BAR in str(err.value) and ID_FOO not in str(err.value)
    assert ID_FOO in p.function_analyzer.examined_function_memo
    assert ID_BAR not in p.function_analyzer.examined_function_memo


def test_explicit_completion_with_zero_findings_succeeds(tmp_path, monkeypatch):
    """guard: an analysis that the adequacy check completed, with nothing found, is a valid result"""
    p, state = pipeline(tmp_path, monkeypatch, "ok")
    result = analyze(p)
    a = p.function_analyzer
    assert result["potentially_vulnerable_functions"] == {} and a.unresolved_failures == {}
    assert sorted(a.examined_function_memo) == sorted([ID_FOO, ID_BAR])
    assert state.proc_failed == 0


def test_zero_eligible_candidates_still_succeeds(tmp_path, monkeypatch):
    """guard"""
    p, state = pipeline(tmp_path, monkeypatch, "zero")
    assert analyze(p)["transaction_hash"] == HASH and state.analyzed == []


# --------------------------------------------------------------------------- real worker / API / run files

def run_scenario(make_client, scenario):
    c = make_client(FAULTSEEKER_WORKER_MODULE="tests.pipeline_fake_worker")
    run_id = start_run(c, txn_hash="0x" + fakes.HASH_PREFIX[scenario] + "0" * 60)
    return c, run_id, wait_final(c, run_id, 90)["run"]


def everything_the_run_exposed(c, run_id):
    from faultseeker.server import settings
    texts = [c.get(f"/api/runs/{run_id}").text, c.get("/api/runs").text, c.get(f"/api/runs/{run_id}/result").text]
    for path in (settings.RUNS_DIR / run_id).rglob("*"):
        if path.is_file():
            texts.append(path.read_text(errors="replace"))
    return "\n".join(texts)


@pytest.mark.parametrize("scenario,reason", [("capped", "iteration limit"), ("finding", "stopped by an error")])
def test_api_mid_candidate_outage_ends_failed_and_result_is_rejected(make_client, scenario, reason):
    c, run_id, run = run_scenario(make_client, scenario)
    assert run["state"] == "failed", run
    err = run["error"]
    assert err["code"] == "analysis_incomplete" and ID_FOO in err["message"] and reason in err["message"]
    assert "provider key, quota and availability" in err["hint"]
    assert c.get(f"/api/runs/{run_id}/result").status_code in (404, 409), "no completed result for a failed run"
    from faultseeker.server import settings
    assert not (settings.RUNS_DIR / run_id / "result.json").exists()
    assert_no_secrets(everything_the_run_exposed(c, run_id))


def test_api_completed_retry_after_an_incomplete_attempt_completes(make_client):
    c, run_id, run = run_scenario(make_client, "cappedretry")
    assert run["state"] == "completed", run
    assert c.get(f"/api/runs/{run_id}/result").status_code == 200
    assert_no_secrets(everything_the_run_exposed(c, run_id))


def test_api_explicit_completion_with_no_findings_completes(make_client):
    c, run_id, run = run_scenario(make_client, "ok")
    assert run["state"] == "completed", run
    assert c.get(f"/api/runs/{run_id}/result").status_code == 200
