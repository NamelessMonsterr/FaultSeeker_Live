"""Audit F07: every terminal run path leaves a consistent stage / current / event state. OFFLINE."""
import pytest

from tests.test_run_lifecycle_races import make_manager
from tests.conftest import HASH, USER_KEY


def prepared(make_client):
    runs, mgr = make_manager(make_client)
    run = runs.Run(HASH, "bsc", "gpt-4o-mini", "server", "user")
    run.stages[0]["status"] = "done"
    run.stages[1]["status"] = "active"
    run.proc = type("P", (), {"returncode": 1})()
    return runs, mgr, run


def active(run):
    return [s["id"] for s in run.stages if s["status"] == "active"]


@pytest.mark.parametrize("branch,state", [("fatal", "failed"), ("timeout", "failed"), ("cancel", "cancelled"), ("shutdown", "interrupted"),
                                          ("result_missing", "failed"), ("worker_error", "failed")])
def test_no_terminal_path_leaves_an_active_stage_or_the_starting_text(make_client, branch, state):
    runs, mgr, run = prepared(make_client)
    timed_out = branch == "timeout"
    if branch == "fatal":
        run.fatal = {"code": "provider_failed", "message": "The provider failed.", "hint": "x"}
    elif branch == "cancel":
        run.cancel_requested = True
    elif branch == "shutdown":
        run.shutting_down = True
    elif branch == "result_missing":
        run.proc.returncode, run.result_ready = 0, True
        mgr.result = lambda run_id, raw=False: None
    elif branch == "worker_error":
        run.worker_error = {"type": "RuntimeError", "message": "boom"}
    mgr._decide(run, timed_out)
    assert run.state == state
    assert active(run) == [], f"{branch}: a terminal run must not keep an active stage ({active(run)})"
    assert run.current["title"] != "Starting the pipeline", f"{branch}: stale 'Starting the pipeline' text"
    if state == "failed":
        assert run.stages[1]["status"] == "failed" and run.error and run.current["description"] == run.error["message"]
    elif state in ("cancelled", "interrupted"):
        assert run.stages[1]["status"] in ("cancelled", "interrupted", "failed"), run.stages[1]
    assert run.events or branch == "shutdown", f"{branch}: a terminal event is emitted"
    assert run.stages[0]["status"] == "done", "stages that completed stay done"


def test_a_successful_completion_still_marks_every_stage_done(make_client):
    runs, mgr, run = prepared(make_client)
    run.proc.returncode, run.result_ready = 0, True
    import json
    mgr._dir(run.id).mkdir(parents=True, exist_ok=True)
    (mgr._dir(run.id) / "result.raw.json").write_text(json.dumps({"transaction_hash": HASH, "chain": "bsc", "ranked_suspicious_functions": [],
                                                                  "potentially_vulnerable_functions": {}, "transaction_understanding": ""}))
    mgr.result = lambda run_id, raw=False: json.loads((mgr._dir(run.id) / "result.raw.json").read_text())
    mgr._decide(run, False)
    assert run.state == "completed" and all(s["status"] == "done" for s in run.stages)


def test_the_documented_precedence_is_unchanged(make_client):
    runs, mgr, run = prepared(make_client)
    run.shutting_down = run.cancel_requested = True
    run.fatal = {"code": "x", "message": "m", "hint": "h"}
    mgr._decide(run, True)
    assert run.state == "interrupted", "shutdown > cancel > timeout > fatal > result"
    runs2, mgr2, run2 = prepared(make_client)
    run2.cancel_requested = True
    run2.fatal = {"code": "x", "message": "m", "hint": "h"}
    mgr2._decide(run2, True)
    assert run2.state == "cancelled"
    runs3, mgr3, run3 = prepared(make_client)
    run3.fatal = {"code": "x", "message": "m", "hint": "h"}
    mgr3._decide(run3, True)
    assert run3.state == "failed" and run3.error["code"] == "timeout"


def test_finalization_failure_also_leaves_no_active_stage(make_client):
    runs, mgr, run = prepared(make_client)
    mgr._finalization_failed(run, RuntimeError("disk full"))
    assert run.state == "failed" and active(run) == []
