import importlib
import os
import re
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPO = os.environ.get("FAULTSEEKER_TEST_PIPELINE_REPO", "")
PIN = "fb57c3fad63784b7a63dc7fdf1845364c76ce0b7"
wg = importlib.import_module("app.function_wall_guard")


def _fork_src():
    p = Path(REPO) / "faultseeker/function_analysis/function_analyzer.py"
    if not REPO or not p.exists():
        pytest.skip("pinned pipeline checkout required: set FAULTSEEKER_TEST_PIPELINE_REPO")
    return p.read_text()


def test_constants_pinned_to_fork_source():
    src = _fork_src()
    assert set(re.findall(r"MAX_FUNCTION_SECS\s*=\s*(\d+)", src)) == {str(wg.FORK_FUNCTION_WALL_CAP_SECS)}
    prefixes = re.findall(r"is_cloud = any\(self\.txn_analyzer_model\.startswith\(p\)\s*for p in \((.*?)\)\)", src, re.S)
    assert len(prefixes) == 2
    for blob in prefixes:
        assert tuple(re.findall(r"'([^']+)'", blob)) == wg.FORK_CLOUD_PREFIXES
    assert "max_iterations = 3 if is_cloud else 8" in src and "txn_iters = 2 if is_cloud else 3" in src


@pytest.mark.parametrize("exit_,cycles,wall,mono,expect", [
    ("adequate", 1, 900, 900, ("normal", "adequate")),
    (None, 3, 100, 100, ("normal", "iteration_ceiling")),
    (None, 2, 100, 100, ("unknown_exit", None)),        # under cap but no positive exit: never inferred normal
    (None, 0, 5, 5, ("unknown_exit", None)),            # e.g. two empty selections
    (None, 1, 481, 10, ("likely_forced", None)),        # fork clock saw the cap, monotonic did not
    (None, 1, 10, 481, ("likely_forced", None)),
])
def test_classify_never_infers_normal_from_elapsed(exit_, cycles, wall, mono, expect):
    assert wg.classify(exit_, cycles, 3, wall, mono) == expect


class _Org:
    def __init__(self, answers):
        self.answers = list(answers)
    def query(self, prompt, **k):
        return self.answers.pop(0) if self.answers else "No"


def _real_fork_run(monkeypatch, *, select, advance, answers=("No",), model="gpt-6.1-sol-low", kind="function", raises=False):
    """Drive the REAL pinned FunctionAnalyzer loop with stubbed model-dependent steps and a controllable fork clock."""
    _fork_src()
    sys.path[:0] = [REPO]
    fa_mod = importlib.import_module("faultseeker.function_analysis.function_analyzer")
    FA = fa_mod.FunctionAnalyzer
    clock = [1000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    fa = object.__new__(FA)
    prompts = SimpleNamespace(function_analysis_init_prompt="{task_tree}{current_understanding}{function_call_info_summary}",
                              check_analysis_adequacy="ADEQ?", check_analysis_adequacy_alt="ADEQ-ALT?")
    fa.function_prompts = prompts
    fa.txn_analyzer_model = model
    fa.function_call_info_summary = {"function": "0xaa", "address": "0xbb"}
    fa.understanding_result = "u"
    fa.reasoning_agent = SimpleNamespace(query=lambda *a, **k: "tree")
    fa.organization_agent = _Org(answers)
    fa.potentially_vulnerable_functions = {}
    fa._temp_check = lambda: False
    fa._update_current_understanding = lambda is_init=False: None
    fa._update_task_tree = lambda: None
    seq = list(select)
    def sel():
        return seq.pop(0) if seq else "t"
    fa._select_task = sel
    def perform():
        clock[0] += advance
        if raises:
            raise RuntimeError("x")
    fa._perform_task = perform
    ledger = wg.WallCapLedger()
    monkeypatch.setattr(FA, "_update_potentially_vulnerable_function", ledger.wrap_update(lambda self: None))
    name = "_function_analysis_init" if kind == "function" else "_txn_analysis_init"
    monkeypatch.setattr(FA, name, ledger.wrap(getattr(FA, name), kind))
    getattr(fa, name)()
    return ledger.summary(), fa


def test_real_loop_forced_wall_exit_is_labelled(monkeypatch):
    s, _ = _real_fork_run(monkeypatch, select=["t"] * 5, advance=300)   # iteration 1 done at 300s, iteration 2 at 600s, iteration 3 starts over the cap
    assert (s["normal"], s["likely_forced"]) == (0, 1)
    assert s["functions"][0]["completed_cycles"] == 2


def test_real_loop_ceiling_is_positive_normal(monkeypatch):
    s, _ = _real_fork_run(monkeypatch, select=["t"] * 5, advance=10)
    f = s["functions"][0]
    assert (f["outcome"], f["detail"], f["completed_cycles"]) == ("normal", "iteration_ceiling", 3)


def test_real_loop_adequacy_yes_is_positive_normal_even_over_cap(monkeypatch):
    s, fa = _real_fork_run(monkeypatch, select=["t"] * 5, advance=300, answers=("Yes.",))
    f = s["functions"][0]
    assert (f["outcome"], f["detail"]) == ("normal", "adequate")
    assert "query" not in vars(fa.organization_agent)         # per-function hook restored


def test_real_loop_empty_selection_skip_is_not_normal(monkeypatch):
    s, _ = _real_fork_run(monkeypatch, select=["", ""], advance=1)
    f = s["functions"][0]
    assert f["outcome"] == "unknown_exit" and f["completed_cycles"] == 0


def test_real_loop_exception_cycles_are_not_completed_cycles(monkeypatch):
    s, _ = _real_fork_run(monkeypatch, select=["t"] * 5, advance=1, raises=True)
    f = s["functions"][0]
    assert f["completed_cycles"] == 0 and f["outcome"] == "unknown_exit"


def test_real_txn_loop_ceiling_normal_and_wrong_prompt_ignored(monkeypatch):
    s, _ = _real_fork_run(monkeypatch, select=["t"] * 3, advance=10, kind="transaction")
    f = s["functions"][0]
    assert (f["outcome"], f["completed_cycles"], f["ceiling"]) == ("normal", 2, 2)


def test_exception_propagates_and_is_recorded_as_error():
    ledger = wg.WallCapLedger()
    class A:
        function_call_info_summary = {"function": "f", "address": "a"}
        def init(self):
            raise ValueError("model failed")
    A.init = ledger.wrap(A.init, "function")
    with pytest.raises(ValueError):
        A().init()
    s = ledger.summary()
    assert s["error"] == 1 and not ledger.active


def test_concurrent_functions_keep_isolated_state():
    import threading
    ledger = wg.WallCapLedger()
    class A:
        def __init__(self, n):
            self.n = n
            self.function_call_info_summary = {"function": f"f{n}", "address": "a"}
            self.txn_analyzer_model = "gpt-x"
            self.function_prompts = SimpleNamespace(check_analysis_adequacy="ADEQ?")
            self.organization_agent = _Org(["Yes" if n % 2 == 0 else "No"])
        def _update_potentially_vulnerable_function(self):
            pass
        def init(self):
            self.organization_agent.query("ADEQ? ..")
            time.sleep(0.01)
    A._update_potentially_vulnerable_function = ledger.wrap_update(A._update_potentially_vulnerable_function)
    A.init = ledger.wrap(A.init, "function")
    ts = [threading.Thread(target=A(n).init) for n in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    s = ledger.summary()
    assert s["normal"] == 4 and s["unknown_exit"] == 4 and not ledger.active


def _annotate(records, scored=False):
    m = importlib.import_module("app.pipeline_guards")
    identity = importlib.import_module("app.trace_identity")
    import json
    fx = json.loads((ROOT / "tests/fixtures/hedgey_verified_trace.json").read_text())
    tx = fx["provenance"]["transaction_hash"]
    runtime = m.PipelineRuntime(tx, "eth")
    runtime.sequence = identity.sequence_from_parity(fx["responses"]["trace_transaction"], tx, "eth")
    runtime.function_analysis = {"started": len(records), "completed": len(records)}
    for r in records:
        runtime.wall_cap.add(r)
    runtime.session = SimpleNamespace(summary=lambda: {"calls": {"preflight": {"ok": 1}, "analysis": {"ok": 9, "failed": 0}}, "tokens": {}},
                                      assert_healthy=lambda: None)
    base = {"transaction_hash": tx, "chain": "eth", "analysis_status": "completed"}   # no limitations key on purpose
    if scored:
        base["scored_functions"] = [{"function": "0xaa", "address": "0xbb"}]
    return runtime.annotate_result(base)


@pytest.mark.parametrize("outcome,section", [("likely_forced", "partial_wall_cap"), ("unknown_exit", "partial_unverified_exit"), ("error", "partial_errors")])
def test_any_non_normal_function_forces_partial_with_exact_counts(outcome, section):
    r = _annotate([{"kind": "function", "function": "a", "outcome": "normal"}, {"kind": "function", "function": "b", "outcome": outcome}])
    assert r["analysis_status"] == "partial"
    assert r["stage_completed"] == "function-analysis-partial"
    assert r["sections"]["function_analysis"] == section and r["sections"]["scoring"] == "not_validated"
    assert r["priority_basis"] == "heuristic_preanalysis_estimate"
    w = r["analysis_integrity"]["function_wall_cap"]
    assert w["normal"] == 1 and w[outcome] == 1
    assert any("ended normally" in x for x in r["limitations"])


def test_all_normal_stays_completed():
    r = _annotate([{"kind": "function", "function": "a", "outcome": "normal"}])
    assert r["analysis_status"] == "completed"
