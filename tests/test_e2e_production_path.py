"""End-to-end OFFLINE regression over the REAL production selection path:
canonical trace -> forensics admission (orchestrator's own check_* functions,
fed by the REAL AddressClassifier.run) -> hooked ranker (recall repair, prune,
ordering, annotation via PipelineRuntime.install) -> the REAL narrow-down
serializer (FunctionAnalyzer._review_function_calls, not a reconstructed
payload). LLM boundaries are stubbed at agent.query; everything else is the
production code. Covers ETH (Hedgey) and BSC (Uranium) together so input-shape
assumptions are reviewed as one path, per review directive.

Assertions:
- Hedgey custom selectors (createLockedCampaign 0xefd86b62, cancelCampaign
  0xf412e4c7) at the vulnerable contract reach ranked targets AND the real
  serialized narrow-down payload.
- The token-only adversarial candidate (USDC proxy, only standard ERC-20
  selectors observed) is preserved as a visible candidate, not excluded.
- BSC: pair swap 0x022c0d9f at the exploited pair and factory allPairs
  0x1e3dd18b reach ranked targets and the serialized payload.
- Annotation (possible-signature hint, implementation-unverified label) must
  be present in the REAL serialized payload, not only in a hand-built summary.
"""
import importlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

ETH_FIX = json.loads((ROOT / "tests/fixtures/hedgey_tx1_parity_trace.json").read_text())
BSC_FIX = json.loads((ROOT / "tests/fixtures/uranium_bsc_parity_trace.json").read_text())

ETH_TX = ETH_FIX["provenance"]["transaction_hash"]
BSC_TX = BSC_FIX["provenance"]["transaction_hash"]

ETH_ATTACKER = "0xded2b1a426e1b7d415a40bcad44e98f47181dda2"
ETH_VULN = "0xbc452fdc8f851d7c5b72e1fe74dfb63bb793d511"
USDC_PROXY = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

BSC_ATTACKER = "0xc47bdd0a852a88a019385ea3ff57cf8de79f019d"
BSC_PAIR = "0xa08c4571b395f81fbd3755d44eaf9a25c9399a4a"
BSC_FACTORY = "0xa943ea143cd7e79806d670f4a7cf08f8922a454f"



import os
import subprocess


PIN = "fb57c3f"


@pytest.fixture
def pinned(monkeypatch, tmp_path):
    location = os.getenv("FAULTSEEKER_TEST_PIPELINE_REPO")
    if not location:
        pytest.skip("Exact pinned pipeline checkout required")
    assert subprocess.check_output(["git", "-C", location, "rev-parse", "HEAD"], text=True).strip().startswith(PIN)
    monkeypatch.syspath_prepend(location)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "true")
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://model.invalid/v1")
    monkeypatch.setenv("FAULTSEEKER_LLM_FALLBACK_MODEL", "")
    def blocked(*args, **kwargs):
        raise AssertionError("Unmocked network access is forbidden")
    import urllib.request
    import requests
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(requests.sessions.Session, "request", blocked)
    return location

class _StubAgent:
    """LLM boundary stub: captures every prompt, returns canned answers.
    narrow_answers (list) scripts sequential narrow-down replies (invalid /
    empty intermediates included); once exhausted the last answer repeats."""
    def __init__(self, narrow_answer=None, narrow_answers=None):
        self.prompts = []
        self.narrow_answer = narrow_answer
        self.narrow_answers = list(narrow_answers) if narrow_answers else None
    def query(self, prompt, format=None):
        self.prompts.append(str(prompt))
        if format == 'dict':
            return {'unknown': 'uncategorized'}  # keep address inspectable
        if self.narrow_answers:
            return self.narrow_answers.pop(0)
        return self.narrow_answer


class _SelectionCaptured(Exception):
    pass


def _merged_sequence(identity, tx, chain):
    return {"transaction_hash": tx, "chain": chain, "trace": identity["trace"],
            "canonical_trace": identity.get("canonical_trace"), "address_relation": {},
            "created_address": [], "storage_events": [], "trace_state_diff": {}}


def _run_production_path(pinned, monkeypatch, fixture, tx, chain, attacker, victim, stop_env=False,
                         scripted_answers=None):
    from app.trace_identity import sequence_from_parity
    m = importlib.import_module("app.pipeline_guards")
    if stop_env:
        monkeypatch.setenv("FAULTSEEKER_STOP_AFTER_NARROWDOWN", "1")
    identity = sequence_from_parity(fixture["responses"]["trace_transaction"], tx, chain,
                                    verified_chain=chain)
    seq = _merged_sequence(identity, tx, chain)

    trace_module = importlib.import_module("faultseeker.forensics.trace_analyzer")
    monkeypatch.setattr(trace_module, "build_agent", lambda *args: None)

    orch_mod = importlib.import_module("faultseeker.forensics.orchestrator")
    orch = orch_mod.ForensicsOrchestrator(model="offline-no-llm", cache_dir=str(Path(pinned) / ".cache_e2e"))

    # Real TraceAnalyzer over the real sequence.
    analysis = trace_module.TraceAnalyzer(seq, {"transaction_hash": tx}, model="offline-no-llm").run()
    assert analysis and len(analysis["flatten_trace"]) > 10

    # REAL AddressClassifier.run with only its LLM/RPC boundaries stubbed.
    cls = orch.address_classifier
    monkeypatch.setattr(cls.txn_sequencer, "run", lambda *a, **k: seq)
    monkeypatch.setattr(cls.txn_info_collector, "run", lambda *a, **k: {"transaction_hash": tx})
    canned_fundflow = {"potential_attacker": [attacker], "potential_victim": [victim],
                       "balance_change": {}, "address_memo": {}}
    monkeypatch.setattr(cls.fundflow_analyzer, "run", lambda *a, **k: canned_fundflow)
    cls_agent = _StubAgent()
    monkeypatch.setattr(cls, "agent", cls_agent)
    token_filter = cls.run(tx, chain)
    assert token_filter, "real AddressClassifier.run returned None offline"

    # REAL orchestrator admission functions (the production input boundary the
    # earlier reconstructed-fixture tests bypassed).
    orch.txn_seq = seq
    orch.txn_info = {"transaction_hash": tx}
    orch.tx_analysis = analysis
    orch.token_filter_result = token_filter
    orch.trace = [analysis['trace']]
    orch.address_calls_with_created_contract = analysis.get('address_calls_with_created_contract_in_params', [])
    orch.check_flashloan_fallback_execution()
    orch.check_function_name_with_hash()
    orch.check_call_with_created_contract()
    orch.get_other_functions_to_be_inspected()
    orch.adaptive_fallback = orch.adaptive_controller.apply(
        orch.functions_to_be_inspected, orch.tx_analysis, orch.token_filter_result)
    admitted = set()
    for bucket, calls in (orch.functions_to_be_inspected or {}).items():
        for c in calls or []:
            if isinstance(c, dict) and c.get("function") and c.get("address"):
                admitted.add(f"{c['function']}_{c['address']}".lower())

    # Hooked ranker through the real PipelineRuntime install.
    runtime = m.PipelineRuntime(tx, chain).install()
    runtime.sequence = seq
    ranker = importlib.import_module("faultseeker.function_analysis.function_ranker").FunctionRanker()
    ranked = ranker.rank(orch, analysis)
    ranked_keys = [k.lower() for k in ranked.functions_to_be_inspected]

    # REAL narrow-down serializer with a capturing stub at the LLM boundary.
    fa_mod = importlib.import_module("faultseeker.function_analysis.function_analyzer")
    analyzer = fa_mod.FunctionAnalyzer(model="offline-no-llm")
    stub = _StubAgent(narrow_answer=list(ranked.functions_to_be_inspected)[:5],
                      narrow_answers=scripted_answers)
    analyzer.agent = stub
    analyzer.functions_to_be_inspected = ranked.functions_to_be_inspected
    analyzer.address_calls_with_created_contract_in_params = {}
    analyzer.fundflow_analysis = {"balance_change": {}}
    analyzer.repeated_patterns = []
    captured = {}
    monkeypatch.delenv("FAULTSEEKER_MAX_FUNCTIONS", raising=False)
    if stop_env:
        # No instance override: the production class-level hook runs, records
        # the post-selection entry, and stops the run diagnostically.
        with pytest.raises(m.NarrowdownCaptureStop) as excinfo:
            analyzer._review_function_calls()
        report = runtime.failure_report(excinfo.value)
        captures = list(runtime.narrowdown_capture)
        runtime.close()
        return {"ranked": ranked, "ranked_keys": ranked_keys, "captures": captures,
                "failure": report.get("failure"), "report": report,
                "prompts": list(stub.prompts)}
    def _capture_selection(selected):
        captured["selected"] = list(selected) if not isinstance(selected, dict) else list(selected.keys())
        raise _SelectionCaptured()
    monkeypatch.setattr(analyzer, "_prepare_children_call_memo", _capture_selection)
    with pytest.raises(_SelectionCaptured):
        analyzer._review_function_calls()
    narrowdown_prompt = stub.prompts[0] if stub.prompts else ""
    # The production capture hook must record the exact payload + raw reply.
    assert runtime.narrowdown_capture, "narrowdown capture hook did not fire"
    assert runtime.narrowdown_capture[0]["prompt"] == narrowdown_prompt
    assert runtime.narrowdown_capture[0]["reply"] == list(ranked.functions_to_be_inspected)[:5]
    assert runtime.narrowdown_capture[0]["candidate_count"] == len(ranked.functions_to_be_inspected)
    runtime.close()

    return {
        "admitted": admitted,
        "ranked_keys": ranked_keys,
        "ranked": ranked,
        "prompt": narrowdown_prompt,
        "selected": captured.get("selected", []),
    }


def test_e2e_eth_hedgey_production_path(pinned, monkeypatch):
    r = _run_production_path(pinned, monkeypatch, ETH_FIX, ETH_TX, "eth", ETH_ATTACKER, ETH_VULN)
    create_key = f"0xefd86b62_{ETH_VULN}"
    cancel_key = f"0xf412e4c7_{ETH_VULN}"
    # Custom exploit-path selectors reach ranked targets (via real path + recall repair).
    assert create_key in r["ranked_keys"], f"createLockedCampaign missing from ranked targets: {r['ranked_keys'][:10]}"
    assert cancel_key in r["ranked_keys"], "cancelCampaign missing from ranked targets"
    # Custom (non-token-surface) functions lead the ranking.
    m = importlib.import_module("app.pipeline_guards")
    first_sel = r["ranked_keys"][0].rsplit("_", 1)[0]
    assert first_sel not in m.SEL_TOKEN_SURFACE, f"token-surface selector still leads: {r['ranked_keys'][0]}"
    # Token-only adversarial candidate (USDC proxy shows ONLY standard ERC-20
    # selectors) is preserved as a visible candidate, not excluded.
    usdc_keys = [k for k in r["ranked_keys"] if k.rsplit("_", 1)[1] == USDC_PROXY]
    assert usdc_keys, "USDC proxy candidacy lost - token-only candidate excluded"
    # Real serialized narrow-down payload carries the custom selectors and the
    # token-only representative.
    assert "0xefd86b62" in r["prompt"] and ETH_VULN in r["prompt"]
    assert any(k in r["prompt"] for k in usdc_keys)
    # Annotation must reach the REAL serializer payload (not a reconstructed one).
    assert "possible signature" in r["prompt"].lower() or "possible_signature" in r["prompt"], \
        "annotation does not propagate through the real narrow-down serializer"
    # The stub's final selection is bounded and drawn from ranked candidates.
    assert 0 < len(r["selected"]) <= 5
    assert all(s.lower() in r["ranked_keys"] for s in r["selected"])


def test_e2e_bsc_uranium_production_path(pinned, monkeypatch):
    r = _run_production_path(pinned, monkeypatch, BSC_FIX, BSC_TX, "bsc", BSC_ATTACKER, BSC_PAIR)
    swap_key = f"0x022c0d9f_{BSC_PAIR}"
    assert swap_key in r["ranked_keys"], f"pair swap missing from ranked targets: {r['ranked_keys'][:10]}"
    # Factory allPairs candidate present (case-insensitive address match).
    assert any(k.startswith("0x1e3dd18b_") for k in r["ranked_keys"]), "allPairs candidate missing"
    # Pair swap (a state-changing custom-surface selector at the exploit site)
    # is not demoted below token reads.
    m = importlib.import_module("app.pipeline_guards")
    swap_pos = r["ranked_keys"].index(swap_key)
    assert swap_pos <= 5, f"exploit-site swap ranked too low: position {swap_pos}"
    assert "0x022c0d9f" in r["prompt"] and BSC_PAIR in r["prompt"]
    assert "possible signature" in r["prompt"].lower() or "possible_signature" in r["prompt"]
    assert 0 < len(r["selected"]) <= 5


def test_e2e_stop_after_narrowdown_is_diagnostic(pinned, monkeypatch):
    """FAULTSEEKER_STOP_AFTER_NARROWDOWN=1: the run halts right after the real
    selection loop with a clearly diagnostic failure record, retaining the
    actual serializer prompt, raw reply, pre/post counts and model config."""
    r = _run_production_path(pinned, monkeypatch, ETH_FIX, ETH_TX, "eth", ETH_ATTACKER, ETH_VULN,
                             stop_env=True)
    assert r["failure"]["kind"] == "diagnostic_stop", r["failure"]
    assert "not a provider or product failure" in r["failure"]["message"].lower()
    nd = [c for c in r["captures"] if c.get("kind") == "narrowdown"]
    assert nd, "no narrow-down query captures"
    assert nd[0]["candidate_count"] == len(r["ranked"].functions_to_be_inspected)
    assert nd[0]["prompt"] and nd[0]["reply"] is not None
    sel = [c for c in r["captures"] if c.get("kind") == "narrowdown_selection"]
    assert len(sel) == 1, f"expected exactly one post-selection entry: {sel}"
    s = sel[0]
    assert s["pre_candidate_count"] == len(r["ranked"].functions_to_be_inspected)
    assert 0 < s["post_selection_count"] <= 5
    assert all(k.lower() in r["ranked_keys"] for k in s["post_selection_keys"])
    assert set(s["env_snapshot"]) >= {"model", "reasoning_effort", "retry_limit", "max_functions"}
    assert isinstance(s["dispatched_configs"], list)  # empty offline: stub bypasses dispatch
    assert any("intentionally" in l for l in r["report"].get("limitations", []))


def test_e2e_stop_capture_complete_across_reasks(pinned, monkeypatch):
    """R12 finding 2: scripted narrow-down sequence - invalid, empty, then a
    valid shrink. Every dispatched query must be captured in order with its
    raw reply; the final selection must reflect the REAL production
    bound-validation/reask/fallback logic, and the stop fires only after it."""
    ranked_keys_probe = _run_production_path  # noqa - clarity alias
    # First discover the ranked universe with the plain helper (no stop).
    base = _run_production_path(pinned, monkeypatch, ETH_FIX, ETH_TX, "eth", ETH_ATTACKER, ETH_VULN)
    valid = base["ranked_keys"][:3]
    scripted = ["not-a-list", [], valid]  # invalid type, empty list, then valid shrink
    r = _run_production_path(pinned, monkeypatch, ETH_FIX, ETH_TX, "eth", ETH_ATTACKER, ETH_VULN,
                             stop_env=True, scripted_answers=scripted)
    nd = [c for c in r["captures"] if c.get("kind") == "narrowdown"]
    # Production loop: >5 candidates -> up to 3 reasks; invalid type and empty
    # replies are rejected (0 < len < prev required) but each query is still made.
    assert len(nd) == 3, f"expected 3 dispatched narrow-down queries: {len(nd)}"
    assert [c["reply"] for c in nd] == scripted, "raw replies not retained in dispatch order"
    assert all(c["candidate_count"] == len(r["ranked"].functions_to_be_inspected) for c in nd)
    assert all(c["prompt"] for c in nd)
    sel = [c for c in r["captures"] if c.get("kind") == "narrowdown_selection"]
    assert len(sel) == 1
    # Final selection = the valid scripted reply, i.e. the fallback/reask logic ran first.
    assert [k.lower() for k in sel[0]["post_selection_keys"]] == [k.lower() for k in valid]
    assert r["failure"]["kind"] == "diagnostic_stop"


def test_e2e_stop_after_narrowdown_bsc(pinned, monkeypatch):
    """R12 finding 3: the diagnostic stop path on the BSC (281-candidate-class)
    input shape. No unconditional five-function bound: the production contract
    permits >5 when reasks exhaust."""
    r = _run_production_path(pinned, monkeypatch, BSC_FIX, BSC_TX, "bsc", BSC_ATTACKER, BSC_PAIR,
                             stop_env=True)
    assert r["failure"]["kind"] == "diagnostic_stop"
    nd = [c for c in r["captures"] if c.get("kind") == "narrowdown"]
    assert nd and all(c["prompt"] and c["reply"] is not None for c in nd)
    sel = [c for c in r["captures"] if c.get("kind") == "narrowdown_selection"]
    assert len(sel) == 1
    s = sel[0]
    assert s["pre_candidate_count"] == len(r["ranked"].functions_to_be_inspected)
    assert s["post_selection_count"] >= 1  # no unconditional <=5 bound (production contract)
    assert all(k.lower() in r["ranked_keys"] for k in s["post_selection_keys"])
    # Selection CONTENT is the model/stub's choice; swap membership in the
    # ranked universe is covered by test_e2e_bsc_uranium_production_path.
