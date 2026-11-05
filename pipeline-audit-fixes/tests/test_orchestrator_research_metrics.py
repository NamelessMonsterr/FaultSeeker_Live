from faultseeker.forensics.orchestrator import ForensicsOrchestrator


def test_trace_entropy_is_normalized():
    flat = [
        {"function": "swap"},
        {"function": "swap"},
        {"function": "transfer"},
        {"function": "withdraw"},
    ]

    entropy = ForensicsOrchestrator._trace_entropy(flat)

    assert 0.0 < entropy <= 1.0


def test_trace_entropy_handles_empty_trace():
    assert ForensicsOrchestrator._trace_entropy([]) == 0.0



def test_actual_orchestrator_reports_trace_depth_not_address_node_count(monkeypatch):
    from types import SimpleNamespace
    from faultseeker.forensics import orchestrator as module
    from faultseeker.research.ablation import AblationConfig
    root = {"address": "0x" + "1" * 40, "function": "root", "children": [
        {"address": "0x" + digit * 40, "function": "read", "children": []} for digit in "234"]}
    analysis = {"trace": root, "flatten_trace": [], "repeated_patterns": {}}
    orch = ForensicsOrchestrator.__new__(ForensicsOrchestrator)
    orch.model = "controlled-offline"
    orch.cache_dir = None
    orch.cost_tracker = None
    orch.ablation = AblationConfig.full_system()
    orch.txn_sequencer = SimpleNamespace(run=lambda *a: {"chain": "eth", "trace": root})
    orch.txn_info_collector = SimpleNamespace(run=lambda *a: {"transaction_hash": "synthetic-depth-contract"})
    orch.address_classifier = SimpleNamespace(run=lambda *a: {})
    orch.adaptive_controller = SimpleNamespace(apply=lambda *a: {})
    captured = []
    orch._calibrated_confidence = lambda features: captured.append(features) or None
    monkeypatch.setattr(module, "TraceAnalyzer", lambda *a: SimpleNamespace(run=lambda: analysis))
    result, _, _ = orch.run("synthetic-depth-contract", "eth")
    assert result.signals["graph_reasoning"]["node_count"] == 4
    assert result.signals["call_depth_max"] == result.signals["call_depth"] == 1
    assert captured[0]["call_depth"] == 1



def test_trace_depth_is_iterative_and_distinguishes_absent_from_root_only():
    import pytest
    root = {"children": []}
    child = root
    for _ in range(1023):
        child["children"] = [{"children": []}]
        child = child["children"][0]
    assert ForensicsOrchestrator._trace_max_depth(root) == 1023
    assert ForensicsOrchestrator._trace_max_depth({"children": []}) == 0
    assert ForensicsOrchestrator._trace_max_depth(None) is None
    root["children"] = [root]
    with pytest.raises(ValueError, match="Cyclic"):
        ForensicsOrchestrator._trace_max_depth(root)


def test_stage1_refuses_unknown_contract_without_predicting(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from faultseeker.research.ablation import AblationConfig
    path = tmp_path / "model.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("FAULTSEEKER_CALIBRATOR_PATH", str(path))
    orch = ForensicsOrchestrator.__new__(ForensicsOrchestrator)
    orch.ablation = AblationConfig.full_system()
    attempts = []
    orch._calibrator = SimpleNamespace(trained=True, predict_proba=lambda row: attempts.append(row) or .9)
    assert orch._calibrated_confidence({"trace_entropy": .5}) is None
    assert attempts == []
    assert orch.calibration_status == {"status": "not_applied", "reason": "feature_contract_unverified"}
