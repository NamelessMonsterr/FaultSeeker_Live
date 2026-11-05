"""Synthetic failed-call metadata through real conversion and serialization."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from faultseeker.data_collection.txn_sequencer import TransactionSequencer
from faultseeker.data_collection.trace_parser import TraceNode

ROOT = {"callee": "0x" + "1" * 40, "caller": "0x" + "2" * 40,
        "input": "0x123456780000", "function_selector": "0x12345678", "call_type": "CALL",
        "success": False, "return_data": "0x08c379a0", "error": "execution reverted", "children": []}

@pytest.mark.parametrize("through_sequencer", [False, True])
def test_legacy_conversion_preserves_failed_call_metadata(through_sequencer):
    if through_sequencer:
        sequencer = TransactionSequencer.__new__(TransactionSequencer)
        sequencer.replayer = SimpleNamespace(get_structured_trace=lambda *a: {"trace": deepcopy(ROOT)}, run=lambda *a: "")
        sequencer.parser = SimpleNamespace(address_call_memo={}, created_address=[])
        sequencer.visualizer = SimpleNamespace(build_graph_from_tree=lambda *a: None, draw_address_relation=lambda: {})
        converted = sequencer.run("synthetic", "eth")["trace"]
    else:
        converted = TransactionSequencer._canonical_to_legacy_trace(deepcopy(ROOT))
    for key in ("caller", "input", "success", "return_data", "error"):
        assert converted[key] == ROOT[key]
    round_trip = TraceNode.from_dict(converted).to_dict()
    for key in ("caller", "input", "success", "return_data", "error"):
        assert round_trip[key] == ROOT[key]


def test_provider_error_survives_normalization_and_legacy_conversion():
    from faultseeker.utils.rpc_provider import normalize_trace_node
    raw = {"type": "CALL", "from": ROOT["caller"], "to": ROOT["callee"], "input": ROOT["input"], "output": ROOT["return_data"], "error": ROOT["error"], "calls": []}
    canonical = normalize_trace_node(raw)
    converted = TransactionSequencer._canonical_to_legacy_trace(canonical)
    assert canonical["success"] is False
    assert canonical["error"] == converted["error"] == "execution reverted"
