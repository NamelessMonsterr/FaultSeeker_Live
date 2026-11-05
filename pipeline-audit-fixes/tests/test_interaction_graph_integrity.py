"""Synthetic resource-bound regressions, not on-chain forensic evidence."""
import sys
import pytest
from faultseeker.forensics.interaction_graph import TransactionInteractionGraph


def test_trace_graph_accepts_1024_frames_without_recursion_workaround():
    root = {"address": "root", "children": []}
    current = root
    for i in range(1023):
        child = {"address": str(i), "children": []}
        current["children"] = [child]
        current = child
    before = sys.getrecursionlimit()
    assert before == 1000
    graph = TransactionInteractionGraph()
    graph.add_trace(root)
    assert graph.graph.number_of_edges() == 1023
    assert sys.getrecursionlimit() == before


def test_cyclic_python_trace_is_rejected():
    root = {"address": "root"}
    root["children"] = [root]
    with pytest.raises(ValueError, match="Cyclic trace"):
        TransactionInteractionGraph().add_trace(root)


def test_cycle_enumeration_is_bounded_and_labelled():
    graph = TransactionInteractionGraph()
    graph.graph.add_edges_from((i, j) for i in range(8) for j in range(8) if i != j)
    metrics = graph.metrics()
    assert metrics["cycle_count"] == 1000
    assert metrics["cycle_count_truncated"] is True
    assert metrics["cycle_count_kind"] == "lower_bound"
    assert "recursive_cycle" in metrics["motifs"]


def test_small_graph_cycle_count_remains_exact():
    graph = TransactionInteractionGraph()
    graph.graph.add_edges_from([(1, 2), (2, 1)])
    metrics = graph.metrics()
    assert metrics["cycle_count"] == 1
    assert metrics["cycle_count_truncated"] is False
    assert metrics["cycle_count_kind"] == "exact"
