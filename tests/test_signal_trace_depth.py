"""Synthetic trace traversal boundaries; no exploit ground truth implied."""
import pytest
from faultseeker.forensics.signal_extractor import SignalExtractor

A = '0x' + '1' * 40


def frame(children=None):
    return {'to': A, 'type': 'CALL', 'input': '0x12345678', 'children': children or []}


def test_reentrancy_walker_accepts_1024_frames_without_python_recursion():
    root = frame()
    leaf = root
    for _ in range(1023):
        child = frame()
        leaf['children'] = [child]
        leaf = child
    extractor = SignalExtractor({}, {'canonical_trace': root})
    extractor._check_reentrancy()
    counts = extractor._reentrancy_debug_components
    assert counts['call_depth_max'] == 1023
    assert counts['external_calls'] == 1023
    assert counts['same_contract_reentry'] == 0
    assert counts['same_function_reentered'] is False


def test_reentrancy_walker_rejects_ancestor_cycle():
    root = frame()
    root['children'] = [root]
    with pytest.raises(ValueError, match='Cyclic trace'):
        SignalExtractor({}, {'canonical_trace': root})._check_reentrancy()


def test_reused_sibling_frame_is_counted_twice_not_treated_as_cycle():
    child = frame()
    extractor = SignalExtractor({}, {'canonical_trace': frame([child, child])})
    extractor._check_reentrancy()
    assert extractor._reentrancy_debug_components['external_calls'] == 2
    assert extractor._reentrancy_debug_components['call_depth_max'] == 1
