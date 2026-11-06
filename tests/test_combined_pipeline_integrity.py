"""Cross-patch synthetic contracts; no on-chain fixture or model verdict."""
from faultseeker.utils.rpc_provider import build_parity_tree, normalize_trace_node
from faultseeker.data_collection.txn_sequencer import TransactionSequencer
from faultseeker.data_collection.trace_parser import TraceNode
from faultseeker.core.confidence_scorer import calibrated_confidence


def test_deep_parity_creation_keeps_target_input_and_calibrated_report_coherence():
    rows = []
    for depth in range(1024):
        rows.append({'type': 'create', 'traceAddress': [0] * depth,
                     'action': {'from': '0x' + '1' * 40, 'init': '0x60806040526000',
                                'value': '0x0', 'gas': '0x1000'},
                     'result': {'address': '0x' + format(depth + 1, '040x')}})
    canonical = normalize_trace_node(build_parity_tree(rows))
    legacy = TransactionSequencer._canonical_to_legacy_trace(canonical)
    node = TraceNode.from_dict(legacy)
    for depth in range(1024):
        expected = '0x' + format(depth + 1, '040x')
        assert canonical['callee'] == expected
        assert canonical['input'] == '0x60806040526000'
        assert canonical['call_type'] == 'CREATE'
        assert node.address == expected and node.call_type == 'create'
        if depth < 1023:
            assert len(canonical['children']) == len(node.children) == 1
            canonical, node = canonical['children'][0], node.children[0]
        else:
            assert not canonical['children'] and not node.children
    original = {'overall': 0.6025, 'level': 'moderate',
                'explanation': ['Heuristic confidence: 60.2%'], 'components': {'code_evidence': 0.35}}
    result = calibrated_confidence(original, 0.9941, 'controlled-test-calibrator')
    assert result['overall'] == 0.9941 and result['level'] == 'very_high'
    assert '99.4%' in result['explanation'][0]
    assert result['heuristic_confidence'] == original
