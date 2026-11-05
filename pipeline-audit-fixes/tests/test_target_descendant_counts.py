"""Synthetic trace-tree regression; no on-chain or model claims."""
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer


def node(name, children=()):
    return {"function": name, "address": "0x" + "1" * 40,
            "call_type": "call", "type": "call", "params": "0x", "children": list(children)}


def test_target_memo_counts_only_descendants_once():
    leaf = node("leaf")
    target = node("target", [leaf])
    root = node("root", [node("sibling"), node("wrapper", [target])])
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)
    analyzer.trace = [root]
    key = "target_" + target["address"]
    analyzer.functions_to_be_inspected = {key: {"calls": [{"depth": [0, 1, 0]}]}}
    analyzer.children_call_memo = {}
    analyzer.children_call_memo_single = {}
    analyzer._prepare_children_call_memo([key])
    memo = analyzer.children_call_memo[key]
    assert set(memo) == {"leaf::" + leaf["address"]}
    assert memo["leaf::" + leaf["address"]]["count"] == 1


def test_target_memo_keeps_real_repeated_descendants():
    target = node("target", [node("leaf"), node("leaf")])
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)
    analyzer.trace = [target]
    key = "target_" + target["address"]
    analyzer.functions_to_be_inspected = {key: {"calls": [{"depth": [0]}]}}
    analyzer.children_call_memo = {}
    analyzer.children_call_memo_single = {}
    analyzer._prepare_children_call_memo([key])
    assert analyzer.children_call_memo[key]["leaf::" + target["address"]]["count"] == 2


def test_verified_hedgey_setup_trace_descendant_counts():
    # Saved Blockscout trace cross-checked against RPC transaction identity.
    # Only topology/counting is tested; no ABI or forensic correctness claim.
    import json
    from pathlib import Path
    fixture = json.loads((Path(__file__).parent / 'fixtures/hedgey_setup_descendants.json').read_text(encoding='utf-8'))
    assert fixture['chain'] == 'eth'
    assert fixture['transaction_hash'] == '0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517'
    def convert(raw):
        return dict(function=raw.get('input', '')[:10], address=raw['callee'],
                    call_type=raw['call_type'], type='call', params=raw.get('input', ''),
                    children=[convert(child) for child in raw.get('children', [])])
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)
    analyzer.trace = [convert(fixture['trace'])]
    analyzer.functions_to_be_inspected = {}
    address = '0xbc452fdc8f851d7c5b72e1fe74dfb63bb793d511'
    def walk(nodes, path=()):
        for index, call in enumerate(nodes):
            depth = path + (index,)
            if call['address'].lower() == address:
                key = call['function'] + '_' + address
                analyzer.functions_to_be_inspected.setdefault(key, {'calls': []})['calls'].append({'depth': list(depth)})
            walk(call['children'], depth)
    walk(analyzer.trace)
    analyzer.children_call_memo = {}
    analyzer.children_call_memo_single = {}
    analyzer._prepare_children_call_memo(list(analyzer.functions_to_be_inspected))
    counts = {key.split('_')[0]: sum(item['count'] for item in memo.values())
              for key, memo in analyzer.children_call_memo.items()}
    assert counts == {'0xefd86b62': 12, '0xf412e4c7': 6}
    assert all(len(target['calls']) == 1 for target in analyzer.functions_to_be_inspected.values())
