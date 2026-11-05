"""Selector -> verified-source binding (analysis-input root cause #2).

Canonical traces carry calldata-selector function identity; parse_contract keys
downloaded source by function NAME; the pinned analyzer looks up by that key.
These tests exercise the production hook path (PipelineRuntime hooks on the real
engine methods), the canonical-signature builder, overload and collision
handling, and source-parser coverage.
"""
import importlib
import json
import os
import shutil

import pytest

HEDGEY = "0xbc452fdc8f851d7c5b72e1fe74dfb63bb793d511"
TX = "0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517"
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")



@pytest.fixture
def pinned_fork(monkeypatch, tmp_path):
    """Independent pinned-fork sys.path (same pattern as test_pipeline_guards)."""
    import subprocess
    from pathlib import Path
    location = os.getenv("FAULTSEEKER_TEST_PIPELINE_REPO")
    if not location:
        pytest.skip("Exact pinned pipeline unavailable: set FAULTSEEKER_TEST_PIPELINE_REPO")
    root = Path(__file__).resolve().parents[1]
    pin = next(l.split("=", 1)[1] for l in (root / "Dockerfile").read_text().splitlines()
               if l.startswith("ARG FAULTSEEKER_SHA="))
    assert subprocess.check_output(["git", "-C", location, "rev-parse", "HEAD"], text=True).strip() == pin
    monkeypatch.syspath_prepend(location)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "true")
    return location


def _load_abi():
    with open(os.path.join(FIXTURES, "hedgey_claimcampaigns_abi.json")) as f:
        return json.load(f)


def _parse_hedgey_source(tmp_path):
    from faultseeker.data_collection.contract_downloader import ContractDownloader
    src = tmp_path / "src"
    src.mkdir()
    shutil.copy(os.path.join(FIXTURES, "ClaimCampaigns.sol"), src / "ClaimCampaigns.sol")
    return ContractDownloader.parse_contract(str(src))


def _runtime():
    m = importlib.import_module("app.pipeline_guards")
    rt = m.PipelineRuntime(TX, "eth")
    rt._install_selector_source_binding()
    return rt


def _restore(rt):
    for owner, name, value in reversed(rt.restorers):
        setattr(owner, name, value)
    rt.restorers.clear()



def _hedgey_trace(extra_children=None):
    """Minimal observed trace: two ordinary-call frames at the Hedgey address."""
    children = [{"address": HEDGEY, "function": "0xf412e4c7", "call_type": "call", "children": []}]
    children.extend(extra_children or [])
    return {"trace": {"address": HEDGEY, "function": "0xefd86b62",
                      "call_type": "call", "children": children}}

def _analyzer_stub(contract_info):
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    stub = object.__new__(FunctionAnalyzer)  # real production method, no model agents
    stub.contract_info = contract_info
    return stub, FunctionAnalyzer


def test_canonical_signature_vectors_from_verified_hedgey_abi():
    m = importlib.import_module("app.pipeline_guards")
    mapping = m.PipelineRuntime._build_selector_map(_load_abi())
    assert mapping["0xefd86b62"]["name"] == "createLockedCampaign"
    assert mapping["0xefd86b62"]["signature"] == (
        "createLockedCampaign(bytes16,(address,address,uint256,uint256,uint8,bytes32),"
        "(address,uint256,uint256,uint256,uint256),(address,uint256,uint256,uint256,uint256,uint256))")
    assert mapping["0xf412e4c7"] == {"name": "cancelCampaign", "signature": "cancelCampaign(bytes16)",
                                     "input_count": 1, "input_types": ["bytes16"],
                                     "input_internal_types": ["bytes16"], "input_components": [None]}
    assert mapping["0xefd86b62"]["input_types"][0] == "bytes16"
    assert mapping["0xefd86b62"]["input_types"][1].startswith("(address,address,uint256,uint256,uint8,bytes32)")
    assert mapping["0x47d1e2c1"]["name"] == "claimTokens"
    assert "ambiguous" not in mapping.values()  # no collisions in the real ABI


def test_overloads_resolve_by_selector_not_name():
    m = importlib.import_module("app.pipeline_guards")
    abi = [
        {"type": "function", "name": "transfer", "inputs": [{"type": "address", "name": "to"}]},
        {"type": "function", "name": "transfer", "inputs": [{"type": "address", "name": "to"},
                                                            {"type": "uint256", "name": "amt"}]},
    ]
    mapping = m.PipelineRuntime._build_selector_map(abi)
    assert mapping["0x1a695230"] == {"name": "transfer", "signature": "transfer(address)", "input_count": 1,
                                     "input_types": ["address"], "input_internal_types": [""],
                                     "input_components": [None]}
    assert mapping["0xa9059cbb"] == {"name": "transfer", "signature": "transfer(address,uint256)",
                                     "input_count": 2, "input_types": ["address", "uint256"],
                                     "input_internal_types": ["", ""], "input_components": [None, None]}
    assert "ambiguous" not in mapping.values()


def _find_collision(limit=400000):
    from eth_utils import function_signature_to_4byte_selector as f4
    seen = {}
    for i in range(limit):
        sig = "f%d()" % i
        sel = "0x" + f4(sig).hex()
        if sel in seen and seen[sel] != sig:
            return seen[sel], sig, sel
        seen[sel] = sig
    raise AssertionError("no 4-byte collision found within limit")


def test_selector_collision_fails_unresolved(pinned_fork):
    m = importlib.import_module("app.pipeline_guards")
    sig_a, sig_b, sel = _find_collision()
    abi = [{"type": "function", "name": sig_a[:-2], "inputs": []},
           {"type": "function", "name": sig_b[:-2], "inputs": []}]
    mapping = m.PipelineRuntime._build_selector_map(abi)
    assert mapping[sel] == "ambiguous"
    rt = _runtime()
    try:
        rt.selector_bindings[HEDGEY] = {"selectors": mapping}
        rt.sequence = {"trace": {"address": HEDGEY, "function": sel,
                                 "call_type": "call", "children": []}}
        stub, FA = _analyzer_stub({HEDGEY: {sig_a[:-2]: [{"path": ".", "start_line": 1,
                                                          "end_line": 2, "content": "x"}]}})
        out = FA._retrieve_source_code(stub, HEDGEY, sel)
        assert out == []  # collision: refuse to bind, never guess
        rec = rt.selector_resolution_log[-1]
        assert rec["status"] == "ambiguous_collision" and rec["source_entries"] == 0
        assert rec["selector"] == sel  # identity preserved, not renamed
    finally:
        _restore(rt)


def test_retrieval_resolves_selector_through_real_analyzer_method(tmp_path, pinned_fork):
    m = importlib.import_module("app.pipeline_guards")
    rt = _runtime()  # hooks installed: parse_contract now attaches decl indices
    parsed = _parse_hedgey_source(tmp_path)
    try:
        rt.selector_bindings[HEDGEY] = {"selectors": m.PipelineRuntime._build_selector_map(_load_abi())}
        rt.sequence = _hedgey_trace()
        stub, FA = _analyzer_stub({HEDGEY: parsed})
        # createLockedCampaign's unqualified struct names are PROVEN by the
        # file's own declarations (ClaimCampaigns.Campaign etc., declared in
        # ClaimCampaigns.sol) plus field-layout equality with the ABI tuples.
        assert parsed["createLockedCampaign"][0]["decl_index"]["decls"]["Campaign"] == [("ClaimCampaigns.Campaign", "ClaimCampaigns")]
        assert parsed["createLockedCampaign"][0]["fn_scope"] == "ClaimCampaigns"
        out = FA._retrieve_source_code(stub, HEDGEY, "0xefd86b62")
        assert out and "createLockedCampaign" in out[0]["source_code"]
        rec = rt.selector_resolution_log[-1]
        assert rec["status"] == "resolved"
        assert rec["selector"] == "0xefd86b62"  # canonical identity preserved
        assert rec["resolved_name"] == "createLockedCampaign"
        # cancelCampaign (0xf412e4c7, elementary bytes16) resolves through the
        # real analyzer method against the real ABI and source.
        out2 = FA._retrieve_source_code(stub, HEDGEY, "0xf412e4c7")
        assert out2 and "cancelCampaign" in out2[0]["source_code"]
        rec2 = rt.selector_resolution_log[-1]
        assert rec2["status"] == "resolved"
        assert rec2["code_address"] == HEDGEY and rec2["execution_context"] == HEDGEY
        assert rec2["call_type"] == "call"
    finally:
        _restore(rt)


def test_unresolved_selector_stays_empty_and_is_logged(tmp_path, pinned_fork):
    parsed = _parse_hedgey_source(tmp_path)
    rt = _runtime()
    try:
        rt.selector_bindings[HEDGEY] = {"selectors": {}}
        rt.sequence = _hedgey_trace()
        stub, FA = _analyzer_stub({HEDGEY: parsed})
        out = FA._retrieve_source_code(stub, HEDGEY, "0xdeadbeef")
        assert out == []  # no observed frame: fail unresolved, never guess
        rec = rt.selector_resolution_log[-1]
        assert rec["status"] == "unresolved" and rec["reason"] == "no_observed_frame"
        # Observed frame but no ABI binding: also unresolved, with the code context recorded.
        out2 = FA._retrieve_source_code(stub, HEDGEY, "0xefd86b62")
        assert out2 == []
        rec2 = rt.selector_resolution_log[-1]
        assert rec2["status"] == "unresolved" and rec2["reason"] == "no_abi_binding"
        assert rec2["code_address"] == HEDGEY
    finally:
        _restore(rt)


def test_name_identity_passthrough_unchanged(tmp_path, pinned_fork):
    parsed = _parse_hedgey_source(tmp_path)
    rt = _runtime()
    try:
        stub, FA = _analyzer_stub({HEDGEY: parsed})
        out = FA._retrieve_source_code(stub, HEDGEY, "createLockedCampaign")
        assert out and "createLockedCampaign" in out[0]["source_code"]
        assert rt.selector_resolution_log == []  # name identity: no binding involved
    finally:
        _restore(rt)


def test_parse_contract_coverage(tmp_path, pinned_fork):
    parsed = _parse_hedgey_source(tmp_path)
    expected = {"createLockedCampaign", "createUnlockedCampaign", "cancelCampaign",
                "claimTokens", "verify", "changeDonationcollector"}
    assert expected <= set(parsed), sorted(parsed)
    body = parsed["createLockedCampaign"][0]["content"]
    assert "safeIncreaseAllowance" in body and "claimLockup.tokenLocker" in body
    assert parsed["createLockedCampaign"][0]["start_line"] <= parsed["createLockedCampaign"][0]["end_line"]


def test_run_hook_builds_binding_with_code_hash_evidence(tmp_path, monkeypatch, pinned_fork):
    """Production route, offline: hooked ContractDownloader.run -> real
    get_source_code/get_abi parsing of explorer payloads -> binding record."""
    import faultseeker.data_collection.contract_downloader as cd
    from faultseeker.utils import rpc_provider
    with open(os.path.join(FIXTURES, "ClaimCampaigns.sol")) as f:
        source_text = f.read()

    def fake_explorer(chain, params, timeout=20):
        if params["action"] == "getsourcecode":
            return {"status": "1", "message": "OK",
                    "result": [{"SourceCode": source_text, "ContractName": "ClaimCampaigns"}]}
        if params["action"] == "getabi":
            return {"status": "1", "message": "OK", "result": json.dumps(_load_abi())}
        raise AssertionError("unexpected explorer action %s" % params["action"])

    code = "0x600160025500"
    def fake_rpc(chain, method, params, timeout=60):
        if method == "eth_getCode":
            return code
        if method == "eth_getTransactionByHash":
            return {"hash": TX, "blockNumber": "0x12c69cf"}
        raise AssertionError("unexpected rpc %s" % method)

    monkeypatch.setattr(cd, "explorer_call", fake_explorer)
    monkeypatch.setattr(rpc_provider, "rpc_call", fake_rpc)
    rt = _runtime()
    try:
        info = cd.ContractDownloader("eth", [HEDGEY], output_dir=str(tmp_path / "out"),
                                     cache_dir=str(tmp_path / "cache")).run()
        assert "createLockedCampaign" in info[HEDGEY]
        rec = rt.selector_bindings[HEDGEY]
        assert rec["selectors"]["0xefd86b62"]["name"] == "createLockedCampaign"
        assert rec["code_address"] == HEDGEY
        assert rec["abi_provenance"] == "explorer_registry_after_fallback"
        from eth_utils import keccak
        assert rec["code_hash_latest"] == "0x" + keccak(hexstr=code).hex()
        assert rec["latest_code"] == "fetched"
        assert rec["tx_lookup"] == "found"
        assert rec["tx_block"] == "0x12c69cf"
        assert rec["code_at_tx_block"] == "matches_latest"
        assert "not a verification" in rec["source_bytecode_link"]
        # Historical mismatch is reported, never smoothed over.
        monkeypatch.setattr(rpc_provider, "rpc_call",
                            lambda c, m2, p, timeout=60: ("0xdeadbeef" if m2 == "eth_getCode" and p[1] != "latest"
                                                          else fake_rpc(c, m2, p, timeout)))
        ev2 = rt._code_hash_evidence(HEDGEY)
        assert ev2["code_at_tx_block"] == "differs_from_latest"
        # RPC failure: explicit bounded reason, never swallowed.
        def boom(chain, method, params, timeout=60):
            raise TimeoutError("rpc timeout")
        monkeypatch.setattr(rpc_provider, "rpc_call", boom)
        ev3 = rt._code_hash_evidence(HEDGEY)
        assert ev3["latest_code"].startswith("unavailable:TimeoutError:")
        assert ev3["tx_lookup"].startswith("unavailable:TimeoutError:")
        assert ev3["code_at_tx_block"] == "not_checked"  # block unknown -> not checked
        # Transaction without a block number: historical comparison stays not_checked.
        monkeypatch.setattr(rpc_provider, "rpc_call",
                            lambda c, m2, p, timeout=60: (code if m2 == "eth_getCode" else {"hash": TX}))
        ev4 = rt._code_hash_evidence(HEDGEY)
        assert ev4["tx_lookup"] == "unavailable:no_block_number"
        assert ev4["code_at_tx_block"] == "not_checked"
    finally:
        _restore(rt)


def test_delegatecall_binds_code_address_and_execution_context(tmp_path):
    """Delegatecall frame: the code address is the frame target; the execution
    (storage) context is the parent frame's address. Both are recorded."""
    m = importlib.import_module("app.pipeline_guards")
    proxy = "0xaaaabbbbccccddddeeeeffff0000111122223333"
    rt = _runtime()
    parsed = _parse_hedgey_source(tmp_path)
    try:
        rt.selector_bindings[HEDGEY] = {"selectors": m.PipelineRuntime._build_selector_map(_load_abi())}
        rt.sequence = {"trace": {
            "address": proxy, "function": "0xefd86b62", "call_type": "call",
            "children": [{"address": HEDGEY, "function": "0xefd86b62",
                          "call_type": "delegatecall", "children": []}]}}
        stub, FA = _analyzer_stub({HEDGEY: parsed})
        out = FA._retrieve_source_code(stub, HEDGEY, "0xefd86b62")
        assert out and "createLockedCampaign" in out[0]["source_code"]
        rec = rt.selector_resolution_log[-1]
        assert rec["status"] == "resolved"
        assert rec["code_address"] == HEDGEY          # target whose code executes
        assert rec["execution_context"] == proxy      # storage context = parent frame
        assert rec["call_type"] == "delegatecall"
    finally:
        _restore(rt)


def test_erigon_fixture_delegatecall_semantics_preserved(pinned_fork):
    """Production-captured Erigon parity trace (hedgey_tx1 fixture): the pinned
    normalize_trace_node drops action.callType and mislabels DELEGATECALL frames
    CALL. The hook preserves the explicit metadata; the index must then bind
    code address = target implementation and execution context = caller frame."""
    import json
    fixture = json.load(open(os.path.join(FIXTURES, "hedgey_tx1_parity_trace.json")))
    trace_list = fixture["responses"]["trace_transaction"]
    rt = _runtime()
    try:
        from faultseeker.utils.rpc_provider import build_parity_tree, normalize_trace_node
        tree = build_parity_tree(trace_list)
        canonical = normalize_trace_node(tree)  # hooked: preserves action.callType
        # Real fixture: USDC proxy 0xa0b8... delegatecalls implementation
        # 0x4350... with selector 0x70a08231 (balanceOf).
        target = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"
        caller = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        found = {}
        def walk(n, parent=None):
            if str(n.get("call_type", "")).upper() == "DELEGATECALL" and str(n.get("callee") or n.get("to")).lower() == target:
                found["node"] = n
                found["parent"] = parent
            for c in n.get("children", []) or []:
                walk(c, n)
        walk(canonical)
        assert found, "hooked normalize must preserve DELEGATECALL frames from the real fixture"
        assert found["node"]["function_selector"] == "0x70a08231"
        rt.sequence = {"canonical_trace": canonical}
        idx = rt._frame_code_index()
        entry = idx[(target, "0x70a08231")]
        assert entry["code_address"] == target           # implementation whose code runs
        assert entry["execution_context"] == caller      # storage context: USDC proxy frame
        assert entry["call_type"] == "delegatecall"
        # Documentary: without the hook the pinned producer mislabels these frames.
        _restore(rt)
        from faultseeker.utils.rpc_provider import normalize_trace_node as unhooked
        bare = unhooked(build_parity_tree(trace_list))
        types = set()
        def walk2(n):
            types.add(str(n.get("call_type", "")).upper())
            for c in n.get("children", []) or []:
                walk2(c)
        walk2(bare)
        assert "DELEGATECALL" not in types  # pinned engine loses the metadata; the hook restores it
    finally:
        _restore(rt)


def test_frame_index_rebuilt_when_trace_replaced(pinned_fork):
    m = importlib.import_module("app.pipeline_guards")
    addr_a = "0x1111111111111111111111111111111111111111"
    addr_b = "0x2222222222222222222222222222222222222222"
    rt = _runtime()
    try:
        rt.selector_bindings = {
            addr_a: {"selectors": {"0xefd86b62": {"name": "f", "signature": "f()", "input_count": 0, "input_types": []}}},
            addr_b: {"selectors": {"0xefd86b62": {"name": "g", "signature": "g()", "input_count": 0, "input_types": []}}},
        }
        rt.sequence = {"trace": {"address": addr_a, "function": "0xefd86b62",
                                 "call_type": "call", "children": []}}
        stub, FA = _analyzer_stub({addr_a: {"f": [{"path": ".", "start_line": 1, "end_line": 2,
                                                   "content": "function f() {}"}]},
                                   addr_b: {"g": [{"path": ".", "start_line": 1, "end_line": 2,
                                                   "content": "function g() {}"}]}})
        out_a = FA._retrieve_source_code(stub, addr_a, "0xefd86b62")
        assert rt.selector_resolution_log[-1]["resolved_name"] == "f"
        # Replace the trace: the index must rebuild, never reuse trace A's mapping.
        rt.sequence = {"trace": {"address": addr_b, "function": "0xefd86b62",
                                 "call_type": "call", "children": []}}
        out_b = FA._retrieve_source_code(stub, addr_b, "0xefd86b62")
        rec = rt.selector_resolution_log[-1]
        assert rec["resolved_name"] == "g" and rec["code_address"] == addr_b
        assert out_b and "function g()" in out_b[0]["source_code"]
        # And the old trace's address no longer resolves (no observed frame there).
        out_old = FA._retrieve_source_code(stub, addr_a, "0xefd86b62")
        assert out_old == []
        assert rt.selector_resolution_log[-1]["reason"] == "no_observed_frame"
    finally:
        _restore(rt)


def test_overloaded_source_units_disambiguated_or_fail(pinned_fork):
    """Multiple same-name source bodies: bind the exact unit whose canonical
    input types match the ABI signature. Arity alone is NOT sufficient
    (foo(uint256) vs foo(address)); unmatched or undecidable -> fail unresolved."""
    m = importlib.import_module("app.pipeline_guards")
    addr = "0x3333333333333333333333333333333333333333"
    rt = _runtime()
    try:
        rt.sequence = {"trace": {"address": addr, "function": "0xefd86b62",
                                 "call_type": "call", "children": []}}
        # Same-arity overloads: only canonical TYPES distinguish them.
        body_uint = "function foo(uint256 x) external { _use(x); }"
        body_addr = "function foo(address y) external { _use(y); }"
        rt.selector_bindings[addr] = {"selectors": {
            "0xefd86b62": {"name": "foo", "signature": "foo(address)",
                           "input_count": 1, "input_types": ["address"]}}}
        stub, FA = _analyzer_stub({addr: {"foo": [
            {"path": "./U.sol", "start_line": 1, "end_line": 1, "content": body_uint},
            {"path": "./A.sol", "start_line": 1, "end_line": 1, "content": body_addr}]}})
        out = FA._retrieve_source_code(stub, addr, "0xefd86b62")
        assert len(out) == 1 and out[0]["source_code"] == body_addr  # types decide, not arity
        rec = rt.selector_resolution_log[-1]
        assert rec["unit_binding"]["disambiguated_by"] == "canonical_input_types_vs_source_header"
        assert rec["unit_binding"]["selected_path"] == "./A.sol"
        # Struct/enum params are not parser-comparable: two such overloads cannot
        # be distinguished -> fail unresolved, never guess.
        rt.selector_bindings[addr] = {"selectors": {
            "0xefd86b62": {"name": "foo", "signature": "foo((address,uint256))",
                           "input_count": 1, "input_types": ["(address,uint256)"],
                           "input_internal_types": ["struct X.B"]}}}
        stub2, FA2 = _analyzer_stub({addr: {"foo": [
            {"path": "./S1.sol", "start_line": 1, "end_line": 1, "content": "function foo(X.A memory a) external { _use(a); }",
             "decl_index": {"decls": {"A": [("X.A", "X")]}, "kinds": {"X.A": "struct"}, "fields": {}, "scopes": []}},
            {"path": "./S2.sol", "start_line": 1, "end_line": 1, "content": "function foo(X.B memory b) external { _use(b); }",
             "decl_index": {"decls": {"B": [("X.B", "X")]}, "kinds": {"X.B": "struct"}, "fields": {}, "scopes": []}}]}})
        out2 = FA2._retrieve_source_code(stub2, addr, "0xefd86b62")
        # structA vs structB: qualified internalType identity selects B, arity cannot
        assert len(out2) == 1 and "X.B memory b" in out2[0]["source_code"]
        rec2 = rt.selector_resolution_log[-1]
        assert rec2["status"] == "resolved"
        # Same pair with UNQUALIFIED names: namespace identity unproven ->
        # fail closed even though internalType names a unique struct
        stub2q, FA2q = _analyzer_stub({addr: {"foo": [
            {"path": "./S1.sol", "start_line": 1, "end_line": 1, "content": "function foo(A memory a) external { _use(a); }"},
            {"path": "./S2.sol", "start_line": 1, "end_line": 1, "content": "function foo(B memory b) external { _use(b); }"}]}})
        out2q = FA2q._retrieve_source_code(stub2q, addr, "0xefd86b62")
        assert out2q == []
        assert rt.selector_resolution_log[-1]["status"] == "ambiguous_overload"
        # One proven match + one UNDECIDABLE candidate: the undecidable one
        # might be the ABI-matched overload -> fail closed, no silent select.
        rt.selector_bindings[addr] = {"selectors": {
            "0xefd86b62": {"name": "foo", "signature": "foo((address,uint256))",
                           "input_count": 1, "input_types": ["(address,uint256)"],
                           "input_internal_types": ["struct X.B"]}}}
        stub2c, FA2c = _analyzer_stub({addr: {"foo": [
            {"path": "./S1.sol", "start_line": 1, "end_line": 1, "content": "// no header here"},
            {"path": "./S2.sol", "start_line": 1, "end_line": 1, "content": "function foo(X.B memory b) external { _use(b); }",
             "decl_index": {"decls": {"B": [("X.B", "X")]}, "kinds": {"X.B": "struct"}, "fields": {}, "scopes": []}}]}})
        out2c = FA2c._retrieve_source_code(stub2c, addr, "0xefd86b62")
        assert out2c == []
        assert rt.selector_resolution_log[-1]["status"] == "ambiguous_overload"
        # Without internalType the same pair is indistinguishable -> ambiguous
        rt.selector_bindings[addr] = {"selectors": {
            "0xefd86b62": {"name": "foo", "signature": "foo((address,uint256))",
                           "input_count": 1, "input_types": ["(address,uint256)"]}}}
        stub2b, FA2b = _analyzer_stub({addr: {"foo": [
            {"path": "./S1.sol", "start_line": 1, "end_line": 1, "content": "function foo(A memory a) external { _use(a); }"},
            {"path": "./S2.sol", "start_line": 1, "end_line": 1, "content": "function foo(B memory b) external { _use(b); }"}]}})
        out2b = FA2b._retrieve_source_code(stub2b, addr, "0xefd86b62")
        assert out2b == []
        rec2b = rt.selector_resolution_log[-1]
        assert rec2b["status"] == "ambiguous_overload" and rec2b["matching_signature"] == 0
        # Single candidate whose header disagrees with the ABI signature: the
        # source does not describe the ABI's function -> unresolved, not bound.
        rt.selector_bindings[addr] = {"selectors": {
            "0xefd86b62": {"name": "foo", "signature": "foo(uint256)",
                           "input_count": 1, "input_types": ["uint256"]}}}
        stub3, FA3 = _analyzer_stub({addr: {"foo": [
            {"path": "./M.sol", "start_line": 1, "end_line": 1, "content": body_addr}]}})
        out3 = FA3._retrieve_source_code(stub3, addr, "0xefd86b62")
        assert out3 == []
        assert rt.selector_resolution_log[-1]["reason"] == "signature_mismatch"
        # Single candidate with non-elementary params (Hedgey shape): ABI is
        # unique per (name, signature) and the explorer verified both against
        # the same bytecode - bound as a single candidate.
        hedgey_body = ("function createLockedCampaign(bytes16 id, Campaign memory campaign, "
                       "ClaimLockup memory claimLockup, Donation memory donation) external {}")
        rt.selector_bindings[addr] = {"selectors": {
            "0xefd86b62": {"name": "createLockedCampaign",
                           "signature": "createLockedCampaign(bytes16,(...),(...),(...))",
                           "input_count": 4,
                           "input_types": ["bytes16", "(address,address,uint256,uint256,uint8,bytes32)",
                                           "(address,uint256,uint256,uint256,uint256)",
                                           "(address,uint256,uint256,uint256,uint256,uint256)"],
                           "input_internal_types": ["bytes16", "struct ClaimCampaigns.Campaign",
                                                    "struct ClaimCampaigns.ClaimLockup",
                                                    "struct ClaimCampaigns.Donation"],
                           "input_components": [None,
                                                ["address", "address", "uint256", "uint256", "uint8", "bytes32"],
                                                ["address", "uint256", "uint256", "uint256", "uint256"],
                                                ["address", "uint256", "uint256", "uint256", "uint256"]]}}}
        decl_index = {"decls": {"Campaign": [("ClaimCampaigns.Campaign", "ClaimCampaigns")],
                                "ClaimLockup": [("ClaimCampaigns.ClaimLockup", "ClaimCampaigns")],
                                "Donation": [("ClaimCampaigns.Donation", "ClaimCampaigns")]},
                      "kinds": {"ClaimCampaigns.Campaign": "struct",
                                "ClaimCampaigns.ClaimLockup": "struct",
                                "ClaimCampaigns.Donation": "struct"},
                      "fields": {"ClaimCampaigns.Campaign": ["address", "address", "uint256", "uint256", "uint8", "bytes32"],
                                 "ClaimCampaigns.ClaimLockup": ["address", "uint256", "uint256", "uint256", "uint256"],
                                 "ClaimCampaigns.Donation": ["address", "uint256", "uint256", "uint256", "uint256"]},
                      "scopes": [("ClaimCampaigns", 0, 999)]}
        stub4, FA4 = _analyzer_stub({addr: {"createLockedCampaign": [
            {"path": "./ClaimCampaigns.sol", "start_line": 1, "end_line": 2, "content": hedgey_body,
             "decl_index": decl_index, "fn_scope": "ClaimCampaigns"}]}})
        out4 = FA4._retrieve_source_code(stub4, addr, "0xefd86b62")
        # Unqualified names PROVEN by the declaration index + field layouts.
        assert len(out4) == 1
        assert rt.selector_resolution_log[-1]["status"] == "resolved"
        # Without the declaration index the same header stays unproven.
        stub4u, FA4u = _analyzer_stub({addr: {"createLockedCampaign": [
            {"path": "./ClaimCampaigns.sol", "start_line": 1, "end_line": 2, "content": hedgey_body}]}})
        out4u = FA4u._retrieve_source_code(stub4u, addr, "0xefd86b62")
        assert out4u == []
        assert rt.selector_resolution_log[-1]["reason"] == "type_identity_unsupported"
        # A same-named struct with a DIFFERENT layout is a mismatch, not a bind.
        bad_fields = {"decls": decl_index["decls"], "kinds": decl_index["kinds"],
                      "scopes": decl_index["scopes"],
                      "fields": {**decl_index["fields"],
                                 "ClaimCampaigns.Campaign": ["address", "address", "uint256", "uint256", "uint8", "uint128"]}}
        stub4b, FA4b = _analyzer_stub({addr: {"createLockedCampaign": [
            {"path": "./ClaimCampaigns.sol", "start_line": 1, "end_line": 2, "content": hedgey_body,
             "decl_index": bad_fields, "fn_scope": "ClaimCampaigns"}]}})
        out4b = FA4b._retrieve_source_code(stub4b, addr, "0xefd86b62")
        assert out4b == []
        assert rt.selector_resolution_log[-1]["reason"] == "signature_mismatch"
        # The same shape with QUALIFIED type names binds by exact identity.
        qualified_body = ("function createLockedCampaign(bytes16 id, "
                          "ClaimCampaigns.Campaign memory campaign, "
                          "ClaimCampaigns.ClaimLockup memory claimLockup, "
                          "ClaimCampaigns.Donation memory donation) external {}")
        stub4q, FA4q = _analyzer_stub({addr: {"createLockedCampaign": [
            {"path": "./ClaimCampaigns.sol", "start_line": 1, "end_line": 2, "content": qualified_body,
             "decl_index": decl_index, "fn_scope": "ClaimCampaigns"}]}})
        out4q = FA4q._retrieve_source_code(stub4q, addr, "0xefd86b62")
        assert len(out4q) == 1
        assert rt.selector_resolution_log[-1]["unit_binding"]["disambiguated_by"] == "single_candidate_exact_types"
        assert (rt.selector_resolution_log[-1]["unit_binding"]["evidence_basis"]
                == "abi_internal_type_and_canonical_match")
        # Single candidate whose header CANNOT be parsed (not merely
        # non-elementary): uniqueness of a name-based lookup is not evidence
        # that this unit is the ABI-matched function -> unresolved, not bound.
        rt.selector_bindings[addr] = {"selectors": {
            "0xefd86b62": {"name": "foo", "signature": "foo(uint256)",
                           "input_count": 1, "input_types": ["uint256"]}}}
        stub5, FA5 = _analyzer_stub({addr: {"foo": [
            {"path": "./X.sol", "start_line": 1, "end_line": 1,
             "content": "// truncated body, no header"}]}})
        out5 = FA5._retrieve_source_code(stub5, addr, "0xefd86b62")
        assert out5 == []
        assert rt.selector_resolution_log[-1]["status"] == "unresolved"
        assert rt.selector_resolution_log[-1]["reason"] == "type_identity_unsupported"
        # Single candidate with a PARSED non-elementary header whose arity
        # disagrees with the ABI (1 source param vs 2 ABI inputs): a concrete
        # source/ABI disagreement, not an incomparable type -> unresolved.
        rt.selector_bindings[addr] = {"selectors": {
            "0xefd86b62": {"name": "foo", "signature": "foo(uint256,uint256)",
                           "input_count": 2, "input_types": ["uint256", "uint256"]}}}
        stub6, FA6 = _analyzer_stub({addr: {"foo": [
            {"path": "./Y.sol", "start_line": 1, "end_line": 1,
             "content": "function foo(Campaign memory campaign) external { _use(campaign); }"}]}})
        out6 = FA6._retrieve_source_code(stub6, addr, "0xefd86b62")
        assert out6 == []
        assert rt.selector_resolution_log[-1]["status"] == "unresolved"
        assert rt.selector_resolution_log[-1]["reason"] == "signature_mismatch"
    finally:
        _restore(rt)


def test_source_header_params_vectors(pinned_fork):
    m = importlib.import_module("app.pipeline_guards")
    f = m.PipelineRuntime._source_header_params
    assert f("function transfer(address to) external {}") == ("ok", ["address"])
    assert f("function transfer(address to, uint256 amt) external {}") == ("ok", ["address", "uint256"])
    assert f("function f() {}") == ("ok", [])
    assert f("function u(uint x) {}") == ("ok", ["uint256"])            # alias normalized
    assert f("function b(byte x) {}") == ("ok", ["bytes1"])             # alias normalized
    assert f("function p(address payable to) {}") == ("ok", ["address"])
    assert f("function g(bytes32[] calldata xs, uint256 amt) {}") == ("ok", ["bytes32[]", "uint256"])
    assert f("function h(uint8[3] memory xs) {}") == ("ok", ["uint8[3]"])
    assert f("function s(Campaign memory c) {}") == ("non_elementary", 1)   # struct: parsed, not comparable
    assert f("function e(TokenLockup t) {}") == ("non_elementary", 1)       # enum: parsed, not comparable
    assert f("function s(Campaign[] memory c) {}") == ("non_elementary", 1) # struct array
    assert f("function d(IERC20.Token memory t) {}") == ("non_elementary", 1)  # dotted user type
    assert f("function m(bytes16 id, Campaign memory c) {}") == ("non_elementary", 2)  # count retained
    # unparseable is NOT non_elementary: no single-candidate exception for these
    assert f("no function here") == ("unparseable", None)
    assert f("function broken(address to {}") == ("unparseable", None)         # unbalanced parens
    assert f("function u(uint257 x) {}") == ("unparseable", None)              # misspelled elementary
    assert f("function b(bytes33 x) {}") == ("unparseable", None)              # misspelled elementary
    assert f("function x(a b c) {}") == ("unparseable", None)                  # malformed parameter


def test_delegatecall_restoration_via_production_trace_route(monkeypatch, pinned_fork):
    """R2/R6 blocker: exercise the ACTUAL production trace-acquisition entry
    point (TxnReplayer._rpc_structured_trace), not the hooked functions
    directly. The engine's call sites import build_parity_tree and
    normalize_trace_node function-locally (txn_replayer.py), so the runtime
    replace() hooks are picked up at call time; this test proves the canonical
    trace that production receives preserves the Erigon delegatecall frames."""
    import json
    from faultseeker.data_collection import txn_replayer as tr
    fixture = json.load(open(os.path.join(FIXTURES, "hedgey_tx1_parity_trace.json")))
    trace_list = fixture["responses"]["trace_transaction"]

    def fake_rpc_call(chain, method, params, timeout=None):
        if method == "trace_replayTransaction":
            return {"trace": trace_list, "stateDiff": {}}
        return None  # debug_traceTransaction variants: force the parity path

    monkeypatch.setattr(tr, "rpc_call", fake_rpc_call)
    rt = _runtime()  # installs the runtime replace() hooks, as production does
    try:
        result = tr.TransactionReplayer._rpc_structured_trace(
            "0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517", "eth")
        assert result and result.get("trace"), "production route returned no canonical trace"
        canonical = result["trace"]
        target = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"   # USDC implementation
        caller = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"   # USDC proxy
        found = {}
        def walk(n):
            if str(n.get("call_type", "")).upper() == "DELEGATECALL" \
                    and str(n.get("callee") or n.get("to")).lower() == target:
                found["node"] = n
            for c in n.get("children", []) or []:
                walk(c)
        walk(canonical)
        assert found, "production-route canonical trace lost the DELEGATECALL frame"
        assert found["node"]["function_selector"] == "0x70a08231"
        rt.sequence = {"canonical_trace": canonical}
        idx = rt._frame_code_index()
        entry = idx[(target, "0x70a08231")]
        assert entry["code_address"] == target
        assert entry["execution_context"] == caller
        assert entry["call_type"] == "delegatecall"
    finally:
        _restore(rt)


def test_header_matches_abi_exact_type_identity(pinned_fork):
    m = importlib.import_module("app.pipeline_guards")
    f = m.PipelineRuntime._header_matches_abi
    # elementary exact
    assert f("function f(address to, uint x) {}", ["address", "uint256"], ["address", "uint256"]) is True
    # enum vs uint: ABI enum (canonical uint8) must NOT match a plain uint8 source token
    assert f("function f(uint8 x) {}", ["uint8"], ["enum X.Status"]) is False
    # enum source token matches ABI enum internalType (qualified full path),
    # provable only WITH a declaration index establishing the kind
    idx_x = {"decls": {"Status": [("X.Status", "X")], "Campaign": [("X.Campaign", "X")]},
             "kinds": {"X.Status": "enum", "X.Campaign": "struct"},
             "fields": {"X.Campaign": ["address"]}, "scopes": [("X", 0, 999)]}
    assert f("function f(X.Status s) {}", ["uint8"], ["enum X.Status"], None, idx_x) is True
    # no declaration index: name identity alone is NOT proof -> unresolved
    assert f("function f(X.Status s) {}", ["uint8"], ["enum X.Status"]) is None
    # wrong enum path: a proven NAME mismatch needs no index
    assert f("function f(Y.Status s) {}", ["uint8"], ["enum X.Status"]) is False
    # struct array shape must match canonical ABI array shape
    assert f("function f(X.Campaign[] memory c) {}", ["(address)[]"], ["struct X.Campaign[]"], None, idx_x) is True
    assert f("function f(X.Campaign[] memory c) {}", ["(address)[]"], ["struct X.Campaign[]"]) is None
    assert f("function f(X.Campaign[] memory c) {}", ["(address)"], ["struct X.Campaign"], None, idx_x) is False
    # user-defined source token with no ABI internalType: cannot prove -> None
    assert f("function f(Campaign memory c) {}", ["(address)"], [""]) is None
    # unparseable -> None
    assert f("garbage", ["uint256"], ["uint256"]) is None
    # arity mismatch -> False
    assert f("function f(uint a) {}", ["uint256", "uint256"], ["uint256", "uint256"]) is False
    # qualified source name: full dotted path must equal the ABI internalType's,
    # and (with an index) the declaration kind must agree
    assert f("function f(X.Campaign memory c) {}", ["(address)"], ["struct X.Campaign"], None, idx_x) is True
    assert f("function f(X.Campaign memory c) {}", ["(address)"], ["struct X.Campaign"]) is None
    assert f("function f(Y.Campaign memory c) {}", ["(address)"], ["struct X.Campaign"]) is False
    # unqualified user-defined names are ALWAYS unproven without source-context
    # resolution - even when unique among the signature's inputs (the header's
    # Campaign could be an imported/inherited Y.Campaign absent from the ABI)
    assert f("function f(Campaign memory c, Lock memory l) {}", ["(address)", "(address)"],
             ["struct X.Campaign", "struct X.Lock"]) is None
    assert f("function f(Campaign memory a, Campaign memory b) {}", ["(address)", "(address)"],
             ["struct X.Campaign", "struct X.Campaign"]) is None


def test_declaration_scope_provenance(pinned_fork):
    """Namespace proof is scoped to the function's OWN enclosing contract (or a
    unique file-level declaration). A same-name declaration in ANOTHER contract
    of the same file - or import/inheritance ambiguity - never proves it."""
    m = importlib.import_module("app.pipeline_guards")
    P = m.PipelineRuntime
    src = (
        "contract A {\n"
        "  struct Item { address a; uint256 b; }\n"
        "  function f(Item memory x) external {}\n"
        "}\n"
        "contract B {\n"
        "  struct Item { address a; }\n"
        "  function g(Item memory x) external {}\n"
        "}\n")
    idx = P._declaration_index(src)
    assert idx["decls"]["Item"] == [("A.Item", "A"), ("B.Item", "B")]
    # function in A: its own scope's declaration proves the name
    assert P._resolve_decl(idx, "Item", "A") == "A.Item"
    assert P._resolve_decl(idx, "Item", "B") == "B.Item"
    # unknown scope (import/inheritance ambiguity): unproven
    assert P._resolve_decl(idx, "Item", "C") is None
    assert P._resolve_decl(idx, "Item", None) is None
    # file-level declaration proves for any contract scope, uniquely
    src2 = "struct Top { address a; }\ncontract C {\n  function h(Top memory t) external {}\n}\n"
    idx2 = P._declaration_index(src2)
    assert P._resolve_decl(idx2, "Top", "C") == "Top"
    # enclosing-contract declaration shadows a file-level one (Solidity rule)
    src3 = ("struct Top { address a; }\ncontract D {\n"
            "  struct Top { address a; uint256 b; }\n"
            "  function h(Top memory t) external {}\n}\n")
    idx3 = P._declaration_index(src3)
    assert P._resolve_decl(idx3, "Top", "D") == "D.Top"
    # end to end: function in B, ABI names A.Item -> mismatch; layout differs too
    body_b = "function g(Item memory x) external {}"
    v = P._header_matches_abi(body_b, ["(address,uint256)"], ["struct A.Item"],
                              [["address", "uint256"]], idx, fn_scope="B")
    assert v is False  # B.Item != A.Item: proven mismatch, not a bind


def test_declaration_kind_identity(pinned_fork):
    """A matched NAME is not a matched TYPE when declaration kinds differ:
    ABI enum vs source struct of the same qualified name is a proven mismatch;
    unknown kind is unresolved; contract-typed params resolve via contract decls."""
    m = importlib.import_module("app.pipeline_guards")
    P = m.PipelineRuntime
    src = ("contract Vault {\n"
           "  struct Campaign { uint256 amount; }\n"
           "  function execute(Campaign calldata c, Vault v) external {}\n"
           "}\n")
    idx = P._declaration_index(src)
    assert idx["kinds"]["Vault.Campaign"] == "struct"
    assert idx["kinds"]["Vault"] == "contract"
    body = "function execute(Campaign calldata c, Vault v) external {}"
    # ABI says enum Vault.Campaign: proven kind mismatch
    assert P._header_matches_abi(body, ["uint8", "address"],
                                 ["enum Vault.Campaign", "contract Vault"],
                                 [None, None], idx, fn_scope="Vault") is False
    # ABI says struct: kinds agree, layout checked
    assert P._header_matches_abi(body, ["(uint256)", "address"],
                                 ["struct Vault.Campaign", "contract Vault"],
                                 [["uint256"]], idx, fn_scope="Vault") is True
    # declaration context present but kind not established -> unresolved
    idx_nk = {"decls": {"Campaign": [("Vault.Campaign", "Vault")]}, "kinds": {},
              "fields": {}, "scopes": [("Vault", 0, 999)]}
    assert P._header_matches_abi(body, ["(uint256)", "address"],
                                 ["struct Vault.Campaign", "contract Vault"],
                                 [["uint256"]], idx_nk, fn_scope="Vault") is None
    # unknown enclosing scope: unique file-level declaration still unproven
    src2 = "struct Top { address a; }\ncontract C { function h(Top memory t) external {} }\n"
    idx2 = P._declaration_index(src2)
    assert P._resolve_decl(idx2, "Top", None) is None
    assert P._resolve_decl(idx2, "Top", "C") == "Top"


def test_indented_contract_scope_provenance(pinned_fork):
    """Indented contract declarations still establish scope; a same-name struct
    in a DIFFERENT indented contract never proves the name."""
    m = importlib.import_module("app.pipeline_guards")
    P = m.PipelineRuntime
    src = ("    contract A {\n"
           "      struct Item { address a; uint256 b; }\n"
           "      function f(Item memory x) external {}\n"
           "    }\n"
           "\tcontract B {\n"
           "\t  struct Item { address a; }\n"
           "\t}\n")
    idx = P._declaration_index(src)
    assert idx["decls"]["Item"] == [("A.Item", "A"), ("B.Item", "B")]
    assert P._resolve_decl(idx, "Item", "A") == "A.Item"
    assert P._resolve_decl(idx, "Item", "B") == "B.Item"
    body = "function f(Item memory x) external {}"
    assert P._header_matches_abi(body, ["(address,uint256)"], ["struct A.Item"],
                                 [["address", "uint256"]], idx, fn_scope="A") is True
    assert P._header_matches_abi(body, ["(address)"], ["struct B.Item"],
                                 [["address"]], idx, fn_scope="A") is False


def test_string_literals_cannot_fabricate_declarations(pinned_fork):
    """Adversarial: declaration keywords and braces inside Solidity string
    literals are DATA. They must not register declarations, shift scope, or
    produce a successful binding."""
    m = importlib.import_module("app.pipeline_guards")
    P = m.PipelineRuntime
    # fake struct/enum/contract inside string literals, escaped quotes, braces
    src = (
        'contract CampaignManager {\n'
        '  string constant DECOY = "struct Campaign { uint256 amount; }";\n'
        "  string constant DECOY2 = 'enum TokenLockup { A, B }';\n"
        '  string constant DECOY3 = "} contract Evil { struct X { uint256 y; }";\n'
        '  string constant ESC = "q \\\" struct Nope { uint256 z; } \\\" end";\n'
        "  struct Real { address a; }\n"
        "  function execute(Real memory r) external {}\n"
        "}\n")
    idx = P._declaration_index(src)
    # no fabricated declarations from string content
    assert "Campaign" not in idx["decls"]
    assert "TokenLockup" not in idx["decls"]
    assert "Evil" not in idx["decls"] and "Nope" not in idx["decls"]
    # braces inside strings did not break scope tracking of the REAL struct
    assert idx["decls"].get("Real") == [("CampaignManager.Real", "CampaignManager")]
    assert idx["kinds"].get("CampaignManager.Real") == "struct"
    # the real function still binds against its real struct
    body = "function execute(Real memory r) external {}"
    assert P._header_matches_abi(body, ["(address)"], ["struct CampaignManager.Real"],
                                 [["address"]], idx, fn_scope="CampaignManager") is True
    # and an ABI naming the decoy cannot bind: the name is unproven
    assert P._header_matches_abi(body, ["(uint256)"], ["struct CampaignManager.Campaign"],
                                 [["uint256"]], idx, fn_scope="CampaignManager") in (None, False)
    # unterminated string blanks to EOF: nothing after it can be proven
    src2 = 'contract C {\n  string s = "oops;\n  struct Late { uint256 x; }\n}\n'
    idx2 = P._declaration_index(src2)
    assert "Late" not in idx2["decls"]


def test_multiline_comment_offsets_and_scope(pinned_fork):
    """Block comments are blanked length- and newline-preservingly: offsets map
    1:1 to the original source, comment contents register no declarations, and
    scope provenance across a multiline comment is correct (cross-contract
    same-name still fails)."""
    m = importlib.import_module("app.pipeline_guards")
    P = m.PipelineRuntime
    src = ("contract A {\n"
           "    /*\n"
           "       decoy: struct Campaign { address zzz; }\n"
           "    */\n"
           "    struct Campaign { uint256 id; }\n"
           "    function execute(Campaign calldata c) external {}\n"
           "}\n"
           "contract B {\n"
           "    struct Campaign { address owner; }\n"
           "}\n")
    blanked = P._strip_comments_and_strings(src)
    assert len(blanked) == len(src)
    assert [i for i, c in enumerate(src) if c == "\n"] == [i for i, c in enumerate(blanked) if c == "\n"]
    idx = P._declaration_index(src)
    # the decoy inside the block comment registered nothing
    assert idx["decls"]["Campaign"] == [("A.Campaign", "A"), ("B.Campaign", "B")]
    # scope spans are valid ORIGINAL byte offsets: the function's line lands in A
    off = sum(len(l) + 1 for l in blanked.split("\n")[:5])
    assert next((n for n, s, e in idx["scopes"] if s <= off <= e), None) == "A"
    body = "function execute(Campaign calldata c) external {}"
    assert P._header_matches_abi(body, ["(uint256)"], ["struct A.Campaign"],
                                 [["uint256"]], idx, fn_scope="A") is True
    assert P._header_matches_abi(body, ["(address)"], ["struct B.Campaign"],
                                 [["address"]], idx, fn_scope="A") is False


def test_utf8_multibyte_offsets_and_scope(pinned_fork):
    """Multibyte UTF-8 in comments/strings before a function cannot shift scope
    attribution: start_line is an ANTLR LINE NUMBER (ctx.start.line; the engine
    slices lines[start_line-1:end_line] on Python str lines), and the blanked
    text preserves exact Python length and newline positions, so the hook's
    line->offset math is consistent in character space end to end."""
    m = importlib.import_module("app.pipeline_guards")
    P = m.PipelineRuntime
    src = ("/* \xe9\xe9\xe9 \u20ac\u20ac\u20ac multibyte\n"
           "   still comment \U0001f600 */\n"
           "contract A {\n"
           '    string s = "\xe9\U0001f600 } contract Z { struct Q { uint256 q; }";\n'
           "    struct Campaign { uint256 id; }\n"
           "    function execute(Campaign calldata c) external {}\n"
           "}\n"
           "contract B {\n"
           "    struct Campaign { address owner; }\n"
           "}\n")
    blanked = P._strip_comments_and_strings(src)
    assert len(blanked) == len(src)
    assert [i for i, c in enumerate(src) if c == "\n"] == [i for i, c in enumerate(blanked) if c == "\n"]
    idx = P._declaration_index(src)
    # string/comment payloads with multibyte chars registered nothing
    assert idx["decls"]["Campaign"] == [("A.Campaign", "A"), ("B.Campaign", "B")]
    assert "Q" not in idx["decls"] and "Z" not in idx["decls"]
    # the hook's exact line->offset algorithm places the function in contract A
    lines = blanked.split("\n")
    fn_line = next(i for i, l in enumerate(lines) if "function execute" in l)
    off = sum(len(l) + 1 for l in lines[:fn_line])
    assert next((n for n, s, e in idx["scopes"] if s <= off <= e), None) == "A"
    body = "function execute(Campaign calldata c) external {}"
    assert P._header_matches_abi(body, ["(uint256)"], ["struct A.Campaign"],
                                 [["uint256"]], idx, fn_scope="A") is True
    # invariant: missing/unparseable field info never binds on name+kind alone
    idx_nf = {"decls": idx["decls"], "kinds": idx["kinds"], "fields": {}, "scopes": idx["scopes"]}
    assert P._header_matches_abi(body, ["(uint256)"], ["struct A.Campaign"],
                                 [["uint256"]], idx_nf, fn_scope="A") is None


@pytest.mark.skipif(os.getenv("FAULTSEEKER_LIVE_NETWORK") != "1",
                    reason="keyless Blockscout route; run explicitly, not in the offline suite")
def test_live_blockscout_binding_route(tmp_path, pinned_fork):
    rt = _runtime()
    try:
        rt._ensure_eth_explorer_fallback()
        import faultseeker.data_collection.contract_downloader as cd
        info = cd.ContractDownloader("eth", [HEDGEY], output_dir=str(tmp_path / "out"),
                                     cache_dir=str(tmp_path / "cache")).run()
        assert "createLockedCampaign" in info.get(HEDGEY, {})
        rec = rt.selector_bindings[HEDGEY]
        assert rec["selectors"]["0xefd86b62"]["name"] == "createLockedCampaign"
        rt.sequence = _hedgey_trace()
        stub, FA = _analyzer_stub({HEDGEY: info[HEDGEY]})
        out = FA._retrieve_source_code(stub, HEDGEY, "0xefd86b62")
        assert out and "safeIncreaseAllowance" in out[0]["source_code"]
        assert rt.selector_resolution_log[-1]["status"] == "resolved"
    finally:
        _restore(rt)


def test_model_request_construction_includes_bound_source(pinned_fork, tmp_path):
    """Offline, no-model proof of the FULL production request construction: drive
    the real _retrieve_related_info -> function_call_info_summary ->
    _function_analysis_init path with the real Hedgey fixture, capture every
    payload handed to the model agents, and assert the COMPLETE bound root
    source bytes appear in the actual prompts (not merely that the binding
    method returned them). Canned agent responses stand in for the model; the
    construction code under test is the unmodified production code."""
    import networkx as nx
    from faultseeker.prompts.local_model_prompts import get_worker_prompts, get_vuln_prompts
    from faultseeker.prompts.function_analysis import (
        OrchestrationSessionPrompts, TaskCoordinatorPrompts, LocalTaskPrompts)
    m = importlib.import_module("app.pipeline_guards")
    rt = _runtime()
    try:
        rt.selector_bindings[HEDGEY] = {"selectors": m.PipelineRuntime._build_selector_map(_load_abi())}
        rt.sequence = _hedgey_trace()
        parsed = _parse_hedgey_source(tmp_path)
        stub, FA = _analyzer_stub({HEDGEY: parsed})
        bound = FA._retrieve_source_code(stub, HEDGEY, "0xefd86b62")
        assert bound and "createLockedCampaign" in bound[0]["source_code"]

        stub.fundflow_analysis = {"balance_change": {}}
        stub.txn_seq = {"address_calls": {}}
        stub.address_relation = nx.DiGraph()
        stub.session_prompts = OrchestrationSessionPrompts()
        stub.task_prompts = TaskCoordinatorPrompts()
        stub.function_prompts = get_worker_prompts("phi3:mini")
        stub.vulnerability_prompts = get_vuln_prompts("phi3:mini")
        stub.local_task_prompts = LocalTaskPrompts()
        stub.txn_analyzer_model = "gpt-4o-mini"
        stub.cost_tracker = None
        stub.task_tree = ""
        stub.current_task = ""
        stub.processing_result = ""
        stub.understanding_result = ""
        stub.potentially_vulnerable_functions = {}
        stub.children_call_memo_single = {}
        stub.children_call_memo = {}

        captured = {}

        class Capture:
            def __init__(self, name, reply):
                captured[name] = []
                self.name, self.reply = name, reply

            def query(self, user_message, *a, **k):
                captured[self.name].append(str(user_message))
                return self.reply

        stub.reasoning_agent = Capture("reasoning", "1. done")
        stub.organization_agent = Capture("organization", "understanding")
        stub.generation_agent = Capture("generation", "")  # task selection dies -> loop exits
        stub.processing_agent = Capture("processing", "")
        stub.children_call_filtering_agent = Capture("filtering", "")

        related_info = FA._retrieve_related_info(stub, HEDGEY, "0xefd86b62")
        assert related_info.get("function_source_code"), "binding produced no source for related info"
        # exactly the production shape (function_analyzer.py:707)
        stub.function_call_info_summary = {
            "function": "0xefd86b62", "address": HEDGEY, "appearance_count": 1,
            "calls": [],
            "function_call_related_info": {f"0xefd86b62::{HEDGEY}": related_info},
        }
        FA._function_analysis_init(stub)

        # prompts carry json.dumps(summary): the source's newlines/quotes are
        # JSON-escaped in the payload, so compare the escaped form
        full_source = bound[0]["source_code"]
        escaped = json.dumps(full_source)[1:-1]
        # understanding init (organization) and task-tree init (reasoning) both
        # serialize function_call_info_summary into the model-facing payload
        assert captured["organization"], "no understanding prompt was constructed"
        assert any(escaped in p for p in captured["organization"]), \
            "bound root source absent from the understanding payload"
        assert captured["reasoning"], "no analysis-init prompt was constructed"
        assert any(escaped in p for p in captured["reasoning"]), \
            "bound root source absent from the analysis-init payload"
        print("PROMPTLENS", {k: [len(p) for p in v] for k, v in captured.items()}, "srclen", len(full_source))
        # task-selection prompts also carry the summary (str(dict) form)
        assert captured["generation"], "no task-selection prompt was constructed"
        assert any("createLockedCampaign" in p for p in captured["generation"]), \
            "bound source absent from task-selection payloads"
    finally:
        _restore(rt)


# ---- outbound-boundary source retention (preview repair, 2026-11-05) ----

def _P():
    return importlib.import_module("app.pipeline_guards").PipelineRuntime


def test_preserve_bound_sources_component(pinned_fork):
    """COMPONENT test of the retention helper (synthetic strings)."""
    P = _P()
    src = "function f(address a) external {\n  _x(a);\n}\n" * 20   # ~800 chars
    forms = {"raw": src, "json": json.dumps(src)[1:-1], "repr": repr(src)[1:-1]}
    for name, form in forms.items():
        msg = ("A" * 6000) + form + ("B" * 6000)
        out, ev = P._preserve_bound_sources(msg, [src])
        assert ev["status"] == "preserved_other_text_trimmed", name
        assert len(out) <= 10000 and form in out, name
        assert "removed to preserve bound source" in out, name
    # under the cap or no source present: untouched, no event
    assert P._preserve_bound_sources("x" * 9999, [src]) == ("x" * 9999, None)
    big = "z" * 12000
    assert P._preserve_bound_sources(big, [src]) == (big, None)
    # oversized source cannot be preserved: message unchanged, explicit event
    huge = "function g() {\n" + "  y();\n" * 1700 + "}\n"
    m2 = ("P" * 3000) + huge + ("Q" * 3000)
    out2, ev2 = P._preserve_bound_sources(m2, [huge])
    assert out2 == m2 and ev2["status"] == "source_oversized_unpreserved"
    # source plus minimum context cannot fit -> fail closed even below 10000 source chars
    near = "s" * 9000
    m3 = "a" * 2000 + near + "b" * 2000
    out3, ev3 = P._preserve_bound_sources(m3, [near])
    assert ev3["status"] == "source_oversized_unpreserved" and out3 == m3


def test_outbound_boundary_retention_with_real_engine_truncation(pinned_fork, tmp_path):
    """OUTBOUND-BOUNDARY regression (synthetic padding, no model/network): real
    UniversalAgent._send_message wrapped by the production checked_send hook,
    capture below it at _llm_call_with_retry. Large model-written padding used
    to make the engine drop the bound source; now it is preserved, and an
    oversized source is reported as unpreserved."""
    import types
    from faultseeker.utils import agent as A
    m = importlib.import_module("app.pipeline_guards")
    rt = _runtime()
    sent = []

    def fake_call(create_client, kwargs, model, *a, **k):
        sent.append(kwargs["messages"][-1]["content"])
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=types.SimpleNamespace(content="ok"))], usage=None)

    rt.session = types.SimpleNamespace(assert_healthy=lambda: None, call=fake_call, route_policy=None)
    rt._model_config = None
    try:
        parsed = _parse_hedgey_source(tmp_path)
        rt.selector_bindings[HEDGEY] = {"selectors": m.PipelineRuntime._build_selector_map(_load_abi())}
        rt.sequence = _hedgey_trace()
        stub, FA = _analyzer_stub({HEDGEY: parsed})
        src = FA._retrieve_source_code(stub, HEDGEY, "0xefd86b62")[0]["source_code"]
        assert src in rt.bound_source_texts
        rt.install_model_hooks(A)
        agent = A.UniversalAgent("system", "qwen-plus", api_key="dummy")
        esc = json.dumps(src)[1:-1]
        # padded prompt: engine alone would drop the middle (source sits there)
        prompt = ("U" * 6000) + esc + ("T" * 6000)
        assert len(prompt) > 10000
        agent._send_message(prompt)
        assert esc in sent[-1] and len(sent[-1]) <= 10000
        assert "removed to preserve bound source" in sent[-1]
        assert rt.source_retention_events[-1]["status"] == "preserved_other_text_trimmed"
        # oversized source: engine truncation applies, event is explicit
        huge = "function g() {\n" + "  y();\n" * 1700 + "}\n"
        rt.bound_source_texts.append(huge)
        agent2 = A.UniversalAgent("system", "qwen-plus", api_key="dummy")
        agent2._send_message(("P" * 3000) + json.dumps(huge)[1:-1] + ("Q" * 3000))
        assert rt.source_retention_events[-1]["status"] == "source_oversized_unpreserved"
        assert "middle truncated" in sent[-1]
        # reporting: unpreserved source can never leave a run "fully analyzed"
    finally:
        _restore(rt)


def test_unpreserved_bound_source_marks_run_partial(pinned_fork):
    """Reporting (component test): an unpreserved source can never leave a run
    'completed' / fully analyzed; trimmed-but-preserved is a visible limitation."""
    from types import SimpleNamespace
    from pathlib import Path
    m = importlib.import_module("app.pipeline_guards")
    identity = importlib.import_module("app.trace_identity")
    fx = json.loads((Path(__file__).resolve().parent / "fixtures/hedgey_verified_trace.json").read_text())
    tx = fx["provenance"]["transaction_hash"]

    def run(events):
        rt = m.PipelineRuntime(tx, "eth")
        rt.sequence = identity.sequence_from_parity(fx["responses"]["trace_transaction"], tx, "eth")
        rt.session = SimpleNamespace(summary=lambda: {"calls": {"preflight": {"ok": 1}, "analysis": {"ok": 3, "failed": 0}}, "tokens": {}},
                                     assert_healthy=lambda: None)
        rt.source_retention_events = events
        return rt.annotate_result({"transaction_hash": tx, "chain": "eth", "analysis_status": "completed"})

    bad = run([{"status": "source_oversized_unpreserved", "original_chars": 15000, "protected_chars": 12000, "cap": 10000}])
    clean = run([])
    assert "source_retention" not in clean
    assert bad["analysis_status"] == "partial" and bad["stage_completed"] == "function-analysis-partial"
    assert bad["sections"]["function_analysis"] == "partial_bound_source_unpreserved"
    assert bad["source_retention"]["source_unpreserved"] == 1
    assert any("not fully analyzed" in l for l in bad["limitations"])
    trimmed = run([{"status": "preserved_other_text_trimmed", "original_chars": 11000, "protected_chars": 2000, "cap": 10000}])
    # trimming alone adds a limitation but does not change status/stage vs the baseline
    assert trimmed["analysis_status"] == clean["analysis_status"]
    assert trimmed.get("stage_completed") == clean.get("stage_completed")
    assert trimmed["source_retention"]["preserved_with_other_text_trimmed"] == 1
    assert any("trimmed" in l for l in trimmed["limitations"])
