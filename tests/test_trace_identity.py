"""Canonical-target checks against a fetched historical trace, not invented calls."""
import copy
import importlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/fixtures/hedgey_verified_trace.json").read_text())
TX = FIXTURE["provenance"]["transaction_hash"]


def test_verified_trace_transaction_and_receipt_match():
    data = FIXTURE["responses"]
    root = data["trace_transaction"][0]
    assert root["transactionHash"] == data["eth_getTransactionByHash"]["hash"] == TX
    assert all(row["blockHash"] == data["eth_getTransactionReceipt"]["blockHash"] for row in data["trace_transaction"])
    assert data["eth_getTransactionReceipt"]["status"] == "0x1"
    # The observed transaction pulls a pre-existing allowance, not a campaign call.
    assert len(data["trace_transaction"]) == 5
    assert data["trace_transaction"][3]["action"]["input"].startswith("0x23b872dd")


def test_historical_updategho_label_is_not_a_verified_function_identity():
    from eth_utils import keccak
    name = "updateGhoBorrowRate(uint16,uint32,uint32,uint32)"
    calldata = FIXTURE["responses"]["eth_getTransactionByHash"]["input"]
    assert "0x" + keccak(text=name)[:4].hex() == calldata[:10]
    assert (len(calldata) - 10) // 64 == 2  # The displayed ABI requires four words.
    assert int(calldata[10:74], 16) > 65535  # First word cannot be a uint16.
    old = json.loads((ROOT / "app/samples/hedgey_e7c04c6fb037.result.json").read_text())
    assert old["scored_functions"][0]["function"] == "updateGhoBorrowRate"


def test_canonical_identity_keeps_selector_and_execution_context():
    m = importlib.import_module("app.trace_identity")
    result = m.sequence_from_parity(FIXTURE["responses"]["trace_transaction"], TX, "eth")
    root = result["trace"]
    assert root["function"] == "0xe32a9a37"
    assert root["address"] == "0xc793113f1548b97e37c409f39244ee44241bf2b3"
    assert root["children"][1]["function"] == "0x23b872dd"
    assert root["children"][1]["children"][0]["call_type"] == "delegatecall"
    assert "updateGhoBorrowRate" not in json.dumps(result)
    assert result["trace_provenance"]["block_hash"] == FIXTURE["provenance"]["block_hash"]


@pytest.mark.parametrize("chain,tx", [("bsc", TX), ("eth", "0x" + "1" * 64)])
def test_wrong_chain_or_hash_is_not_silently_accepted(chain, tx):
    m = importlib.import_module("app.trace_identity")
    with pytest.raises(m.TraceIdentityError):
        m.sequence_from_parity(FIXTURE["responses"]["trace_transaction"], tx, chain, verified_chain="eth")


@pytest.mark.parametrize("mutate", [
    lambda rows: [row.pop("blockHash") for row in rows],
    lambda rows: rows[1].__setitem__("traceAddress", []),  # duplicate root location
    lambda rows: rows[1].__setitem__("traceAddress", [-1]),
])
def test_sequence_from_parity_rejects_malformed_frame_identity(mutate):
    from app.trace_identity import sequence_from_parity, TraceIdentityError
    rows = copy.deepcopy(FIXTURE["responses"]["trace_transaction"])
    mutate(rows)
    with pytest.raises(TraceIdentityError):
        sequence_from_parity(rows, TX, "eth")


@pytest.mark.parametrize("kind", ["CREATE", "CREATE2"])
def test_creation_initcode_is_not_a_function_selector(kind):
    from app.trace_identity import canonical_to_legacy
    frame = canonical_to_legacy({"type": kind, "input": "0x60806040526000", "children": []})
    assert frame["function"] == kind.lower()
    assert frame["function_identity"] == "contract_creation"
    assert frame["params"] == "0x60806040526000"


def test_deep_trace_conversion_and_walk_are_iterative():
    from app.trace_identity import canonical_to_legacy
    from app.pipeline_guards import walk
    root = {"input": "0x", "children": []}
    current = root
    for _ in range(1023):
        child = {"input": "0x12345678", "children": []}
        current["children"] = [child]
        current = child
    result = canonical_to_legacy(root)
    assert sum(1 for _ in walk(result)) == 1024
    assert result["function_identity"] == "no_selector"


@pytest.mark.parametrize("mismatch", [None, "receipt_hash", "created_address", "caller", "input", "call_type"])
def test_creation_root_requires_receipt_and_transaction_provenance(mismatch):
    from app.trace_identity import validate_trace_root, TraceIdentityError
    tx_hash = "0x" + "a" * 64
    tx = {"hash": tx_hash, "to": None, "from": "0xsender", "input": "0x60806040"}
    root = {"type": "CREATE", "callee": "0xcreated", "caller": "0xsender", "input": "0x60806040"}
    receipt = {"transactionHash": tx_hash, "contractAddress": "0xcreated"}
    if mismatch == "receipt_hash": receipt["transactionHash"] = "0xother"
    if mismatch == "created_address": receipt["contractAddress"] = "0xother"
    if mismatch == "caller": root["caller"] = "0xother"
    if mismatch == "input": root["input"] = "0x12345678"
    if mismatch == "call_type": root["type"] = "CALL"
    if mismatch:
        with pytest.raises(TraceIdentityError): validate_trace_root(tx, root, tx_hash, receipt)
    else:
        validate_trace_root(tx, root, tx_hash, receipt)


def test_call_root_still_checks_destination():
    from app.trace_identity import validate_trace_root, TraceIdentityError
    tx = {"hash": "0xtx", "to": "0xright", "from": "0xsender", "input": "0x12345678"}
    root = {"type": "CALL", "callee": "0xwrong", "caller": "0xsender", "input": "0x12345678"}
    with pytest.raises(TraceIdentityError): validate_trace_root(tx, root, "0xtx")
