"""Canonical-target checks against a fetched historical trace, not invented calls."""
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
