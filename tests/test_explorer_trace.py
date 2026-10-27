import copy
import importlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
et = importlib.import_module("app.explorer_trace")
ti = importlib.import_module("app.trace_identity")
HEDGEY = json.loads((ROOT / "tests/fixtures/hedgey_verified_trace.json").read_text())
BS_ETH = json.loads((ROOT / "tests/fixtures/blockscout_eth_hedgey_raw_trace.json").read_text())
OP = json.loads((ROOT / "tests/fixtures/blockscout_optimism_raw_trace.json").read_text())
TX = HEDGEY["provenance"]["transaction_hash"]
ETH_TX = HEDGEY["responses"]["eth_getTransactionByHash"]
ETH_TX = ETH_TX.get("result", ETH_TX)
OP_HASH = OP["tx"]["hash"]


def test_eth_explorer_trace_equals_recorded_trace_and_binds_block_identity():
    rows = et.rows_from_parity(copy.deepcopy(BS_ETH), ETH_TX, TX, chain_id=1)
    got = ti.sequence_from_parity(rows, TX, "eth")
    want = ti.sequence_from_parity(HEDGEY["responses"]["trace_transaction"], TX, "eth")
    assert got["canonical_trace"] == want["canonical_trace"]
    assert got["trace_provenance"]["block_hash"] == want["trace_provenance"]["block_hash"]
    assert got["trace_provenance"]["block_number"] == 19687890 and rows[0]["transactionPosition"] == 27


@pytest.mark.parametrize("mutate", [
    lambda raw, tx: raw[0]["action"].__setitem__("input", "0xdeadbeef"),
    lambda raw, tx: raw[0]["action"].__setitem__("to", "0x" + "11" * 20),
    lambda raw, tx: raw[0]["action"].__setitem__("from", "0x" + "22" * 20),
    lambda raw, tx: raw.pop(0),                                # root missing
    lambda raw, tx: raw[1].__setitem__("type", "create"),
    lambda raw, tx: raw.append(copy.deepcopy(raw[1])),         # duplicate location
    lambda raw, tx: tx.__setitem__("hash", "0x" + "33" * 32),
    lambda raw, tx: tx.pop("blockHash"),
    lambda raw, tx: tx.__setitem__("chainId", "0x2"),
])
def test_eth_adapter_refuses_any_identity_gap(mutate):
    raw, tx = copy.deepcopy(BS_ETH), copy.deepcopy(ETH_TX)
    mutate(raw, tx)
    with pytest.raises(ti.TraceIdentityError):
        et.rows_from_parity(raw, tx, TX, chain_id=1)


def test_eth_adapter_refuses_non_list_and_empty():
    for bad in ({}, [], None, {"calls": []}):
        with pytest.raises(ti.TraceIdentityError):
            et.rows_from_parity(bad, ETH_TX, TX)


def test_optimism_calltracer_tree_becomes_verified_parity_rows():
    rows = et.rows_from_calltracer(copy.deepcopy(OP["raw_trace"]), OP["tx"], OP_HASH, chain_id=10)
    assert len(rows) == 66 and rows[0]["traceAddress"] == []
    assert all(r["blockNumber"] == 158747826 and r["transactionPosition"] == 35 for r in rows)
    seq = ti.sequence_from_parity(rows, OP_HASH, "optimism", verified_chain="optimism")
    assert seq["trace_provenance"]["frame_count"] == 66
    root = seq["canonical_trace"]
    assert root["callee"].lower() == OP["tx"]["to"].lower() and len(root["children"]) == rows[0]["subtraces"]


@pytest.mark.parametrize("mutate", [
    lambda t, tx: t.__setitem__("input", "0x00"),
    lambda t, tx: t.__setitem__("to", "0x" + "44" * 20),
    lambda t, tx: t["calls"][0].__setitem__("type", "CREATE"),
    lambda t, tx: tx.__setitem__("chainId", "0x1"),
    lambda t, tx: tx.pop("transactionIndex"),
])
def test_optimism_adapter_refuses_identity_gap(mutate):
    t, tx = copy.deepcopy(OP["raw_trace"]), copy.deepcopy(OP["tx"])
    mutate(t, tx)
    with pytest.raises(ti.TraceIdentityError):
        et.rows_from_calltracer(t, tx, OP_HASH, chain_id=10)


def test_reverted_internal_call_is_kept_and_labelled_not_dropped():
    rows = et.rows_from_calltracer(copy.deepcopy(OP["raw_trace"]), OP["tx"], OP_HASH, chain_id=10)
    reverted = [r for r in rows if r.get("error")]
    assert reverted and all(r["error"] == "execution reverted" for r in reverted)
