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


# ---- fetch + pipeline payload --------------------------------------------------------------

class _Resp:
    def __init__(self, data, url):
        self._d, self._u = data, url
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def geturl(self): return self._u
    def read(self, n=-1): return self._d if n < 0 else self._d[:n]


def test_fetch_uses_one_verified_url_and_refuses_redirect_oversize_and_bad_input():
    seen = []
    def ok(request, timeout):
        seen.append((request.full_url, timeout))
        return _Resp(json.dumps(BS_ETH).encode(), request.full_url)
    assert et.fetch_raw_trace("eth", TX, opener=ok) == BS_ETH
    assert seen == [(f"https://eth.blockscout.com/api/v2/transactions/{TX}/raw-trace", 20)]
    with pytest.raises(ti.TraceIdentityError):
        et.fetch_raw_trace("eth", TX, opener=lambda r, timeout: _Resp(b"[]", "https://evil.example/x"))
    with pytest.raises(ti.TraceIdentityError):
        et.fetch_raw_trace("eth", TX, opener=lambda r, timeout: _Resp(b"x" * 3_000_000, r.full_url))
    with pytest.raises(ti.TraceIdentityError):
        et.fetch_raw_trace("eth", TX, opener=lambda r, timeout: _Resp(b"<html>", r.full_url))
    for chain, h in (("bsc", TX), ("eth", "0x12"), ("eth", TX + "/../x")):
        with pytest.raises(ti.TraceIdentityError):
            et.fetch_raw_trace(chain, h, opener=ok)


def test_payload_shapes_and_unknown_shape_refused():
    p = et.payload_from_explorer("eth", TX, ETH_TX, fetch=lambda c, h: copy.deepcopy(BS_ETH))
    assert p["trace"]["callee"].lower() == ETH_TX["to"].lower() and p["trace_provenance"]["source"] == "explorer_raw_trace"
    q = et.payload_from_explorer("optimism", OP_HASH, OP["tx"], fetch=lambda c, h: copy.deepcopy(OP["raw_trace"]))
    assert q["trace_provenance"]["frame_count"] == 66 and q["trace_provenance"]["frame_errors"] >= 1
    for bad in ("x", {"foo": 1}, 5):
        with pytest.raises(ti.TraceIdentityError):
            et.payload_from_explorer("eth", TX, ETH_TX, fetch=lambda c, h, b=bad: b)
    with pytest.raises(ti.TraceIdentityError):
        et.payload_from_explorer("polygon", TX, ETH_TX, fetch=lambda c, h: BS_ETH)


def _install(monkeypatch, tmp_path, tx, chain_id_hex, raise_trace=True):
    import os, sys
    repo = os.environ.get("FAULTSEEKER_TEST_PIPELINE_REPO")
    if not repo:
        pytest.skip("pinned pipeline checkout required")
    monkeypatch.syspath_prepend(repo)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "true")
    rp = importlib.import_module("faultseeker.utils.rpc_provider")
    rep = importlib.import_module("faultseeker.data_collection.txn_replayer")
    calls = []
    def fake_rpc(chain, method, params, timeout=None):
        calls.append(method)
        return {"eth_getTransactionByHash": tx, "eth_chainId": chain_id_hex}[method]
    monkeypatch.setattr(rp, "rpc_call", fake_rpc)
    def no_trace(self, tx_hash, chain):
        raise RuntimeError("no rpc trace")
    monkeypatch.setattr(rep.TransactionReplayer, "get_structured_trace", no_trace)
    m = importlib.import_module("app.pipeline_guards")
    runtime = m.PipelineRuntime(TX, "eth")
    return m, runtime, rep, calls


def test_runtime_uses_explorer_trace_only_when_opted_in_and_chain_id_matches(monkeypatch, tmp_path):
    m, runtime, rep, calls = _install(monkeypatch, tmp_path, copy.deepcopy(ETH_TX), "0x1")
    monkeypatch.setattr(et, "fetch_raw_trace", lambda c, h, opener=None: copy.deepcopy(BS_ETH))
    monkeypatch.setattr(m, "payload_from_explorer", lambda c, h, tx: et.payload_from_explorer(c, h, tx, fetch=lambda *a: copy.deepcopy(BS_ETH)))
    runtime.install()
    try:
        monkeypatch.delenv("FAULTSEEKER_EXPLORER_TRACE", raising=False)
        with pytest.raises(RuntimeError):                       # default off: unchanged behaviour
            rep.TransactionReplayer.get_structured_trace(object(), TX, "eth")
        monkeypatch.setenv("FAULTSEEKER_EXPLORER_TRACE", "1")
        payload = rep.TransactionReplayer.get_structured_trace(object(), TX, "eth")
        assert payload["trace_provenance"]["source"] == "explorer_raw_trace"
        assert payload["trace_provenance"]["block_number"] == ETH_TX["blockNumber"]
        assert "eth_chainId" in calls and "eth_getTransactionByHash" in calls
    finally:
        runtime.close()


def test_runtime_refuses_explorer_trace_when_rpc_chain_id_differs(monkeypatch, tmp_path):
    m, runtime, rep, calls = _install(monkeypatch, tmp_path, copy.deepcopy(ETH_TX), "0xa")
    monkeypatch.setattr(m, "payload_from_explorer", lambda c, h, tx: et.payload_from_explorer(c, h, tx, fetch=lambda *a: copy.deepcopy(BS_ETH)))
    monkeypatch.setenv("FAULTSEEKER_EXPLORER_TRACE", "1")
    runtime.install()
    try:
        with pytest.raises(ti.TraceIdentityError):
            rep.TransactionReplayer.get_structured_trace(object(), TX, "eth")
    finally:
        runtime.close()


def test_runtime_refuses_explorer_trace_with_tampered_root(monkeypatch, tmp_path):
    m, runtime, rep, calls = _install(monkeypatch, tmp_path, copy.deepcopy(ETH_TX), "0x1")
    bad = copy.deepcopy(BS_ETH); bad[0]["action"]["input"] = "0xdeadbeef"
    monkeypatch.setattr(m, "payload_from_explorer", lambda c, h, tx: et.payload_from_explorer(c, h, tx, fetch=lambda *a: bad))
    monkeypatch.setenv("FAULTSEEKER_EXPLORER_TRACE", "1")
    runtime.install()
    try:
        with pytest.raises(ti.TraceIdentityError):
            rep.TransactionReplayer.get_structured_trace(object(), TX, "eth")
    finally:
        runtime.close()
