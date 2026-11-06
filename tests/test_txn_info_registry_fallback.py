"""Regression: transaction info must come from the configured RPC when the explorer page is blocked.

Before this fix the fallback only queried hardcoded public nodes, ignoring
<CHAIN>_RPC_URL, so every run stopped at "Failed to collect transaction block info".
All network access is replaced with in-memory fakes.
"""
import pytest

from faultseeker.data_collection.txn_info_collector import TransactionInfoCollector

TX = "0x" + "ab" * 32
FROM = "0xAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaa"
TO = "0xBBBBbbbbBBBBbbbbBBBBbbbbBBBBbbbbBBBBbbbb"


@pytest.fixture
def blocked_explorer(monkeypatch):
    """Explorer HTML unavailable (WAF / offline): forces the RPC fallback path."""
    monkeypatch.setattr(TransactionInfoCollector, "_fetch_website_content", staticmethod(lambda url: None))


def _fake_rpc(receipt_status="0x1", calls=None):
    def rpc_call(chain, method, params, cacheable=False, timeout=None):
        if calls is not None:
            calls.append((chain, method, params))
        if method == "eth_getTransactionByHash":
            return {"hash": TX, "from": FROM, "to": TO, "blockNumber": "0x10"}
        if method == "eth_getTransactionReceipt":
            return {"status": receipt_status}
        raise AssertionError("unexpected RPC method " + method)
    return rpc_call


def _forbid_public(monkeypatch):
    def fail(rpc_url, txn_hash):
        raise AssertionError("hardcoded public RPC must not be used when the configured RPC answers")
    monkeypatch.setattr(TransactionInfoCollector, "_fetch_via_rpc", staticmethod(fail))


def test_configured_rpc_supplies_transaction_info(blocked_explorer, monkeypatch):
    import faultseeker.utils.rpc_provider as provider
    calls = []
    monkeypatch.setattr(provider, "rpc_call", _fake_rpc(calls=calls))
    _forbid_public(monkeypatch)
    result = TransactionInfoCollector().run(TX, "ETH")
    assert result["status"] == "Success"
    assert result["_source"] == "rpc_fallback"
    assert result["address_info"]["from_address"] == FROM.lower()
    assert result["address_info"]["to_address"] == [TO.lower()]
    assert result["block_number"]["block_number"] == 16
    assert [c[1] for c in calls] == ["eth_getTransactionByHash", "eth_getTransactionReceipt"]
    assert all(c[0] == "eth" and c[2] == [TX] for c in calls)


def test_reverted_receipt_is_not_reported_as_success(blocked_explorer, monkeypatch):
    import faultseeker.utils.rpc_provider as provider
    monkeypatch.setattr(provider, "rpc_call", _fake_rpc(receipt_status="0x0"))
    monkeypatch.setattr(TransactionInfoCollector, "_fetch_via_rpc", staticmethod(lambda url, h: {}))
    assert TransactionInfoCollector().run(TX, "eth") == {}


def test_registry_failure_falls_back_to_public_node(blocked_explorer, monkeypatch):
    import faultseeker.utils.rpc_provider as provider

    def broken(*args, **kwargs):
        raise RuntimeError("All providers failed")
    monkeypatch.setattr(provider, "rpc_call", broken)
    sentinel = {"status": "Success", "_source": "public-map"}
    monkeypatch.setattr(TransactionInfoCollector, "_fetch_via_rpc", staticmethod(lambda url, h: sentinel))
    assert TransactionInfoCollector().run(TX, "eth") == sentinel


def test_chain_without_public_node_still_works_through_registry(blocked_explorer, monkeypatch):
    import faultseeker.utils.rpc_provider as provider
    assert "LINEA" not in TransactionInfoCollector._CHAIN_RPC_MAP
    calls = []
    monkeypatch.setattr(provider, "rpc_call", _fake_rpc(calls=calls))
    result = TransactionInfoCollector().run(TX, "linea")
    assert result["status"] == "Success"
    assert calls[0][0] == "linea"


def test_missing_transaction_yields_empty_result(blocked_explorer, monkeypatch):
    import faultseeker.utils.rpc_provider as provider
    monkeypatch.setattr(provider, "rpc_call", lambda *a, **k: None)
    monkeypatch.setattr(TransactionInfoCollector, "_fetch_via_rpc", staticmethod(lambda url, h: {}))
    assert TransactionInfoCollector().run(TX, "eth") == {}
