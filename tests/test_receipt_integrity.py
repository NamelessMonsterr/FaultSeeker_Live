"""RPC fallback must not invent success when receipt evidence is absent."""
import io
import json

import pytest

from faultseeker.data_collection.txn_info_collector import TransactionInfoCollector


@pytest.mark.parametrize("receipt", [None, {}, {"status": None}, {"status": "0x2"},
                                    {"status": "0x0"}])
def test_missing_or_non_success_receipt_is_not_success(monkeypatch, receipt):
    replies = iter([{"result": {"from": "0x" + "a" * 40, "to": "0x" + "b" * 40,
                                "blockNumber": "0x10"}}, {"result": receipt}])
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda *a, **k: io.BytesIO(json.dumps(next(replies)).encode()))
    assert TransactionInfoCollector._fetch_via_rpc("https://rpc.invalid", "0x" + "c" * 64) == {}


def test_explicit_success_receipt_is_accepted(monkeypatch):
    replies = iter([{"result": {"from": "0x" + "a" * 40, "blockNumber": "0x10"}},
                    {"result": {"status": "0x1"}}])
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda *a, **k: io.BytesIO(json.dumps(next(replies)).encode()))
    result = TransactionInfoCollector._fetch_via_rpc("https://rpc.invalid", "0x" + "c" * 64)
    assert result["status"] == "Success"
    assert result["block_number"]["block_number"] == 16
