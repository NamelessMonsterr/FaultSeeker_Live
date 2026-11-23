"""Pruned-history RPC failures are named for what they are; unmined stays unmined; unrelated errors stay unrelated (OFFLINE: local fake node)."""
import pytest

try:
    from faultseeker.data_collection import rpc_client, rpc_collector
    from faultseeker.data_collection.txn_info_collector import TransactionInfoCollector
    from faultseeker.server import progress
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

from tests.fake_rpc import FakeServer, PENDING, PRUNED, TX


@pytest.fixture()
def node(monkeypatch):
    s = FakeServer()
    monkeypatch.setattr(rpc_client, "RETRY_DELAYS", (0, 0))
    for k in ("FAULTSEEKER_EXPLORER_FALLBACK", "ETHERSCAN_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", s.http)
    yield s
    s.close()


def collect_output(txn, capsys):
    info = TransactionInfoCollector().run(txn, "bsc")
    return info, capsys.readouterr().out


def test_a_mined_transaction_without_a_receipt_is_history_unavailable_not_unmined(node, capsys):
    info, out = collect_output(PRUNED, capsys)
    assert info == {}
    assert "RPC collection failed (history_unavailable):" in out and "archive-capable RPC" in out
    assert "not mined" not in out and "not_successful" not in out


def test_a_genuinely_unmined_transaction_keeps_the_unmined_message(node, capsys):
    info, out = collect_output(PENDING, capsys)
    assert info == {}
    assert "RPC collection failed (not_successful): The transaction is not mined yet" in out and "history_unavailable" not in out


def test_collect_raises_a_typed_error_for_the_missing_receipt(node):
    client = rpc_client.RpcClient(node.http)
    with pytest.raises(rpc_client.RpcError) as err:
        rpc_collector.collect(client, PRUNED, "bsc")
    assert err.value.kind == "history_unavailable" and "block 100" in err.value.message
    assert rpc_collector.collect(client, PENDING, "bsc")["status"] == "Pending"


@pytest.mark.parametrize("message", [
    "missing trie node 7a1f (path ) state 0x12ab is not available", "historical state 0x12ab is not available",
    "state at block 1234 is pruned", "Error: old data not available due to pruning", "this node is not an archive node",
    "requires an archive node", "block data has been pruned", "distance to target block exceeds maximum proof window",
    "historical backend does not have this block: not available"])
def test_pruned_history_json_rpc_errors_are_classified_as_history_unavailable(node, message):
    node.method_errors["eth_getTransactionByHash"] = message
    with pytest.raises(rpc_client.RpcError) as err:
        rpc_collector.collect(rpc_client.RpcClient(node.http), TX, "bsc")
    assert err.value.kind == "history_unavailable" and "archive-capable RPC" in err.value.message
    assert len([c for c in node.calls if c[1] == "eth_getTransactionByHash"]) == 1, "not retried: the history will not appear"


@pytest.mark.parametrize("message,kind", [
    ("execution reverted", "rejected"), ("method eth_getTransactionByHash not found", "rejected"), ("invalid params", "rejected"),
    ("header not found", "rejected"), ("insufficient funds for gas", "rejected"), ("unknown block", "rejected"),
    ("nonce too low", "rejected"), ("authentication required", "rejected")])
def test_unrelated_rpc_errors_are_not_called_pruned_history(node, message, kind):
    node.method_errors["eth_getTransactionByHash"] = message
    with pytest.raises(rpc_client.RpcError) as err:
        rpc_collector.collect(rpc_client.RpcClient(node.http), TX, "bsc")
    assert err.value.kind == kind and "archive" not in err.value.message.lower()


def test_a_rate_limit_is_still_retried_and_never_called_pruned_history(node):
    node.method_errors["eth_getTransactionByHash"] = "daily request limit exceeded"
    with pytest.raises(rpc_client.RpcError) as err:
        rpc_collector.collect(rpc_client.RpcClient(node.http), TX, "bsc")
    assert err.value.kind == "rejected" and "archive" not in err.value.message.lower()
    assert len([c for c in node.calls if c[1] == "eth_getTransactionByHash"]) == 3, "retried as before: it is a rate limit, not pruned history"


def test_the_run_reports_a_distinct_code_and_an_archive_hint(make_client):
    c = make_client(FAKE_MODE="history_unavailable")
    from tests.conftest import start_run, wait_final
    data = wait_final(c, start_run(c))
    err = data["run"]["error"]
    assert err["code"] == "rpc_history_unavailable" and "archive" in err["hint"].lower() and "not mined" not in err["message"]


def test_the_progress_parser_reads_the_new_kind():
    m = progress.COLLECT_ERROR.match("RPC collection failed (history_unavailable): The RPC node knows this transaction")
    assert m and m.group(1) == "history_unavailable"
