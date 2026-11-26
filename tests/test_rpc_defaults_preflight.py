"""Server RPC defaults (operator env per chain) and the archive preflight that runs before the replay. OFFLINE: local fake node, mocked cast."""
import os

import pytest

try:
    from faultseeker.data_collection import rpc_client, rpc_collector
    from faultseeker.data_collection.rpc_client import RpcClient, RpcError
    from faultseeker.forensics.orchestrator import ForensicsOrchestrator
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

from tests.fake_rpc import FakeServer, PENDING, PRUNED, TX


@pytest.fixture()
def node(monkeypatch):
    s = FakeServer()
    s.chain_id = 56
    monkeypatch.setattr(rpc_client, "RETRY_DELAYS", (0, 0))
    for name in ("FAULTSEEKER_RPC_URL", "FAULTSEEKER_DEFAULT_RPC_ETH", "FAULTSEEKER_DEFAULT_RPC_BSC"):
        monkeypatch.delenv(name, raising=False)
    yield s
    s.close()


# ------------------------------------------------------------------------------------------------ operator defaults

def test_the_endpoint_precedence_is_run_then_operator_default_then_foundry_alias(monkeypatch):
    for name in ("FAULTSEEKER_RPC_URL", "FAULTSEEKER_DEFAULT_RPC_BSC"):
        monkeypatch.delenv(name, raising=False)
    alias = rpc_client.resolve_endpoint("bsc")
    monkeypatch.setenv("FAULTSEEKER_DEFAULT_RPC_BSC", "https://archive.example/bsc")
    assert rpc_client.resolve_endpoint("bsc") == "https://archive.example/bsc" != alias
    assert rpc_client.resolve_endpoint("eth") != "https://archive.example/bsc", "a default is per chain"
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", "https://mine.example/rpc")
    assert rpc_client.resolve_endpoint("bsc") == "https://mine.example/rpc", "the run's own endpoint wins"
    assert rpc_client.configured_endpoint("bsc") == "https://mine.example/rpc"


def test_the_replay_passes_the_operator_default_to_cast_without_printing_it(monkeypatch, tmp_path, capsys):
    from types import SimpleNamespace
    from faultseeker.data_collection import txn_replayer
    seen = []
    monkeypatch.setenv("FAULTSEEKER_DEFAULT_RPC_ETH", "https://archive.example/eth?key=SECRETKEY")
    monkeypatch.setattr(txn_replayer.subprocess, "run", lambda cmd, **kw: (seen.append(cmd), SimpleNamespace(returncode=1, stdout="", stderr="x"))[1]
                        if cmd[:2] != ["cast", "--version"] else SimpleNamespace(returncode=0, stdout="cast 1", stderr=""))
    txn_replayer.TransactionReplayer.transaction_replay(TX, "eth")
    run_cmd = next(c for c in seen if "run" in c)
    assert "https://archive.example/eth?key=SECRETKEY" in run_cmd, "cast is given the operator's endpoint"
    assert "SECRETKEY" not in capsys.readouterr().out, "and it is never printed"


def test_the_server_redacts_operator_default_endpoints_from_logs(make_client, monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_DEFAULT_RPC_ETH", "https://archive.example/eth?key=SECRETKEY")
    make_client()
    from types import SimpleNamespace
    from faultseeker.server import runs, settings
    reg = settings.registry()
    secrets = runs.RunManager._secrets(reg, "", "", "", SimpleNamespace(host=""))
    assert "https://archive.example/eth?key=SECRETKEY" in secrets


# ------------------------------------------------------------------------------------------------ preflight

def test_a_reachable_archive_endpoint_passes_the_preflight_and_probes_the_block_before(node):
    info = rpc_collector.preflight(RpcClient(node.http), "bsc", TX)
    assert info == {"chain_id": 56, "block_number": 100}
    assert node.balance_blocks == ["0x63"], "state is probed at the block BEFORE the transaction (0x64 - 1)"
    assert [m for _, m in node.calls][:2] == ["eth_chainId", "eth_getTransactionByHash"]


def test_a_pruned_endpoint_fails_the_preflight_with_the_archive_message_before_any_replay(node):
    node.historical_balance_fails = True
    with pytest.raises(RpcError) as err:
        rpc_collector.preflight(RpcClient(node.http), "bsc", TX)
    assert err.value.kind == "history_unavailable" and "archive-capable RPC" in err.value.message


def test_the_wrong_network_fails_the_preflight_first(node):
    node.chain_id = 1
    with pytest.raises(RpcError) as err:
        rpc_collector.preflight(RpcClient(node.http), "bsc", TX)
    assert err.value.kind == "wrong_chain" and [m for _, m in node.calls] == ["eth_chainId"]


def test_an_unknown_hash_fails_the_preflight(node):
    with pytest.raises(RpcError) as err:
        rpc_collector.preflight(RpcClient(node.http), "bsc", "0x" + "dd" * 32)
    assert err.value.kind == "not_found"


def test_a_pending_transaction_is_left_to_the_collector(node):
    info = rpc_collector.preflight(RpcClient(node.http), "bsc", PENDING)
    assert info["block_number"] is None and node.balance_blocks == [], "no state probe for an unmined transaction"


def test_the_orchestrator_stops_before_the_replay_when_the_preflight_fails(node, monkeypatch, capsys):
    node.historical_balance_fails = True
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", node.http)
    assert ForensicsOrchestrator._preflight(TX, "bsc") is False
    out = capsys.readouterr().out
    assert "RPC collection failed (history_unavailable)" in out and "archive-capable RPC" in out
    o = object.__new__(ForensicsOrchestrator)
    o.txn_sequencer = type("S", (), {"run": staticmethod(lambda *a: pytest.fail("the replay must not run after a failed preflight"))})()
    assert o._run(TX, "bsc") is None


def test_the_orchestrator_proceeds_when_the_preflight_passes(node, monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", node.http)
    assert ForensicsOrchestrator._preflight(TX, "bsc") is True


def test_an_unreachable_endpoint_fails_the_preflight_in_the_collection_format(monkeypatch, capsys):
    monkeypatch.setattr(rpc_client, "RETRY_DELAYS", (0, 0))
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", "http://127.0.0.1:9")
    assert ForensicsOrchestrator._preflight(TX, "bsc") is False
    assert "RPC collection failed (unreachable)" in capsys.readouterr().out


def test_a_run_on_the_servers_own_dead_endpoint_says_it_is_the_operators_configuration(make_client):
    from tests.conftest import start_run, wait_final
    c = make_client(FAKE_MODE="server_rpc_dead")
    err = wait_final(c, start_run(c, chain="bsc"))["run"]["error"]
    assert err["code"] == "rpc_failed" and "FAULTSEEKER_DEFAULT_RPC_BSC" in err["hint"] and "archive" in err["hint"].lower()
