"""Audit F03 / F04 / F05: replay acceptance and cache provenance, and the chain-id check. OFFLINE: a local fake node and a mocked `cast`."""
import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest

try:
    from faultseeker.data_collection import rpc_client, rpc_collector, txn_replayer
    from faultseeker.data_collection.rpc_client import RpcClient, RpcError
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

from tests.fake_rpc import FakeServer, TX

GOOD_TRACE = ("Traces:\n  [18] 0x5FbDB2315678afecb367f032d93F642f64180aa3::2fbebd38(0000000000000000000000000000000000000000000000000000000000000007)\n"
              "    \u2514\u2500 \u2190 [Return] 0x2a\n\n\nTransaction successfully executed.\nGas used: 21510\n")
TRUNCATED = GOOD_TRACE.split("\n\n\nTransaction")[0]


@pytest.fixture()
def node(monkeypatch):
    s = FakeServer()
    monkeypatch.setattr(rpc_client, "RETRY_DELAYS", (0, 0))
    monkeypatch.delenv("FAULTSEEKER_EXPLORER_FALLBACK", raising=False)
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", s.http)
    yield s
    s.close()


class Cast:
    """Mocks the cast executable: records every `cast run` and answers as configured."""

    def __init__(self, monkeypatch, rc=0, stdout=GOOD_TRACE, stderr=""):
        self.rc, self.stdout, self.stderr, self.runs = rc, stdout, stderr, []
        monkeypatch.setattr(txn_replayer.subprocess, "run", self)

    def __call__(self, command, **kw):
        if command[:2] == ["cast", "--version"]:
            return SimpleNamespace(returncode=0, stdout="cast 1.5.1\n", stderr="")
        self.runs.append(command)
        return SimpleNamespace(returncode=self.rc, stdout=self.stdout, stderr=self.stderr)


def replayer(tmp_path):
    return txn_replayer.TransactionReplayer(cache_path=str(tmp_path / "replay"))


def cache_files(tmp_path):
    root = tmp_path / "replay"
    return sorted(p.name for p in root.iterdir()) if root.exists() else []


# ------------------------------------------------------------------------------------------------ F03: acceptance

def test_a_nonzero_exit_with_partial_stdout_is_never_accepted_or_cached(node, monkeypatch, tmp_path, capsys):
    cast = Cast(monkeypatch, rc=1, stdout=GOOD_TRACE, stderr="Error: server returned an error response")
    assert replayer(tmp_path).run(TX, "eth") in (None, "")
    assert cache_files(tmp_path) == [], "a failed replay publishes nothing"
    assert "cast exited with code 1" in capsys.readouterr().out
    assert replayer(tmp_path).run(TX, "eth") in (None, "") and len(cast.runs) == 2, "nothing was cached, so the next request replays again"


@pytest.mark.parametrize("stdout", ["", "   \n", TRUNCATED, "Traces:\n", "garbage"])
def test_a_zero_exit_without_a_complete_trace_is_not_accepted_or_cached(node, monkeypatch, tmp_path, stdout):
    Cast(monkeypatch, rc=0, stdout=stdout)
    assert replayer(tmp_path).run(TX, "eth") in (None, "")
    assert cache_files(tmp_path) == []


def test_a_valid_replay_is_returned_cached_atomically_and_reused(node, monkeypatch, tmp_path):
    cast = Cast(monkeypatch)
    r = replayer(tmp_path)
    assert r.run(TX, "eth") == GOOD_TRACE
    names = cache_files(tmp_path)
    assert len(names) == 2 and not any(n.endswith(".tmp") for n in names), names
    assert r.run(TX, "eth") == GOOD_TRACE and len(cast.runs) == 1, "the second call is a cache hit"
    meta = json.loads(next((tmp_path / "replay" / n).read_text() for n in names if n.endswith(".json")))
    assert meta["chain_id"] == 1 and meta["txn_hash"] == TX.lower() and meta["sha256"] == hashlib.sha256(GOOD_TRACE.encode()).hexdigest()


def test_a_corrupted_or_unversioned_cache_entry_is_not_trusted(node, monkeypatch, tmp_path):
    cast = Cast(monkeypatch)
    r = replayer(tmp_path)
    (tmp_path / "replay").mkdir(parents=True, exist_ok=True)
    (tmp_path / "replay" / (TX.lower() + ".txt")).write_text("PARTIAL TRACE FROM AN OLD BUILD")          # the old unversioned name
    assert r.run(TX, "eth") == GOOD_TRACE and len(cast.runs) == 1, "legacy entries are never read"
    names = cache_files(tmp_path)
    trace = next(tmp_path / "replay" / n for n in names if n.endswith(".txt") and n != TX.lower() + ".txt")
    trace.write_text(GOOD_TRACE + "tampered")
    assert r.run(TX, "eth") == GOOD_TRACE and len(cast.runs) == 2, "an entry that does not match its recorded digest is a miss"


def test_an_interrupted_write_leaves_no_cache_entry(node, monkeypatch, tmp_path):
    Cast(monkeypatch)
    import os as os_module
    real = os_module.replace
    monkeypatch.setattr(txn_replayer.os, "replace", lambda a, b: (_ for _ in ()).throw(OSError("disk full")))
    assert replayer(tmp_path).run(TX, "eth") == GOOD_TRACE, "the trace itself is still returned for this run"
    monkeypatch.setattr(txn_replayer.os, "replace", real)
    assert not any(n.endswith(".txt") for n in cache_files(tmp_path)) and not any(n.endswith(".tmp") for n in cache_files(tmp_path))


# ------------------------------------------------------------------------------------------------ F04 + F05: provenance

def test_the_same_hash_on_a_different_chain_never_reuses_the_cached_trace(node, monkeypatch, tmp_path):
    cast = Cast(monkeypatch, stdout=GOOD_TRACE)
    r = replayer(tmp_path)
    node.chain_id = 1
    assert r.run(TX, "eth") == GOOD_TRACE
    bsc_trace = GOOD_TRACE.replace("21510", "99999")
    cast.stdout = bsc_trace
    node.chain_id = 56
    assert r.run(TX, "bsc") == bsc_trace, "BNB Smart Chain must not receive the Ethereum trace"
    assert len(cast.runs) == 2
    node.chain_id = 1
    assert r.run(TX, "eth") == GOOD_TRACE and len(cast.runs) == 2, "each chain keeps its own entry"


def test_an_endpoint_for_another_chain_stops_the_replay_before_cast_runs(node, monkeypatch, tmp_path, capsys):
    cast = Cast(monkeypatch)
    node.chain_id = 56
    assert replayer(tmp_path).run(TX, "eth") in (None, "")
    assert cast.runs == [] and cache_files(tmp_path) == []
    out = capsys.readouterr().out
    assert "RPC collection failed (wrong_chain)" in out and "56" in out and "1" in out


def test_collect_verifies_eth_chain_id_before_anything_else(node):
    client = RpcClient(node.http)
    node.chain_id = 1
    info = rpc_collector.collect(client, TX, "eth")
    assert info["chain_id"] == 1 and node.calls[0][1] == "eth_chainId"
    node.chain_id = 56
    with pytest.raises(RpcError) as err:
        rpc_collector.collect(RpcClient(node.http), TX, "eth")
    assert err.value.kind == "wrong_chain" and "chain ID 56" in err.value.message and "chain ID 1" in err.value.message
    node.calls.clear()
    with pytest.raises(RpcError):
        rpc_collector.collect(RpcClient(node.http), TX, "eth")
    assert [m for _, m in node.calls] == ["eth_chainId"], "nothing else is fetched from the wrong network"


@pytest.mark.parametrize("raw", [None, "garbage", "0x", "", 56, {"x": 1}, "0xZZ", "-0x1"])
def test_a_missing_or_malformed_chain_id_fails_explicitly(node, raw):
    node.chain_id_raw = raw
    with pytest.raises(RpcError) as err:
        rpc_collector.collect(RpcClient(node.http), TX, "eth")
    assert err.value.kind == "bad_response"


def test_a_node_that_rejects_eth_chainid_fails_explicitly_and_never_silently_continues(node):
    node.method_errors["eth_chainId"] = "method eth_chainId not found"
    with pytest.raises(RpcError):
        rpc_collector.collect(RpcClient(node.http), TX, "eth")


@pytest.mark.parametrize("chain,chain_id", [("eth", 1), ("bsc", 56), ("polygon", 137), ("arbitrum", 42161)])
def test_registry_chain_ids_are_accepted_for_their_chain(node, chain, chain_id):
    node.chain_id = chain_id
    assert rpc_collector.verify_chain(RpcClient(node.http), chain) == chain_id


def test_an_unknown_network_label_is_refused_not_guessed(node):
    with pytest.raises(RpcError):
        rpc_collector.verify_chain(RpcClient(node.http), "nowhere")


def test_the_run_reports_a_wrong_chain_with_its_own_code(make_client):
    from tests.conftest import start_run, wait_final
    c = make_client(FAKE_MODE="wrong_chain")
    err = wait_final(c, start_run(c))["run"]["error"]
    assert err["code"] == "rpc_wrong_chain" and "different network" in err["hint"]
