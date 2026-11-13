"""Transaction collection over RPC, with no explorer access at all. OFFLINE: a local fake node on 127.0.0.1."""
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

try:
    from faultseeker.data_collection import rpc_client, rpc_collector, source_fetcher
    from faultseeker.data_collection import contract_downloader as cd
    from faultseeker.data_collection.txn_info_collector import TransactionInfoCollector
    from faultseeker.forensics.fund_flow_analyzer import FundFlowAnalyzer
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

from tests.fake_rpc import FakeServer, TX, REVERTED, PENDING, FROM, TO, TOKEN, NFT, MULTI, POOL


@pytest.fixture()
def node(monkeypatch):
    s = FakeServer()
    monkeypatch.setattr(rpc_client, "RETRY_DELAYS", (0, 0))
    for k in ("FAULTSEEKER_EXPLORER_FALLBACK", "FAULTSEEKER_RPC_URL", "ETHERSCAN_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    yield s
    s.close()


@pytest.fixture()
def blocked_explorer(tmp_path, monkeypatch):
    """curl and any urllib call to an explorer behave like Cloudflare: HTTP 403, and every attempt is recorded."""
    bin_dir = tmp_path / "blockbin"
    bin_dir.mkdir()
    log = tmp_path / "curl.log"
    sh = bin_dir / "curl"
    sh.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\necho "<html>Error 403 Cloudflare</html>"\n')
    sh.chmod(sh.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return log


def test_collection_works_with_explorers_blocked_and_never_touches_them(node, blocked_explorer, monkeypatch):
    """THE regression: both explorers return 403 to this server, yet Collect transaction succeeds over RPC."""
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", node.ws)         # a ws:// endpoint is accepted and used over HTTP
    for chain in ("eth", "bsc"):
        info = TransactionInfoCollector().run(TX, chain)
        assert info["status"] == "Success" and info["transaction_hash"] == TX
        assert info["address_info"] == {"from_address": FROM, "to_address": [TO]}
        assert info["block_number"] == {"block_number": 100, "confirmations": 11}
        assert info["input_data"].startswith("0xa9059cbb") and info["method_selector"] == "0xa9059cbb"
        assert info["transaction_date"]["original"] == "Nov-14-2023 10:13:20 PM UTC"
        assert len(info["logs"]) == 6 and info["logs"][0]["address"] == TOKEN
    assert not blocked_explorer.exists(), "curl (explorer) must not be called on the default path"
    assert {m for _, m in node.calls} >= {"eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getBlockByNumber"}


def test_token_transfers_have_the_exact_shape_fund_flow_parses(node, monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", node.http)
    info = TransactionInfoCollector().run(TX, "eth")
    edges = info["token_transfer"]["edges"]
    labels = sorted((e["source"], e["target"], e["label"]) for e in edges)
    assert (FROM, POOL, f"{TOKEN} [USDC] (1,234.56789)") in labels
    assert (POOL, FROM, f"{TOKEN} [USDC] (0.000005)") in labels          # a second edge between the same pair is kept
    assert (POOL, FROM, f"{NFT} [ERC721] (1)") in labels
    assert (POOL, FROM, f"{MULTI} [ERC1155] (25)") in labels
    assert (POOL, FROM, f"{MULTI} [ERC1155] (10)") in labels and (POOL, FROM, f"{MULTI} [ERC1155] (20)") in labels
    assert len(edges) == 6
    f = FundFlowAnalyzer.__new__(FundFlowAnalyzer)               # no model needed for the arithmetic
    f.txn_info = info
    f._get_balance_change()
    assert f.balance_change[FROM][TOKEN]["amount"] == pytest.approx(-1234.56789 + 0.000005)
    assert f.balance_change[POOL][TOKEN]["label"] == "USDC"


def test_reverted_and_pending_transactions_are_explained_not_retried_elsewhere(node, monkeypatch, capsys):
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", node.http)
    monkeypatch.setenv("FAULTSEEKER_EXPLORER_FALLBACK", "1")          # even with the fallback on, a revert is final
    assert TransactionInfoCollector().run(REVERTED, "eth") == {}
    assert "RPC collection failed (not_successful): The transaction reverted on-chain" in capsys.readouterr().out
    assert TransactionInfoCollector().run(PENDING, "eth") == {}
    assert "not mined yet" in capsys.readouterr().out


def test_unknown_hash_reports_not_found(node, monkeypatch, capsys):
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", node.http)
    assert TransactionInfoCollector().run("0x" + "cd" * 32, "eth") == {}
    assert "RPC collection failed (not_found)" in capsys.readouterr().out


def test_default_endpoint_is_the_foundry_alias_with_ws_rewritten(monkeypatch):
    monkeypatch.delenv("FAULTSEEKER_RPC_URL", raising=False)
    assert rpc_client.resolve_endpoint("eth") == "https://ethereum-rpc.publicnode.com"
    assert rpc_client.resolve_endpoint("bsc") == "https://binance.llamarpc.com"
    assert rpc_client.resolve_endpoint("polygon").startswith("https://")
    assert rpc_client.http_url("wss://mainnet.infura.io/ws/v3/KEY") == "https://mainnet.infura.io/v3/KEY"
    assert rpc_client.http_url("wss://eth-mainnet.g.alchemy.com/v2/KEY") == "https://eth-mainnet.g.alchemy.com/v2/KEY"
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", "https://custom.example/v3/K")
    assert rpc_client.resolve_endpoint("bsc") == "https://custom.example/v3/K"


def test_errors_never_contain_the_endpoint_url(node, monkeypatch, capsys):
    secret_url = node.http + "/v3/SECRETKEY123456"
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", secret_url)
    node.mode = "forbidden"
    assert TransactionInfoCollector().run(TX, "eth") == {}
    node.mode = "down"
    node.close()
    assert TransactionInfoCollector().run(TX, "eth") == {}
    out = capsys.readouterr().out
    assert "RPC collection failed (rejected)" in out and "RPC collection failed (unreachable)" in out
    assert "SECRETKEY" not in out and str(node.port) not in out.replace("127.0.0.1", "")


def test_transient_errors_are_retried(node, monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", node.http)
    node.mode, node.failures_left = "flaky", 2
    assert TransactionInfoCollector().run(TX, "eth")["status"] == "Success"


def test_explorer_fallback_is_off_by_default_and_runs_only_when_flagged(node, blocked_explorer, monkeypatch, capsys):
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", node.http)
    node.mode = "forbidden"                                           # the RPC fails ...
    assert TransactionInfoCollector().run(TX, "eth") == {}
    assert not blocked_explorer.exists(), "no explorer request without the flag"
    monkeypatch.setenv("FAULTSEEKER_EXPLORER_FALLBACK", "1")          # ... now the flag allows the scrape (which is blocked)
    assert TransactionInfoCollector().run(TX, "eth") == {}
    out = capsys.readouterr().out
    assert blocked_explorer.exists() and "etherscan.io/tx/" in blocked_explorer.read_text()
    assert "Trying the block-explorer page" in out and "Explorer page did not report" in out


def test_explorer_fallback_can_rescue_an_rpc_failure(node, monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", node.http)
    monkeypatch.setenv("FAULTSEEKER_EXPLORER_FALLBACK", "yes")
    node.mode = "forbidden"
    page = ("<!-- Status --><i></i>Success</span></div><!-- Block Height --><a>12</a></span></div></i>From:0x"
            + "11" * 20 + "</span>")
    monkeypatch.setattr(TransactionInfoCollector, "_fetch_website_content", staticmethod(lambda url: page))
    info = TransactionInfoCollector().run(TX, "eth")
    assert info["status"] == "Success" and "source" not in info


# --------------------------------------------------------------------------------- source download

SRC = {"match": "exact_match", "chainId": "56", "address": TO,
       "sources": {"contracts/Token.sol": {"content": "contract T { function foo() public {} }"}},
       "proxyResolution": {"isProxy": True, "implementations": [{"address": POOL}]}}
IMPL = {"match": "match", "chainId": "56", "address": POOL,
        "sources": {"Impl.sol": {"content": "contract I { function bar() public {} }"},
                    "../../evil.sol": {"content": "x"}}}


def test_source_download_works_without_any_api_key(node, tmp_path, monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_SOURCIFY_URL", node.http)
    node.sourcify = {f"56/{TO}": SRC, f"56/{POOL}": IMPL}
    ran = []
    monkeypatch.setattr(cd.subprocess, "run", lambda *a, **k: ran.append(a))
    out = tmp_path / "o"
    cd.ContractDownloader.get_source_code("bsc", TO, str(out))
    assert (out / "contracts" / "Token.sol").read_text().startswith("contract T")
    assert (out / "Implementation" / POOL / "Impl.sol").exists(), "proxy implementation is fetched too"
    assert not (tmp_path / "evil.sol").exists() and not (out.parent / "evil.sol").exists(), "path traversal is refused"
    assert ran == [], "getCode is not needed when Sourcify has the contract"
    assert "foo" in cd.ContractDownloader.parse_contract(str(out))


def test_unverified_contract_degrades_with_a_clear_message(node, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("FAULTSEEKER_SOURCIFY_URL", node.http)

    def getcode_fails(cmd, **k):
        raise subprocess.CalledProcessError(1, cmd, stderr=b"NOTOK missing api key")
    monkeypatch.setattr(cd.subprocess, "run", getcode_fails)
    cd.ContractDownloader.get_source_code("eth", TO, str(tmp_path / "o"))        # does not raise
    out = capsys.readouterr().out
    assert "Contract source unavailable" in out and "ETHERSCAN_API_KEY" in out and "getCode failed" in out
    assert cd.ContractDownloader(  "eth", [TO], str(tmp_path / "o2"), str(tmp_path / "c")).run() == {TO.lower(): {}}


def test_sourcify_outage_falls_through_to_getcode(node, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("FAULTSEEKER_SOURCIFY_URL", node.http)
    node.mode = "down"
    seen = {}

    def fake_getcode(cmd, **k):
        seen["cmd"] = cmd
        out = Path(cmd[cmd.index("-o") + 1])
        (out / "A.sol").write_text("contract A { function f() public {} }")
        return type("R", (), {"stdout": b"", "stderr": b""})()
    monkeypatch.setattr(cd.subprocess, "run", fake_getcode)
    cd.ContractDownloader.get_source_code("eth", TO, str(tmp_path / "o"))
    assert "Sourcify lookup failed" in capsys.readouterr().out and seen["cmd"][0] == "getCode"


def test_with_a_key_getcode_goes_first_and_sourcify_is_the_backup(node, tmp_path, monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_SOURCIFY_URL", node.http)
    monkeypatch.setenv("ETHERSCAN_API_KEY", "KEY123")
    node.sourcify = {f"1/{TO}": dict(SRC, proxyResolution=None)}
    monkeypatch.setattr(cd.subprocess, "run", lambda cmd, **k: type("R", (), {"stdout": b"", "stderr": b""})())   # finds nothing
    cd.ContractDownloader.get_source_code("eth", TO, str(tmp_path / "o"))
    assert (tmp_path / "o" / "contracts" / "Token.sol").exists()
    assert node.calls and node.calls[0][1] == "GET"


def test_real_worker_collects_over_rpc_when_explorers_are_blocked(tmp_path, node):
    """End to end through the real worker + pipeline: Stage 1 gets past 'Collecting transaction info' with curl blocked.
    The run still fails later (the stand-in `cast` produces no trace, there is no model), but never because of the explorer."""
    from faultseeker.server import worker
    bin_dir = tmp_path / "wbin"
    bin_dir.mkdir()
    for name, body in (("cast", 'echo "no route to host" >&2; exit 1\n'), ("curl", f'echo x >> "{tmp_path}/curl.log"; exit 22\n')):
        f = bin_dir / name
        f.write_text("#!/bin/sh\n" + body)
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    root = Path(worker.__file__).resolve().parents[2]
    env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], PYTHONPATH=str(root), PYTHONUNBUFFERED="1",
               OPENAI_API_KEY="sk-test-" + "k" * 24, FAULTSEEKER_RPC_URL=node.http, FAULTSEEKER_RPC_RETRIES="0")
    env.pop("FAULTSEEKER_EXPLORER_FALLBACK", None)
    proc = subprocess.run([sys.executable, "-m", "faultseeker.server.worker", "--hash", TX, "--chain", "bsc", "--model",
                           "gpt-4o-mini", "--out", str(tmp_path / "out" / "r.json")], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=120)
    out = proc.stdout
    assert "Collecting transaction info" in out and "Explorer" not in out and "RPC collection failed" not in out
    assert not (tmp_path / "curl.log").exists()
    assert any(m == "eth_getTransactionReceipt" for _, m in node.calls)
