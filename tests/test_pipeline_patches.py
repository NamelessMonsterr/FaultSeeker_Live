"""The small changes made to the original pipeline modules. Needs the project's full requirements."""
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

try:
    from faultseeker import chains
    from faultseeker.data_collection import contract_downloader as cd
    from faultseeker.data_collection.txn_info_collector import TransactionInfoCollector
    from faultseeker.data_collection.txn_replayer import TransactionReplayer
except ImportError as exc:   # the project's full requirements are not installed
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

TX = "0x" + "ab" * 32


def script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


@pytest.fixture()
def fake_cast(tmp_path, monkeypatch):
    """A `cast` that records its arguments and counts calls. Behaviour is set with CAST_MODE."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script(bin_dir / "cast", f'echo "$@" >> "{tmp_path}/argv.log"\n'
           'if [ "$CAST_MODE" = fail ]; then echo "boom line 1" >&2; echo "dns error: could not resolve" >&2; exit 1; fi\n'
           'echo "Traces:"; echo "  [18] 0x5FbDB2315678afecb367f032d93F642f64180aa3::2fbebd38(00)"\n')
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.delenv("FAULTSEEKER_RPC_URL", raising=False)
    monkeypatch.delenv("CAST_MODE", raising=False)
    return SimpleNamespace(argv=tmp_path / "argv.log", cache=str(tmp_path / "replay"))


def calls(fake):
    return fake.argv.read_text().splitlines() if fake.argv.exists() else []


def test_replay_uses_the_foundry_alias_by_default(fake_cast, capsys):
    out = TransactionReplayer(fake_cast.cache).run(TX, "linea")
    assert "Traces:" in out
    assert calls(fake_cast) == [f"run --quick {TX} --rpc-url linea"]
    assert "--rpc-url linea" in capsys.readouterr().out


def test_replay_uses_a_custom_endpoint_without_printing_it(fake_cast, monkeypatch, capsys):
    url = "https://rpc.example/v3/SECRETKEY123456"
    monkeypatch.setenv("FAULTSEEKER_RPC_URL", url)
    TransactionReplayer(fake_cast.cache).run(TX, "eth")
    assert calls(fake_cast) == [f"run --quick {TX} --rpc-url {url}"]
    shown = capsys.readouterr().out
    assert "SECRETKEY" not in shown and "<custom endpoint>" in shown


def test_replay_result_is_cached(fake_cast):
    r = TransactionReplayer(fake_cast.cache)
    first, second = r.run(TX, "eth"), r.run(TX, "eth")
    assert first == second and len(calls(fake_cast)) == 1


def test_replay_failure_is_reported_and_not_cached(fake_cast, monkeypatch, capsys):
    monkeypatch.setenv("CAST_MODE", "fail")
    r = TransactionReplayer(fake_cast.cache)
    assert not r.run(TX, "eth")
    printed = capsys.readouterr().out
    assert "cast exited with code 1:" in printed and "dns error" in printed
    assert r.get_replay_cache(TX) is None


def test_replay_without_cast_installed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PATH", str(tmp_path))
    assert TransactionReplayer(str(tmp_path / "c")).run(TX, "eth") is None
    assert "cast exited with code 127" in capsys.readouterr().out


def test_explorer_fetch_sends_a_browser_agent_timeout_and_optional_proxy(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return SimpleNamespace(stdout="<html>ok</html>")
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.delenv("FAULTSEEKER_HTTP_PROXY", raising=False)
    assert TransactionInfoCollector._fetch_website_content("https://etherscan.io/tx/x") == "<html>ok</html>"
    cmd = seen["cmd"]
    assert cmd[0] == "curl" and "L" in cmd[1] and "--max-time" in cmd and "-A" in cmd and "Mozilla" in cmd[cmd.index("-A") + 1]
    assert "-x" not in cmd and cmd[-1] == "https://etherscan.io/tx/x"
    monkeypatch.setenv("FAULTSEEKER_HTTP_PROXY", "http://proxy.local:3128")
    TransactionInfoCollector._fetch_website_content("https://etherscan.io/tx/x")
    assert seen["cmd"][seen["cmd"].index("-x") + 1] == "http://proxy.local:3128"


def test_explorer_failures_are_printed(monkeypatch, capsys):
    def boom(cmd, **kw):
        raise subprocess.CalledProcessError(6, cmd, stderr="Could not resolve host")
    monkeypatch.setattr(subprocess, "run", boom)
    assert TransactionInfoCollector._fetch_website_content("https://x") is None
    assert "Explorer request failed (curl exit 6)" in capsys.readouterr().out

    def missing(cmd, **kw):
        raise FileNotFoundError()
    monkeypatch.setattr(subprocess, "run", missing)
    assert TransactionInfoCollector._fetch_website_content("https://x") is None
    assert "curl is not installed" in capsys.readouterr().out


def test_blocked_explorer_page_is_explained(monkeypatch, capsys):
    monkeypatch.setattr(TransactionInfoCollector, "_fetch_website_content", staticmethod(lambda url: "<html>Just a moment...</html>"))
    assert TransactionInfoCollector().run(TX, "eth") == {}
    assert "Explorer page did not report a successful transaction" in capsys.readouterr().out


@pytest.mark.parametrize("cid", [c for c, v in chains.CHAINS.items()])
def test_transaction_link_comes_from_the_registry(cid):
    c = TransactionInfoCollector()
    c.txn_hash = TX
    c.get_transaction_link(cid)
    assert c.txn_link == chains.CHAINS[cid]["tx_url"] + TX


def fake_getcode(monkeypatch, store):
    def fake_run(cmd, **kw):
        store["cmd"] = cmd
        return SimpleNamespace(stdout=b"", stderr=b"")
    monkeypatch.setattr(cd.subprocess, "run", fake_run)


def test_getcode_uses_chain_ids_and_the_optional_explorer_key(tmp_path, monkeypatch):
    seen = {}
    fake_getcode(monkeypatch, seen)
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    cd.ContractDownloader.get_source_code("bsc", "0xabc", str(tmp_path / "o"))
    assert seen["cmd"] == ["getCode", "--chainid", "56", "-a", "0xabc", "-o", str(tmp_path / "o")]
    cd.ContractDownloader.get_source_code("scroll", "0xabc", str(tmp_path / "o"))
    assert seen["cmd"][1:3] == ["--chainid", "534352"]
    monkeypatch.setenv("ETHERSCAN_API_KEY", "KEY123")
    cd.ContractDownloader.get_source_code("eth", "0xabc", str(tmp_path / "o"))
    assert seen["cmd"][-2:] == ["-k", "KEY123"] and seen["cmd"][1:3] == ["--chainid", "1"]
    cd.ContractDownloader.get_source_code("somechain", "0xabc", str(tmp_path / "o"))
    assert seen["cmd"][1:3] == ["-n", "somechain"]


def test_stage1_failure_raises_a_clear_error_instead_of_a_typeerror(tmp_path):
    from faultseeker.core.config import FaultSeekerConfig
    from faultseeker.core.pipeline import FaultSeekerPipeline
    p = FaultSeekerPipeline(FaultSeekerConfig(cache_dir=str(tmp_path / "cache")))
    p._agents_initialized = True
    p.forensics_orchestrator = SimpleNamespace(run=lambda *a: None)
    with pytest.raises(RuntimeError, match="Stage 1"):
        p.analyze_transaction(txn_hash=TX, chain="eth")
    with pytest.raises(ValueError):
        p.analyze_transaction()


def test_real_pipeline_reports_a_stage1_failure_end_to_end(tmp_path):
    """Runs the real worker + real pipeline with `cast` and `curl` that fail, so no network is needed."""
    from faultseeker.server import worker
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script(bin_dir / "cast", 'echo "no route to host" >&2; exit 1\n')
    script(bin_dir / "curl", "exit 6\n")
    root = Path(worker.__file__).resolve().parents[2]
    env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], PYTHONPATH=str(root),
               PYTHONUNBUFFERED="1", OPENAI_API_KEY="sk-test-" + "k" * 24)
    proc = subprocess.run([sys.executable, "-m", "faultseeker.server.worker", "--hash", TX, "--chain", "eth",
                           "--model", "gpt-4o-mini", "--out", str(tmp_path / "out" / "r.json")],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    out = proc.stdout
    assert proc.returncode == 1
    assert "##FS## " in out and '"event": "start"' in out and '"event": "error"' in out
    assert "Stage 1 (Forensics) failed to produce results" in out
    assert "cast exited with code 1: no route to host" in out
    assert "Explorer request failed (curl exit 6)" in out
    assert "cannot unpack" not in proc.stderr + out
    assert not (tmp_path / "out" / "r.json").exists()
