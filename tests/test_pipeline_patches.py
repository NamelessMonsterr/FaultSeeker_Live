"""The small changes made to the original pipeline modules. Needs the project's full requirements."""
import json
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
    """A `cast` that records its arguments and counts calls. Failure is switched on by creating a file named fail next to it."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script(bin_dir / "cast", f'echo "$@" >> "{tmp_path}/argv.log"\n'
           'if [ -f "${0%/*}/fail" ]; then echo "boom line 1" >&2; echo "dns error: could not resolve" >&2; exit 1; fi\n'
           'echo "Traces:"; echo "  [18] 0x5FbDB2315678afecb367f032d93F642f64180aa3::2fbebd38(00)"\n')
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.delenv("FAULTSEEKER_RPC_URL", raising=False)
    return SimpleNamespace(argv=tmp_path / "argv.log", cache=str(tmp_path / "replay"))


def calls(fake):
    """Only the replay invocations (the replayer also asks cast for its version first)."""
    lines = fake.argv.read_text().splitlines() if fake.argv.exists() else []
    return [l for l in lines if l.startswith("run ")]


def test_replay_uses_the_foundry_alias_by_default(fake_cast, capsys):
    out = TransactionReplayer(fake_cast.cache).run(TX, "linea")
    assert "Traces:" in out
    assert calls(fake_cast) == [f"run --quick {TX} --rpc-url linea"]
    shown = capsys.readouterr().out
    assert "--rpc-url linea" in shown and "cast version:" in shown


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
    (Path(fake_cast.argv).parent / "bin" / "fail").write_text("")     # cast runs with a scrubbed environment, so a file is the switch
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


def test_cast_runs_in_a_minimal_environment_with_an_empty_home(tmp_path, monkeypatch):
    """OFFLINE: a stand-in `cast` dumps the environment it receives."""
    dump = tmp_path / "env.txt"
    bin_dir = tmp_path / "envbin"
    bin_dir.mkdir()
    script(bin_dir / "cast", f'env > "{dump}"; ls -A "$HOME" >> "{dump}.home"; echo "Traces:"\n')
    polluted = tmp_path / "realhome"
    (polluted / ".foundry" / "cache").mkdir(parents=True)
    (polluted / ".foundry" / "cache" / "signatures").write_text("{}")
    for k, v in {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(polluted), "ETHERSCAN_API_KEY": "etherscan-secret",
                 "OPENAI_API_KEY": "sk-openai-secret", "CODEX_PROXY_API_KEY": "codex-secret", "MERCURY_API_KEY": "mercury-secret",
                 "FAULTSEEKER_ACCESS_CODE": "access-code-secret", "FOUNDRY_ETH_RPC_URL": "http://evil", "FOUNDRY_PROFILE": "x",
                 "HTTPS_PROXY": "http://proxy.local:3128", "LANG": "C.UTF-8"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("FAULTSEEKER_CAST_OFFLINE", raising=False)
    TransactionReplayer.transaction_replay(TX, "eth")
    env = dict(l.split("=", 1) for l in dump.read_text().splitlines() if "=" in l)
    assert env["HOME"] != str(polluted) and env["HOME"].startswith(("/tmp", str(tmp_path.parent), "/var")) or "faultseeker-cast-home-" in env["HOME"]
    assert "faultseeker-cast-home-" in env["HOME"] and not Path(env["HOME"]).exists(), "temporary HOME is removed afterwards"
    assert (Path(str(dump) + ".home").read_text().strip() == ""), "cast starts with an empty home: no signature cache"
    assert env["FOUNDRY_OFFLINE"] == "true" and env["HTTPS_PROXY"] == "http://proxy.local:3128" and env["LANG"] == "C.UTF-8"
    blob = json.dumps(env)
    for leaked in ("etherscan-secret", "sk-openai-secret", "codex-secret", "mercury-secret", "access-code-secret", "evil", "FOUNDRY_PROFILE"):
        assert leaked not in blob, leaked
    assert not [k for k in env if k.startswith(("FOUNDRY_ETH", "FOUNDRY_PROFILE", "ETHERSCAN", "OPENAI", "CODEX", "MERCURY", "FAULTSEEKER"))]


def test_cast_offline_flag_can_be_turned_off(tmp_path, monkeypatch):
    dump = tmp_path / "env.txt"
    bin_dir = tmp_path / "envbin"
    bin_dir.mkdir()
    script(bin_dir / "cast", f'env > "{dump}"; echo "Traces:"\n')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("FAULTSEEKER_CAST_OFFLINE", "0")
    TransactionReplayer.transaction_replay(TX, "eth")
    assert "FOUNDRY_OFFLINE" not in dump.read_text()


def _run_worker(tmp_path, model, env_extra):
    from faultseeker.server import worker
    bin_dir = tmp_path / "wbin"
    bin_dir.mkdir(exist_ok=True)
    script(bin_dir / "cast", 'echo "no route to host" >&2; exit 1\n')
    script(bin_dir / "curl", "exit 6\n")
    root = Path(worker.__file__).resolve().parents[2]
    env = {k: v for k, v in os.environ.items() if not k.startswith(("OPENAI", "CODEX", "MERCURY", "FAULTSEEKER", "OLLAMA"))}
    env.update(PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], PYTHONPATH=str(root), PYTHONUNBUFFERED="1", FAULTSEEKER_ISOLATED_RUN="1", **env_extra)
    return subprocess.run([sys.executable, "-m", "faultseeker.server.worker", "--hash", TX, "--chain", "eth", "--model", model,
                           "--out", str(tmp_path / "out" / "r.json")], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)


def test_real_worker_reports_an_unconfigured_provider_before_doing_any_work(tmp_path):
    proc = _run_worker(tmp_path, "codex-proxy", {})
    assert proc.returncode == 1
    assert '"type": "ProviderConfigError"' in proc.stdout and "CODEX_PROXY_MODEL" in proc.stdout
    assert "cast exited" not in proc.stdout, "no blockchain work is attempted with a model that cannot be built"
    proc = _run_worker(tmp_path, "gpt-4o-mini", {})
    assert '"type": "ProviderConfigError"' in proc.stdout and "OPENAI_API_KEY" in proc.stdout
    proc = _run_worker(tmp_path, "not-in-the-registry", {"OPENAI_API_KEY": "sk-test-x"})
    assert "not in the provider registry" in proc.stdout


def test_real_worker_builds_agents_for_a_proxy_provider_and_reaches_stage_1(tmp_path):
    """OFFLINE: the proxy URL is never called, because Stage 1 (fake cast/curl failing) ends the run first."""
    env = {"CODEX_PROXY_BASE_URL": "http://127.0.0.1:9/v1", "CODEX_PROXY_MODEL": "exact-model", "CODEX_PROXY_API_KEY": "codex-" + "k" * 20}
    proc = _run_worker(tmp_path, "codex-proxy", env)
    assert proc.returncode == 1 and "Stage 1 (Forensics) failed to produce results" in proc.stdout
    assert "cast exited with code 1: no route to host" in proc.stdout and "ProviderConfigError" not in proc.stdout
    assert "codex-kkk" not in proc.stdout + proc.stderr
