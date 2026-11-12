"""Real Foundry on a local anvil chain (no network, no funds). Skipped when Foundry is not installed.

Which versions run: every directory in FAULTSEEKER_TEST_FOUNDRY_DIRS (os.pathsep-separated; each holds `cast` and `anvil`),
otherwise the `cast`/`anvil` found on PATH. CONDITIONS TESTED: the isolated replayer with a polluted HOME (a warm signature
cache), cast run directly with that same HOME, and repeated replays.
"""
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

pytest.importorskip("networkx")
ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("capture", ROOT / "scripts" / "capture_cast_fixtures.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)


def foundry_dirs():
    configured = [d for d in os.environ.get("FAULTSEEKER_TEST_FOUNDRY_DIRS", "").split(os.pathsep) if d]
    if not configured and shutil.which("cast") and shutil.which("anvil"):
        configured = [str(Path(shutil.which("cast")).parent)]
    return [d for d in configured if (Path(d) / "cast").exists() and (Path(d) / "anvil").exists()]


def version_of(directory):
    out = subprocess.run([str(Path(directory) / "cast"), "--version"], capture_output=True, text=True).stdout
    m = re.search(r"(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else "unknown"


DIRS = foundry_dirs()
PARAMS = [pytest.param(d, id=f"cast-{version_of(d)}") for d in DIRS] or [
    pytest.param(None, marks=pytest.mark.skip(reason="Foundry (cast + anvil) not installed"))]


@pytest.fixture(scope="module", params=PARAMS)
def chain(request, tmp_path_factory):
    directory = request.param
    env = {"PATH": f"{directory}:/usr/bin:/bin", "HOME": str(tmp_path_factory.mktemp("home"))}
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    anvil = subprocess.Popen(["anvil", "--port", str(port), "--silent"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        if subprocess.run(["cast", "block-number", "--rpc-url", url], capture_output=True, env=env).returncode == 0:
            break
        time.sleep(0.2)
    else:
        anvil.kill()
        pytest.fail("anvil did not start")

    def send(*args):
        out = subprocess.run(["cast", "send", "--rpc-url", url, "--unlocked", "--from", capture.FROM, *args, "--json"],
                             capture_output=True, text=True, env=env, check=True).stdout
        return json.loads(out)
    stub = send("--create", capture.INIT)["contractAddress"]
    proxy = send("--create", capture.proxy_init(stub))["contractAddress"]
    yield type("Chain", (), {"url": url, "send": staticmethod(send), "stub": stub, "proxy": proxy, "dir": directory,
                             "version": version_of(directory), "env": env})
    anvil.kill()


def warm_home(path: Path) -> Path:
    cache = path / ".foundry" / "cache"
    cache.mkdir(parents=True)
    sigs = {"0x" + subprocess.run(["cast", "sig", sig], capture_output=True, text=True).stdout.strip().removeprefix("0x"): sig
            for sig, _ in list(capture.CALLS.values()) + list(capture.NESTED.values())}
    (cache / "signatures").write_text(json.dumps({"events": {}, "errors": {}, "functions": sigs}))
    return path


def analyzer_buckets(text, monkeypatch):
    from faultseeker.data_collection.trace_parser import TraceParser
    from faultseeker.forensics.trace_analyzer import TraceAnalyzer
    monkeypatch.setenv("FAULTSEEKER_ISOLATED_RUN", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-offline")
    root = TraceParser().parse(text)
    seq = {"trace": root.to_dict(), "transaction_hash": "0x" + "1" * 64, "chain": "eth", "address_relation": {}, "created_address": []}
    loc = TraceAnalyzer(seq, {}, "gpt-4o-mini").run()["function_calls_to_expand_loc"]
    return {k: sorted((c["function"], tuple(c["depth"])) for c in v) for k, v in loc.items()}, root


def test_isolated_replay_ignores_a_warm_signature_cache_and_parses_identically(chain, tmp_path, monkeypatch, capsys):
    from faultseeker.data_collection.txn_replayer import TransactionReplayer
    polluted = warm_home(tmp_path / "polluted")
    monkeypatch.setenv("PATH", f"{chain.dir}:{os.environ['PATH']}")
    monkeypatch.setenv("HOME", str(polluted))                     # what a developer's or a server's real HOME may contain
    monkeypatch.setenv("ETHERSCAN_API_KEY", "must-not-reach-cast")
    tx = chain.send(chain.proxy, "flashLoan(address,address,uint256,bytes)", capture.DEAD, capture.DEAD, "1", "0x")["transactionHash"]

    isolated = TransactionReplayer.transaction_replay(tx, chain.url)
    printed = capsys.readouterr().out
    direct = subprocess.run(["cast", "run", "--quick", tx, "--rpc-url", chain.url], capture_output=True, text=True,
                            env={"PATH": os.environ["PATH"], "HOME": str(polluted)}).stdout

    assert f"cast version: {chain.version}" in printed, "the version used is written to the run log"
    assert "::5cffe9de(" in isolated, f"{chain.version}: isolation should give raw selectors for a signature only the cache knows"
    assert "::flashLoan(" in direct, f"{chain.version}: without isolation the warm cache changes the output (the reported problem)"
    assert isolated != direct

    iso_buckets, iso_root = analyzer_buckets(isolated, monkeypatch)
    dir_buckets, dir_root = analyzer_buckets(direct, monkeypatch)
    assert iso_root.function == dir_root.function == "flashLoan"
    assert iso_root.children[0].function == dir_root.children[0].function == "flashLoan"
    assert iso_buckets == dir_buckets
    assert [f for f, _ in iso_buckets["flashloan"]] == ["flashLoan", "flashLoan"] and iso_buckets["name_in_hash"] == []


def test_replay_output_does_not_depend_on_the_callers_cache_state(chain, tmp_path, monkeypatch):
    from faultseeker.data_collection.txn_replayer import TransactionReplayer
    monkeypatch.setenv("PATH", f"{chain.dir}:{os.environ['PATH']}")
    tx = chain.send(chain.proxy, "foo(uint256)", "7")["transactionHash"]
    outputs = []
    for label in ("empty", "warm", "empty-again"):
        home = tmp_path / label
        home.mkdir()
        if label == "warm":
            warm_home(home / "h")
            monkeypatch.setenv("HOME", str(home / "h"))
        else:
            monkeypatch.setenv("HOME", str(home))
        outputs.append(TransactionReplayer.transaction_replay(tx, chain.url))
    assert outputs[0] == outputs[1] == outputs[2], "same transaction, same trace, whatever the surrounding cache looked like"
    assert "::2fbebd38(" in outputs[0]


def test_well_known_selectors_have_one_identity_whatever_this_cast_version_decodes(chain, tmp_path, monkeypatch):
    """Foundry 1.9.0 decodes transfer() on its own while 1.4.4/1.5.1 print a selector; after parsing they are the same."""
    from faultseeker.data_collection.txn_replayer import TransactionReplayer
    monkeypatch.setenv("PATH", f"{chain.dir}:{os.environ['PATH']}")
    monkeypatch.setenv("HOME", str(tmp_path))
    tx = chain.send(chain.stub, "transfer(address,uint256)", capture.DEAD, "5")["transactionHash"]
    text = TransactionReplayer.transaction_replay(tx, chain.url)
    from faultseeker.data_collection.trace_parser import TraceParser
    node = TraceParser().parse(text)
    assert (node.function, node.selector) == ("transfer", "a9059cbb"), chain.version
    decoded_by_cast = "::transfer(" in text
    assert decoded_by_cast == (chain.version == "1.9.0"), "documents which versions decode this selector without a cache"


def test_the_offline_flag_does_not_stop_replay_against_an_rpc(chain, tmp_path, monkeypatch):
    from faultseeker.data_collection.txn_replayer import TransactionReplayer
    monkeypatch.setenv("PATH", f"{chain.dir}:{os.environ['PATH']}")
    monkeypatch.setenv("FAULTSEEKER_CAST_OFFLINE", "1")
    tx = chain.send(chain.stub, "foo(uint256)", "1")["transactionHash"]
    assert "Traces:" in TransactionReplayer.transaction_replay(tx, chain.url)
