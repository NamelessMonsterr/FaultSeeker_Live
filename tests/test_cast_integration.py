"""Real Foundry: replay an actual transaction on a local anvil chain and parse it with the project's parser.

Skipped unless `cast` and `anvil` are installed. This is the one test that exercises real `cast run` output.
"""
import json
import shutil
import socket
import subprocess
import time

import pytest

pytestmark = pytest.mark.skipif(not (shutil.which("cast") and shutil.which("anvil")), reason="Foundry (cast + anvil) not installed")
pytest.importorskip("networkx")

FROM = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"   # anvil's first unlocked account
# Init code that deploys a 10-byte runtime which returns 42 for any call.
INIT = "0x600a600c600039600a6000f3602a60005260206000f3"


@pytest.fixture(scope="module")
def anvil():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(["anvil", "--port", str(port), "--silent"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        if subprocess.run(["cast", "block-number", "--rpc-url", url], capture_output=True).returncode == 0:
            break
        time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("anvil did not start")
    yield url
    proc.kill()


def send(url, *args):
    out = subprocess.run(["cast", "send", "--rpc-url", url, "--unlocked", "--from", FROM, *args, "--json"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def test_real_cast_trace_flows_through_replayer_and_parser(anvil, tmp_path):
    from faultseeker.data_collection.trace_parser import TraceParser
    from faultseeker.data_collection.txn_replayer import TransactionReplayer
    contract = send(anvil, "--create", INIT)["contractAddress"]
    tx = send(anvil, contract, "foo(uint256)", "7")["transactionHash"]

    text = TransactionReplayer(str(tmp_path / "replay")).run(tx, anvil)    # a URL is a valid --rpc-url target
    assert text and "Traces:" in text
    parser = TraceParser()
    root = parser.parse(text)
    assert root is not None
    node = root.to_dict()
    assert node["type"] == "call" and node["address"].lower() == contract.lower()
    assert len(node["function"]) == 8 and node["params"].endswith("07")
    assert node["children"][0]["type"] == "return" and node["children"][0]["value"].endswith("2a")
    assert parser.address_call_memo[contract.lower()] == [node["function"]]
    assert (tmp_path / "replay" / (tx.lower() + ".txt")).exists()
