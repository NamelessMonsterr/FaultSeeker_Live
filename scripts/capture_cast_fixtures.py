#!/usr/bin/env python3
"""Captures real `cast run` output for a set of calls, per Foundry version and signature-cache condition.

Needs `anvil` and `cast` in each directory passed on the command line (one directory per Foundry version).
Writes tests/fixtures/cast_traces.json. Nothing here touches the network: anvil is a local chain, and the "warm"
condition is produced by writing a signature cache file into an empty HOME.

    python scripts/capture_cast_fixtures.py /path/to/foundry-1.4.4 /path/to/foundry-1.9.0 ...
"""
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

FROM = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"       # anvil's first unlocked account
INIT = "0x600a600c600039600a6000f3602a60005260206000f3"    # deploys a stub that answers any call with 42
DEAD = "0x000000000000000000000000000000000000dEaD"


def proxy_init(target: str) -> str:
    """Init code for a hand-assembled proxy that forwards its calldata to `target` with CALL and returns 32 bytes."""
    t = target.lower().removeprefix("0x")
    runtime = ("36" "6000" "6000" "37"                               # CALLDATACOPY(0, 0, calldatasize)
               "6020" "6000" "36" "6000" "6000" f"73{t}" "5a" "f1" "50"   # CALL(gas, target, 0, 0, calldatasize, 0, 32); POP
               "6020" "6000" "f3")                                    # RETURN(0, 32)
    assert len(runtime) // 2 == 0x2c
    return "0x" + "602c600c6000396" + "02c6000f3" + runtime
CALLS = {   # name -> (signature, args)
    "unknown_foo": ("foo(uint256)", ["7"]),
    "erc20_transfer": ("transfer(address,uint256)", [DEAD, "5"]),
    "univ2_callback": ("uniswapV2Call(address,uint256,uint256,bytes)", [DEAD, "1", "2", "0x"]),
    "univ2_swap": ("swap(uint256,uint256,address,bytes)", ["1", "2", DEAD, "0x"]),
    "erc3156_flashloan": ("flashLoan(address,address,uint256,bytes)", [DEAD, DEAD, "1", "0x"]),
}
NESTED = {    # sent to the proxy, which forwards to the stub: a two-level trace
    "nested_flashloan": ("flashLoan(address,address,uint256,bytes)", [DEAD, DEAD, "1", "0x"]),
    "nested_unknown_foo": ("foo(uint256)", ["7"]),
}


def run(env, *args, **kw):
    return subprocess.run(args, capture_output=True, text=True, env=env, **kw)


def capture(bin_dir: str):
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": tempfile.mkdtemp()}
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    anvil = subprocess.Popen(["anvil", "--port", str(port), "--silent"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if run(env, "cast", "block-number", "--rpc-url", url).returncode == 0:
                break
            time.sleep(0.2)
        send = lambda *a: json.loads(run(env, "cast", "send", "--rpc-url", url, "--unlocked", "--from", FROM, *a, "--json").stdout)
        contract = send("--create", INIT)["contractAddress"]
        proxy = send("--create", proxy_init(contract))["contractAddress"]
        txs = {name: send(contract, sig, *args)["transactionHash"] for name, (sig, args) in CALLS.items()}
        txs.update({name: send(proxy, sig, *args)["transactionHash"] for name, (sig, args) in NESTED.items()})
        version = run(env, "cast", "--version").stdout.split()[2].split("-")[0]
        warm = {"events": {}, "errors": {}, "functions": {}}
        for sig, _ in list(CALLS.values()) + list(NESTED.values()):
            warm["functions"]["0x" + run(env, "cast", "sig", sig).stdout.strip().removeprefix("0x")] = sig
        out = {}
        for condition in ("cold", "warm"):
            home = tempfile.mkdtemp()
            if condition == "warm":
                Path(home, ".foundry/cache").mkdir(parents=True)
                Path(home, ".foundry/cache/signatures").write_text(json.dumps(warm))
            e = dict(env, HOME=home)
            out[condition] = {name: run(e, "cast", "run", "--quick", tx, "--rpc-url", url).stdout for name, tx in txs.items()}
        return version, {"contract": contract, "proxy": proxy, "traces": out}
    finally:
        anvil.kill()


def main():
    result = {}
    for d in sys.argv[1:]:
        version, data = capture(d)
        result[version] = data
        print("captured", version)
    target = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "cast_traces.json"
    target.write_text(json.dumps({"calls": {k: v[0] for k, v in {**CALLS, **NESTED}.items()}, "versions": result}, indent=1) + "\n")
    print("wrote", target)


if __name__ == "__main__":
    main()
