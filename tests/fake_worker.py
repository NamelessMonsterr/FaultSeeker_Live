"""Stand-in worker for server tests. Prints the same lines the real pipeline prints.

The scenario comes from FAKE_MODE, or, when that is unset, from the first hex digits of the transaction
hash (so a browser test can pick a scenario per run): 0xfa11… cast_fail, 0xdead… auth_fail,
0xbad0… bad_rank, 0x0bad… crash, 0x9a07… quota, 0xe8e8… explorer_fail, 0x0000… empty.
"""
import json
import os
import subprocess
import sys
import time

MARK = "##FS##"
BY_PREFIX = {"fa11": "cast_fail", "dead": "auth_fail", "bad0": "bad_rank", "0bad": "crash",
             "9a07": "quota", "e8e8": "explorer_fail", "0000": "empty", "4a49": "hang"}
ADDR = "0xc342774492b54ce5f8ac662113ed702fc1b34972"


def say(text):
    print(text, flush=True)
    time.sleep(float(os.environ.get("FAKE_DELAY", "0.05")))


def marker(payload):
    print(f"{MARK} {json.dumps(payload)}", flush=True)


def main():
    out = sys.argv[sys.argv.index("--out") + 1]
    txn = sys.argv[sys.argv.index("--hash") + 1]
    chain = sys.argv[sys.argv.index("--chain") + 1]
    mode = os.environ.get("FAKE_MODE") or BY_PREFIX.get(txn[2:6], "success")
    marker({"event": "start"})
    say("🔬 [Stage 1] Transaction-Level Forensics")
    say("      → Collecting transaction sequence...")

    if mode == "hang":
        time.sleep(600)
    if mode == "spawn_child":
        child = subprocess.Popen(["sleep", "600"])
        with open(os.environ["FAKE_CHILD_PID_FILE"], "w") as fh:
            fh.write(str(child.pid))
        time.sleep(600)
    if mode == "bigline":
        print("X" * int(os.environ.get("FAKE_BIG", "3000000")), flush=True)
        time.sleep(600)
    if mode == "crash":
        os._exit(3)
    if mode == "cast_fail":
        say(f"cast run --quick {txn} --rpc-url <custom endpoint>")
        say("cast exited with code 1: error sending request for url (" + os.environ.get("FAULTSEEKER_RPC_URL", "") + ")")
        say("      → Collecting transaction info...")
        marker({"event": "error", "type": "RuntimeError", "message": "Stage 1 (Forensics) failed to produce results"})
        sys.exit(1)
    if mode == "explorer_fail":
        say("Explorer page did not report a successful transaction (status: unknown). blocked?")
        marker({"event": "error", "type": "RuntimeError", "message": "Stage 1 (Forensics) failed to produce results"})
        sys.exit(1)
    if mode == "auth_fail":
        say("Traceback (most recent call last):")
        say("openai.AuthenticationError: Error code: 401 - {'error': {'message': 'Incorrect API key provided'}}")
        time.sleep(30)
    if mode == "quota":
        say("openai.RateLimitError: Error code: 429 - {'error': {'code': 'insufficient_quota'}}")
        time.sleep(30)
    if mode == "source_mentions_error":
        # Words that look like a provider error but are only logged contract text must not fail the run.
        say("functions to be analyzed: {'check': 'AuthenticationError invalid_api_key insufficient_quota'}")

    say("      → Collecting transaction info...")
    say("      → Analyzing execution trace...")
    say("      → Classifying addresses...")
    say("      → Identifying vulnerable functions...")
    say("   ✓ Forensics analysis completed")
    say("   → Ranking suspicious functions...")
    say("   ✓ Ranking completed - 2 addresses to analyze")
    say("   → Analyzing vulnerable functions...")
    say("      → Downloading contract source code...")
    say("      → Reviewing function calls...")
    say("         [1/2] Analyzing mint...")
    say("         [2/2] Analyzing burn (created contract param)...")
    say("   ✓ Function analysis completed")
    say("env check key=" + os.environ.get("OPENAI_API_KEY", "none") + " rpc=" + os.environ.get("FAULTSEEKER_RPC_URL", "none")
        + " etherscan=" + os.environ.get("ETHERSCAN_API_KEY", "none"))

    if mode == "bad_rank":
        ranked = ["An error occurred."]
    elif mode == "empty":
        ranked = []
    else:
        ranked = [f"mint_{ADDR}", f"burn_{ADDR}"]
    potential = {} if mode == "empty" else {f"mint_{ADDR}": ["Signature not bound to the caller"],
                                            f"burn_{ADDR}": ["Burns without allowance check"]}
    result = {
        "transaction_hash": txn, "chain": chain, "ranked_suspicious_functions": ranked,
        "potentially_vulnerable_functions": potential,
        "transaction_understanding": "The attacker minted tokens by replaying a signature.",
        "duration": 1.2, "timestamp": "2026-11-06T10:00:00",
        "_debug": {"forensics_duration": 0.5, "analysis_duration": 0.7, "functions_to_inspect_count": 3},
    }
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as fh:
        json.dump(result, fh)
    marker({"event": "result"})


main()
