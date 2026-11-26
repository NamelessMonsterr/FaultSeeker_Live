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
             "9a07": "quota", "e8e8": "explorer_fail", "7c7c": "rpc_collect_fail", "5e5e": "junk_report", "b0b0": "reduced_report", "7e7e": "reverted", "1c1c": "analysis_incomplete", "0000": "empty", "4a49": "hang"}
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
    if mode == "budget_incomplete":
        marker({"event": "error", "type": "FunctionAnalysisIncomplete",
                "message": "Stage 2 (Function Analysis) incomplete: 1 of 5 candidate(s) could not be analyzed: swap@0x88503f48e437a377f1ac2892cbb3a5b09949fadd "
                           "(InputLimitExceeded: the request needs about 10,500 estimated tokens across 3 messages, over this model's input budget of 5,888)"})
        sys.exit(1)
    if mode in ("pipeline_error", "pipeline_error_oddtype", "forensics_model", "input_limit"):
        say("      → Reviewing function calls...")
        say("Traceback (most recent call last): KeyError: internal detail /srv/faultseeker/internal.py")
        marker({"event": "error", "type": {"pipeline_error": "KeyError", "pipeline_error_oddtype": "Bad Type <script>alert(1)</script>",
                                           "forensics_model": "ForensicsModelError", "input_limit": "InputLimitExceeded"}[mode],
                "message": "internal detail /srv/faultseeker/internal.py token=abcd1234efgh model said {'junk': 1} SECRET-REPLY-TEXT"})
        sys.exit(1)
    if mode == "explorer_fail":
        say("Explorer page did not report a successful transaction (status: unknown). blocked?")
        marker({"event": "error", "type": "RuntimeError", "message": "Stage 1 (Forensics) failed to produce results"})
        sys.exit(1)
    if mode == "analysis_incomplete":
        say("      → Reviewing function calls...")
        marker({"event": "error", "type": "FunctionAnalysisIncomplete", "message":
                "Stage 2 (Function Analysis) incomplete: 1 of 2 attempted candidate(s) failed and were not recovered: "
                "bar@0x" + "bb" * 20 + " (CandidateIncomplete: iteration limit (31) reached without an adequacy confirmation "
                "after 1 completed step(s); last error ProviderDown: provider outage [redacted])"})
        sys.exit(1)
    if mode == "server_rpc_dead":
        say("RPC collection failed (unreachable): could not resolve binance.llamarpc.com (gaierror).")
        marker({"event": "error", "type": "RuntimeError", "message": "Stage 1 (Forensics) failed to produce results"})
        sys.exit(1)
    if mode == "wrong_chain":
        say("RPC collection failed (wrong_chain): This RPC endpoint reports chain ID 56, but the selected network (Ethereum) is chain ID 1. "
            "It is an endpoint for a different network.")
        marker({"event": "error", "type": "RuntimeError", "message": "Stage 1 (Forensics) failed to produce results"})
        sys.exit(1)
    if mode == "history_unavailable":
        say("RPC collection failed (history_unavailable): The RPC node knows this transaction (block 100) but has no receipt for it. "
            "That usually means the endpoint has pruned this part of history. Use an archive-capable RPC endpoint.")
        marker({"event": "error", "type": "RuntimeError", "message": "Stage 1 (Forensics) failed to produce results"})
        sys.exit(1)
    if mode in ("rpc_collect_fail", "reverted"):
        say("      → Collecting transaction info...")
        say("RPC collection failed (unreachable): RPC request failed after 3 attempts: could not reach rpc.example (gaierror)."
            if mode == "rpc_collect_fail" else
            "RPC collection failed (not_successful): The transaction reverted on-chain. Only successful transactions are analyzed.")
        marker({"event": "error", "type": "RuntimeError", "message": "Stage 1 (Forensics) failed to produce results"})
        sys.exit(1)
    if mode == "auth_fail":
        say("Traceback (most recent call last):")
        say("openai.AuthenticationError: Error code: 401 - {'error': {'message': 'Incorrect API key provided'}}")
        time.sleep(30)
    if mode == "quota":
        say("openai.RateLimitError: Error code: 429 - {'error': {'code': 'insufficient_quota'}}")
        time.sleep(30)
    errors = {
        "param_rejected": "openai.BadRequestError: Error code: 400 - {'error': {'message': \"Unsupported parameter: 'temperature' is not supported with this model.\", 'param': 'temperature'}}",
        "not_found": "openai.NotFoundError: Error code: 404 - {'error': {'message': 'The model `x` does not exist'}}",
        "forbidden": "openai.PermissionDeniedError: Error code: 403 - {'error': {'message': 'Forbidden'}}",
    }
    if mode in errors:
        say("Traceback (most recent call last):")
        say(errors[mode])
        time.sleep(30)
    if mode in ("unreachable", "unreachable_then_ok"):
        count = 3 if mode == "unreachable" else 2
        for _ in range(count):
            say("openai.APIConnectionError: Connection error.")
        if mode == "unreachable":
            time.sleep(30)
    if mode == "bad_request_other":      # a 400 that is about one request (too long), not about a parameter: not fatal
        say("openai.BadRequestError: Error code: 400 - {'error': {'message': 'maximum context length exceeded', 'code': 'context_length_exceeded'}}")
    if mode == "provider_config":
        marker({"event": "error", "type": "ProviderConfigError",
                "message": "Model 'codex-proxy' is not configured: set CODEX_PROXY_MODEL to the exact model ID."})
        sys.exit(1)
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
    tracked = ["OPENAI_API_KEY", "CODEX_PROXY_API_KEY", "MERCURY_API_KEY", "ETHERSCAN_API_KEY", "FAULTSEEKER_ACCESS_CODE",
               "FAULTSEEKER_SESSION_SECRET", "FAULTSEEKER_RPC_URL", "FAULTSEEKER_ISOLATED_RUN"]
    # Deliberately print raw values so tests can prove the server redacts them before storing or serving the log.
    say("env check " + " ".join(f"{n}={os.environ.get(n, 'unset')}" for n in tracked))
    import hashlib
    report = {n: (hashlib.sha256(os.environ[n].encode()).hexdigest() if n in os.environ else None) for n in tracked}
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(os.path.join(os.path.dirname(out), "env.json"), "w") as fh:
        json.dump(report, fh)

    if mode == "junk_report":
        # Raw model output as the pipeline can really deliver it: object evidence with confidence fields, error sentinels, a ranked key
        # that is no finding, junk findings, rejected verdict entries and limited coverage.
        result = {
            "transaction_hash": txn, "chain": chain,
            "ranked_suspicious_functions": [f"mint_{ADDR}", f"ghost_{ADDR}", "An error occurred."],
            "potentially_vulnerable_functions": {
                f"mint_{ADDR}": [{"evidence": "Signature not bound to the caller", "confidence_score": 0.9, "error": "x"},
                                 {"zzz": {"deep": 1}}, "An error occurred."],
                f"burn_{ADDR}": [{"observation": "burn without allowance check", "hypothesis": "missing approval", "confidence": 0.4}],
                f"junk_{ADDR}": [5, None, {"foo": 1}],
                "no_address_key": ["orphan evidence"]},
            "transaction_understanding": "The attacker minted tokens.", "duration": 1.2, "timestamp": "2026-11-06T10:00:00",
            "verdict_rejections": {"not a candidate of this analysis": 2},
            "coverage": {"status": "limited", "limited": True, "candidates": 6, "selected": 2, "analyzed": 2,
                         "omitted": [f"f{i}@{ADDR}" for i in range(4)], "failed": [], "selection_rejected": 1, "selection_replies_ignored": 0},
            "_debug": {"functions_to_inspect_count": 6}}
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w") as fh:
            json.dump(result, fh)
        marker({"event": "result"})
        return
    if mode == "reduced_report":
        # Execution completed for every candidate, but the evidence the model saw was reduced / source was missing, and nothing was flagged.
        result = {
            "transaction_hash": txn, "chain": chain, "ranked_suspicious_functions": [], "potentially_vulnerable_functions": {},
            "transaction_understanding": "The attacker swapped tokens.", "duration": 1.0, "timestamp": "2026-11-06T10:00:00",
            "coverage": {"status": "complete", "limited": False, "evidence_limited": True, "reduced_count": 1, "source_missing_count": 1,
                         "candidates": 2, "selected": 2, "analyzed": 2, "omitted": [], "failed": [], "selection_rejected": 0,
                         "selection_replies_ignored": 0},
            "evidence_gaps": {f"swap@{ADDR}": ["evidence reduced to fit the model input budget"], f"burn@{ADDR}": ["no function source code"]},
            "function_results": [
                {"identity": f"swap@{ADDR}", "function": "swap", "address": ADDR, "execution": "completed", "evidence": "reduced",
                 "reductions": [{"step": "verdict", "section": "analysis result", "tier": "trace", "action": "shortened",
                                 "original_bytes": 9000, "kept_bytes": 3100}]},
                {"identity": f"burn@{ADDR}", "function": "burn", "address": ADDR, "execution": "completed", "evidence": "source_missing"}],
            "source_lookups": {ADDR: {"chain": chain, "cause": "explorer_credentials", "sourcify": "no verified match",
                                      "explorer": "failed (Missing/Invalid API Key)", "explorer_key_configured": False,
                                      "summary": "Sourcify: no verified match; Etherscan API (no ETHERSCAN_API_KEY): failed (Missing/Invalid API Key). "
                                                 "Likely cause: the explorer reported a missing or invalid API key; a valid key may allow the lookup, "
                                                 "which is not guaranteed to find source."}},
            "_debug": {"functions_to_inspect_count": 2}}
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w") as fh:
            json.dump(result, fh)
        marker({"event": "result"})
        return
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
