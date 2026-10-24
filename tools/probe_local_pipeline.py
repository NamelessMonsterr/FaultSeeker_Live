"""Offline path probe of an available pipeline; never substitutes for the Docker pin."""
import argparse
import contextlib
import copy
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.dont_write_bytecode = True
parser = argparse.ArgumentParser()
parser.add_argument("--repo", required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
repo = Path(args.repo).resolve()
head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
pin = next(line.split("=", 1)[1] for line in (root / "Dockerfile").read_text().splitlines() if line.startswith("ARG FAULTSEEKER_SHA="))
report = {"available_head": head, "docker_pin": pin, "exact_pin": head == pin, "inputs": "synthetic; no on-chain ground truth claimed"}
for name in list(os.environ):
    if any(part in name.upper() for part in ("API_KEY", "RPC_URL", "HISTORY_TOKEN", "GATE_PASSWORD")):
        os.environ.pop(name, None)
os.environ["PYTHON_DOTENV_DISABLED"] = "true"
def block_network(event, args):
    if event in ("socket.connect", "socket.getaddrinfo", "socket.sendto"):
        raise RuntimeError("Offline probe blocked network access")
sys.addaudithook(block_network)
sys.path[:0] = [str(repo), str(root)]
with tempfile.TemporaryDirectory(prefix="faultseeker-path-probe-") as scratch:
    os.chdir(scratch)
    Path("logs").mkdir()
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rpc = importlib.import_module("faultseeker.utils.rpc_provider")
            replay = importlib.import_module("faultseeker.data_collection.txn_replayer")
            sequencer = importlib.import_module("faultseeker.data_collection.txn_sequencer")
            analyzer = importlib.import_module("faultseeker.forensics.trace_analyzer")
            ranker = importlib.import_module("faultseeker.function_analysis.function_ranker")
            result_module = importlib.import_module("faultseeker.forensics.result")
            from app.pipeline_guards import PipelineRuntime
            from app.trace_identity import canonical_to_legacy
            tx_hash = "0x" + "a" * 64
            sender, created = "0x" + "1" * 40, "0x" + "2" * 40
            raw = {"type":"CREATE", "from":sender, "to":created, "input":"0x60806040526000", "value":"0x0", "gas":"0x1000", "calls":[]}
            normalized = rpc.normalize_trace_node(raw)
            report["geth_creation_normalization"] = {"kind": normalized["call_type"], "address_matches": normalized["callee"] == created}
            parity = rpc.normalize_trace_node({"type":"create", "action":{"from":sender,"init":raw["input"],"value":"0x0","gas":"0x1000"}, "result":{"address":created}, "children":[]})
            report["parity_creation_normalization"] = {"address_matches": parity["callee"] == created, "input_matches": parity["input"] == raw["input"]}
            tx = {"hash":tx_hash,"to":None,"from":sender,"input":raw["input"]}
            def rpc_reply(chain, method, params, **kwargs):
                if method == "eth_chainId": return "0x1"
                if method == "eth_getTransactionReceipt": return {"transactionHash":tx_hash,"contractAddress":created}
                return tx
            with patch.object(replay.TransactionReplayer, "get_structured_trace", lambda *a: {"transaction_hash":tx_hash,"chain":"eth","trace":normalized}), patch.object(replay.TransactionReplayer, "run", lambda *a: ""), patch.object(rpc, "rpc_call", rpc_reply), patch.object(analyzer, "build_agent", lambda *a: None):
                os.environ["ETH_RPC_URL"] = "http://127.0.0.1:12345/test-relay"
                os.environ["FAULTSEEKER_VISITOR_RPC_RELAY"] = "1"
                previous_registry = rpc._registry
                runtime = PipelineRuntime(tx_hash,"eth").install()
                report["visitor_rpc_registry_refreshed"] = rpc._registry is not previous_registry and any(p.url == os.environ["ETH_RPC_URL"] for p in rpc._registry._providers("eth"))
                try:
                    seq = sequencer.TransactionSequencer().run(tx_hash,"eth")
                    analysis = analyzer.TraceAnalyzer(seq,{},model="offline-no-llm").run()
                    forensic = result_module.ForensicsResult(transaction_hash=tx_hash,chain="eth",functions_to_be_inspected={"function_name_with_hash":[analysis["flatten_trace"][0]]})
                    ranked = ranker.FunctionRanker().rank(forensic,analysis)
                    report["creation_path"] = {"sequencer":True,"flattening":True,"ranker":True,"target_matches":list(ranked.functions_to_be_inspected)==["create_"+created],"coverage_ends":"before function/model analysis"}
                finally:
                    runtime.close()
            deep = {"type":"CALL","input":"0x12345678","to":created,"from":sender,"calls":[]}
            current = deep
            for _ in range(1023):
                child = {"type":"CALL","input":"0x12345678","to":created,"from":sender,"calls":[]}
                current["calls"] = [child]
                current = child
            canonical = {"call_type":"CALL","input":"0x12345678","callee":created,"children":[]}
            current = canonical
            for _ in range(1023):
                child = {"call_type":"CALL","input":"0x12345678","callee":created,"children":[]}
                current["children"] = [child]
                current = child
            legacy = canonical_to_legacy(canonical)
            report["runtime_recursion_limit"] = sys.getrecursionlimit()
            report["depth_1024"] = {}
            for name, operation in [("upstream_normalization",lambda:rpc.normalize_trace_node(deep)),("console_guard_deepcopy",lambda:copy.deepcopy(canonical)),("console_conversion",lambda:canonical_to_legacy(canonical)),("upstream_legacy_conversion",lambda:sequencer.TransactionSequencer._canonical_to_legacy_trace(canonical)),("upstream_TraceNode",lambda:sequencer.TraceNode.from_dict(legacy)),("json_serialization",lambda:json.dumps(canonical))]:
                try:
                    operation()
                    report["depth_1024"][name] = "returned"
                except Exception as exc:
                    report["depth_1024"][name] = type(exc).__name__
            seen = []
            def fake_open(request, **kwargs):
                seen.append(request.full_url)
                return io.BytesIO(b'{"result":"dummy"}')
            with patch.object(rpc.urllib.request,"urlopen",fake_open):
                rpc._http_post("http://169.254.169.254/", b'{}')
            report["old_rpc_forwards_private_destination"] = seen == ["http://169.254.169.254/"]
            report["network_calls"] = 0
    except Exception as exc:
        report["probe_blocker"] = {"type":type(exc).__name__,"missing_module":getattr(exc,"name",None)}
    finally:
        import logging
        logging.shutdown()
        os.chdir(root)
print(json.dumps(report,indent=2))
