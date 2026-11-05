"""Collect contract-executing benign transactions directly from Ethereum mainnet blocks.

Filters transactions with input != "0x" and gasUsed > 21000 across recent blocks.
Traces each transaction to extract functioncall_count, address_count, max_depth, gas_cost.
Compares feature distributions against the exploit dataset side by side.
"""

from __future__ import annotations

import csv
import json
import os
import sys
import time
import urllib.request
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.honest_eval.features import load_exploit_rows, TRACE_FEATURES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_CSV = os.path.join(ROOT, "benchmark", "imported", "contract_benign_traces.csv")

RPC_URLS = [
    os.environ.get("ETH_RPC_URL", ""),
    "https://eth.drpc.org",
    "https://nodes.mewapi.io/rpc/eth",
]
RPC_URLS = [u for u in RPC_URLS if u]


def rpc_call(method: str, params: list, timeout: float = 20.0) -> Any:
    last_exc = None
    for url in RPC_URLS:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            if "error" in body:
                raise RuntimeError(str(body["error"]))
            return body.get("result")
        except Exception as exc:
            last_exc = exc
            continue
    if last_exc:
        raise last_exc
    raise RuntimeError("All RPCs failed")


def walk_call_tree(node, depth=0, addresses=None):
    if addresses is None:
        addresses = set()
    if not isinstance(node, dict):
        return 0, depth, addresses
    count = 1
    for key in ("to", "from"):
        val = node.get(key)
        if val:
            addresses.add(str(val).lower())
    max_d = depth
    for child in node.get("calls") or []:
        c_count, c_depth, addresses = walk_call_tree(child, depth + 1, addresses)
        count += c_count
        max_d = max(max_d, c_depth)
    return count, max_d, addresses


def get_tx_trace_features(tx_hash: str) -> Optional[dict]:
    try:
        trace = rpc_call("debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}])
        receipt = rpc_call("eth_getTransactionReceipt", [tx_hash])
        if not trace or not receipt:
            return None
        call_count, max_d, addrs = walk_call_tree(trace)
        gas_used = int(receipt.get("gasUsed", "0x0"), 16) if isinstance(receipt, dict) else 0
        if gas_used <= 21000:
            return None
        return {
            "txn_hash": tx_hash,
            "chain": "eth",
            "functioncall_count": call_count,
            "address_count": len(addrs),
            "max_depth": max_d,
            "gas_cost": gas_used,
            "collection_status": "ok",
        }
    except Exception:
        return None


def collect_contract_benign(target_count: int = 150) -> list:
    print(f"Fetching recent block number...")
    latest_hex = rpc_call("eth_blockNumber", [])
    latest_block = int(latest_hex, 16)
    print(f"Latest Ethereum Block: #{latest_block}")

    collected = []
    current_block = latest_block - 100  # Start 100 blocks ago for stability

    while len(collected) < target_count and current_block > latest_block - 2000:
        block_hex = hex(current_block)
        try:
            block = rpc_call("eth_getBlockByNumber", [block_hex, True])
        except Exception as e:
            current_block -= 1
            continue

        if not block or not block.get("transactions"):
            current_block -= 1
            continue

        txs = block.get("transactions", [])
        print(f"Block #{current_block}: inspecting {len(txs)} transactions...", flush=True)
        for tx in txs:
            if not isinstance(tx, dict):
                continue
            inp = tx.get("input", "0x")
            tx_hash = tx.get("hash", "")
            if inp != "0x" and len(inp) > 10 and tx_hash:
                feats = get_tx_trace_features(tx_hash)
                if feats and feats["functioncall_count"] > 1:
                    collected.append(feats)
                    print(f"  [{len(collected)}/{target_count}] {tx_hash[:14]}... calls={feats['functioncall_count']} addrs={feats['address_count']} depth={feats['max_depth']} gas={feats['gas_cost']}", flush=True)
                    
                    # Append row immediately to CSV
                    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
                    file_exists = os.path.exists(OUTPUT_CSV)
                    fieldnames = ["txn_hash", "chain", "functioncall_count", "address_count", "max_depth", "gas_cost", "collection_status"]
                    with open(OUTPUT_CSV, "a", encoding="utf-8", newline="") as csv_f:
                        w = csv.DictWriter(csv_f, fieldnames=fieldnames)
                        if not file_exists:
                            w.writeheader()
                        w.writerow(feats)

                    if len(collected) >= target_count:
                        break
        current_block -= 1

    return collected


def quantile(vals: list, p: float) -> float:
    if not vals:
        return 0.0
    sorted_v = sorted(vals)
    k = (len(sorted_v) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_v[int(k)])
    return float(sorted_v[int(f)] * (c - k) + sorted_v[int(c)] * (k - f))


def print_side_by_side_distributions(exploit_rows: list, benign_rows: list):
    print("\n" + "=" * 76)
    print("SIDE-BY-SIDE FEATURE DISTRIBUTION COMPARISON")
    print("=" * 76)

    for feat in TRACE_FEATURES:
        exp_vals = [float(r.features.get(feat) or 0.0) if hasattr(r, 'features') else float(r.get(feat) or 0.0) for r in exploit_rows if (hasattr(r, 'has_trace_features') and r.has_trace_features) or (isinstance(r, dict) and r.get(feat) is not None)]
        ben_vals = [float(r.get(feat) or 0.0) if isinstance(r, dict) else float(r.features.get(feat) or 0.0) for r in benign_rows]

        print(f"\nFeature: {feat.upper()}")
        print(f"  Metric       Exploit (N={len(exp_vals)})       Benign (N={len(ben_vals)})")
        print(f"  --------     -------------------       ------------------")
        print(f"  Min          {min(exp_vals):<19.2f}       {min(ben_vals):<18.2f}")
        print(f"  25%          {quantile(exp_vals, 0.25):<19.2f}       {quantile(ben_vals, 0.25):<18.2f}")
        print(f"  Median       {quantile(exp_vals, 0.50):<19.2f}       {quantile(ben_vals, 0.50):<18.2f}")
        print(f"  75%          {quantile(exp_vals, 0.75):<19.2f}       {quantile(ben_vals, 0.75):<18.2f}")
        print(f"  Max          {max(exp_vals):<19.2f}       {max(ben_vals):<18.2f}")
        print(f"  Mean         {sum(exp_vals)/len(exp_vals):<19.2f}       {sum(ben_vals)/len(ben_vals):<18.2f}")


def main() -> int:
    exploit_rows = load_exploit_rows()
    print(f"Loaded {len(exploit_rows)} exploit rows.")

    benign_data = collect_contract_benign(target_count=100)
    if not benign_data:
        print("ERROR: Failed to collect contract benign transactions.")
        return 2

    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    fieldnames = ["txn_hash", "chain", "functioncall_count", "address_count", "max_depth", "gas_cost", "collection_status"]
    with open(OUTPUT_CSV, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(benign_data)

    print(f"\nWrote {len(benign_data)} contract benign rows to {OUTPUT_CSV}")
    print_side_by_side_distributions(exploit_rows, benign_data)
    return 0


if __name__ == "__main__":
    import math
    raise SystemExit(main())
