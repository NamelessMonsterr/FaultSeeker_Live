"""Collect trace features for benign transactions via an archive RPC.

This unblocks Tables 4 and 5. The exploit CSV already carries measured trace
statistics; the HuggingFace benign CSV carries none, so any cross-class
comparison today is invalid by construction. Run this once against a
trace-capable endpoint (Tenderly, Alchemy, QuickNode, Ankr premium) to produce
``benchmark/imported/benign_traces.csv``.

Usage::

    python benchmark/collect_benign_traces.py --limit 1000 --rpc-url $ETH_RPC_URL
    python benchmark/collect_benign_traces.py --limit 5 --dry-run

1,000 benign transactions is ample for a valid FPR estimate and far cheaper
than the full 10,000.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENIGN_CSV = os.path.join(
    ROOT, "benchmark", "imported", "hf_ethereum_benign_transactions.csv"
)
OUTPUT_CSV = os.path.join(ROOT, "benchmark", "imported", "benign_traces.csv")

OUTPUT_FIELDS = [
    "txn_hash",
    "chain",
    "functioncall_count",
    "address_count",
    "max_depth",
    "gas_cost",
    "collection_status",
]


def read_benign_hashes(path: str, limit=None):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8-sig", newline="") as handle:
        for raw in csv.DictReader(handle):
            clean = {
                str(k or "").strip().lstrip("\ufeff").lower(): v
                for k, v in raw.items()
            }
            txn = str(clean.get("txn_hash") or "").strip().lower()
            if not txn:
                continue
            rows.append((txn, str(clean.get("chain") or "eth").strip().lower()))
            if limit is not None and len(rows) >= limit:
                break
    return rows


FALLBACK_RPCS = [
    "https://eth.drpc.org",
    "https://nodes.mewapi.io/rpc/eth",
]


def rpc_call(url: str, method: str, params, timeout: float = 30.0):
    urls = [url] if url else []
    for fb in FALLBACK_RPCS:
        if fb not in urls:
            urls.append(fb)

    last_exc = None
    for target_url in urls:
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode("utf-8")
        request = urllib.request.Request(
            target_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
            if "error" in body:
                raise RuntimeError(str(body["error"]))
            return body.get("result")
        except Exception as exc:
            last_exc = exc
            continue

    if last_exc:
        raise last_exc
    raise RuntimeError("No RPC URL available")


def walk_call_tree(node, depth=0, addresses=None):
    """Return (call_count, max_depth, unique_address_count) for a callTracer tree."""
    if addresses is None:
        addresses = set()
    if not isinstance(node, dict):
        return 0, depth, addresses
    count = 1
    for key in ("to", "from"):
        value = node.get(key)
        if value:
            addresses.add(str(value).lower())
    max_depth = depth
    for child in node.get("calls") or []:
        child_count, child_depth, addresses = walk_call_tree(
            child, depth + 1, addresses
        )
        count += child_count
        max_depth = max(max_depth, child_depth)
    return count, max_depth, addresses


def features_from_trace(trace, receipt):
    call_count, max_depth, addresses = walk_call_tree(trace)
    gas_used = 0
    if isinstance(receipt, dict) and receipt.get("gasUsed"):
        try:
            gas_used = int(str(receipt["gasUsed"]), 16)
        except (TypeError, ValueError):
            gas_used = 0
    if not gas_used and isinstance(trace, dict) and trace.get("gasUsed"):
        try:
            gas_used = int(str(trace["gasUsed"]), 16)
        except (TypeError, ValueError):
            gas_used = 0
    return {
        "functioncall_count": call_count,
        "address_count": len(addresses),
        "max_depth": max_depth,
        "gas_cost": gas_used,
    }


def synthetic_placeholder(txn_hash: str):
    """Deterministic placeholder used ONLY by --dry-run to exercise the writer.

    Rows produced this way are marked ``collection_status=DRY_RUN_PLACEHOLDER``
    and are rejected by the honest harness, which requires
    ``collection_status=ok``.
    """
    seed = int(txn_hash[2:10], 16) if len(txn_hash) > 10 else 0
    return {
        "functioncall_count": 1 + seed % 5,
        "address_count": 2 + seed % 3,
        "max_depth": 1 + seed % 2,
        "gas_cost": 21000 + (seed % 50) * 1000,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect benign transaction trace features via archive RPC."
    )
    parser.add_argument("--rpc-url", default=os.environ.get("ETH_RPC_URL", ""))
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--input", default=BENIGN_CSV)
    parser.add_argument("--output", default=OUTPUT_CSV)
    parser.add_argument("--sleep", type=float, default=0.1)
    parser.add_argument(
        "--tracer",
        default="callTracer",
        help="debug_traceTransaction tracer name.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Exercise parsing/writing without network. Output is marked as a "
        "placeholder and is rejected by the harness.",
    )
    args = parser.parse_args()

    targets = read_benign_hashes(args.input, limit=args.limit)
    if not targets:
        print(f"No benign transactions found in {args.input}")
        return 2

    if not args.dry_run and not args.rpc_url:
        print("ERROR: --rpc-url (or ETH_RPC_URL) is required unless --dry-run.")
        print("A trace-capable archive endpoint is needed for debug_traceTransaction.")
        return 2

    rows = []
    ok = failed = 0
    for index, (txn, chain) in enumerate(targets, start=1):
        if args.dry_run:
            features = synthetic_placeholder(txn)
            status = "DRY_RUN_PLACEHOLDER"
        else:
            try:
                trace = rpc_call(
                    args.rpc_url,
                    "debug_traceTransaction",
                    [txn, {"tracer": args.tracer}],
                )
                receipt = rpc_call(
                    args.rpc_url, "eth_getTransactionReceipt", [txn]
                )
                features = features_from_trace(trace, receipt)
                status = "ok"
                ok += 1
            except (urllib.error.URLError, RuntimeError, TimeoutError, OSError) as exc:
                features = {
                    "functioncall_count": "",
                    "address_count": "",
                    "max_depth": "",
                    "gas_cost": "",
                }
                status = f"error: {type(exc).__name__}"
                failed += 1
            time.sleep(args.sleep)

        row = {"txn_hash": txn, "chain": chain, "collection_status": status}
        row.update(features)
        rows.append(row)
        if index % 10 == 0:
            print(f"  processed {index}/{len(targets)} (ok={ok}, failed={failed})", flush=True)
            with open(args.output, "w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
                writer.writeheader()
                writer.writerows(rows)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {args.output} (ok={ok}, failed={failed})")
    if args.dry_run:
        print("DRY RUN: rows are placeholders and will NOT be accepted by the harness.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
