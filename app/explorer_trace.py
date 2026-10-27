"""Turn a keyless explorer trace into verified trace_transaction rows.

The explorer supplies only the call tree. Transaction and block identity must come from a
separate standard JSON-RPC eth_getTransactionByHash result, and the trace root has to match it
(from, to, input). No trace row is produced if any of that fails.
"""
import re

try:
    from .trace_identity import TraceIdentityError
except ImportError:  # flat import
    from trace_identity import TraceIdentityError

_HEX = re.compile(r"0x[0-9a-fA-F]*")


def _same(a, b):
    return str(a or "").lower() == str(b or "").lower()


def _check_tx(tx, tx_hash, chain_id=None):
    if not isinstance(tx, dict) or not _same(tx.get("hash"), tx_hash):
        raise TraceIdentityError("RPC transaction identity does not match the requested hash.")
    for key in ("from", "input", "blockHash", "blockNumber", "transactionIndex"):
        if tx.get(key) in (None, ""):
            raise TraceIdentityError(f"RPC transaction is missing {key}; block identity is unverified.")
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", str(tx["blockHash"])) or not re.fullmatch(r"0x[0-9a-fA-F]+", str(tx["blockNumber"])) \
            or not re.fullmatch(r"0x[0-9a-fA-F]+", str(tx["transactionIndex"])):
        raise TraceIdentityError("RPC transaction block identity is malformed.")
    if tx.get("to") is None:
        raise TraceIdentityError("Contract creation traces are not supported by the explorer adapter.")
    if chain_id is not None and tx.get("chainId") not in (None, "") and int(str(tx["chainId"]), 16) != int(chain_id):
        raise TraceIdentityError("RPC transaction chain id does not match the requested chain.")


def _check_root(tx, root_from, root_to, root_input):
    if not (_same(tx["from"], root_from) and _same(tx["to"], root_to) and _same(tx["input"], root_input)):
        raise TraceIdentityError("Explorer trace root differs from the RPC transaction (from/to/input).")


def _identity(tx):
    return {"blockHash": tx["blockHash"], "blockNumber": int(tx["blockNumber"], 16),
            "transactionHash": tx["hash"], "transactionPosition": int(tx["transactionIndex"], 16)}


def _check_parity_tree(rows):
    """subtraces must equal the immediate children, child indexes contiguous 0..n-1, every parent present."""
    by_loc = {tuple(r["traceAddress"]): r for r in rows}
    children = {}
    for loc in by_loc:
        if loc:
            if not all(isinstance(i, int) and i >= 0 for i in loc):
                raise TraceIdentityError("Explorer trace has an invalid location.")
            if loc[:-1] not in by_loc:
                raise TraceIdentityError("Explorer trace has an orphan frame (missing parent).")
            children.setdefault(loc[:-1], []).append(loc[-1])
    for loc, row in by_loc.items():
        kids = sorted(children.get(loc, []))
        if kids != list(range(len(kids))):
            raise TraceIdentityError("Explorer trace child locations are not contiguous (truncated tree).")
        if row.get("subtraces") != len(kids):
            raise TraceIdentityError("Explorer trace subtrace count differs from the returned children (truncated tree).")


def rows_from_parity(raw_rows, tx, tx_hash, chain_id=None):
    """Blockscout raw-trace in Parity shape (list of action/result frames)."""
    _check_tx(tx, tx_hash, chain_id)
    if not isinstance(raw_rows, list) or not raw_rows:
        raise TraceIdentityError("Explorer returned no parity trace rows.")
    ident = _identity(tx)
    rows, seen = [], set()
    for row in raw_rows:
        if not isinstance(row, dict) or not isinstance(row.get("action"), dict) or not isinstance(row.get("traceAddress"), list):
            raise TraceIdentityError("Explorer trace row is not a parity call frame.")
        if row.get("type") != "call":
            raise TraceIdentityError("Explorer trace contains a non-call frame; whole-trace identity is unverified.")
        key = tuple(row["traceAddress"])
        if key in seen:
            raise TraceIdentityError("Explorer trace has a duplicate frame location.")
        seen.add(key)
        rows.append({**row, **ident})
    root = next((r for r in rows if r["traceAddress"] == []), None)
    if root is None:
        raise TraceIdentityError("Explorer trace has no transaction root.")
    _check_parity_tree(rows)
    a = root["action"]
    _check_root(tx, a.get("from"), a.get("to"), a.get("input"))
    return rows


def rows_from_calltracer(tree, tx, tx_hash, chain_id=None):
    """Blockscout raw-trace in geth callTracer shape (nested calls) -> parity-like rows."""
    _check_tx(tx, tx_hash, chain_id)
    if not isinstance(tree, dict) or "from" not in tree or "to" not in tree:
        raise TraceIdentityError("Explorer returned no callTracer tree.")
    _check_root(tx, tree.get("from"), tree.get("to"), tree.get("input"))
    ident = _identity(tx)
    rows = []
    def walk(node, address):
        if not isinstance(node, dict) or str(node.get("type", "")).upper() not in ("CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"):
            raise TraceIdentityError("Explorer trace contains a non-call frame (e.g. create); whole-trace identity is unverified.")
        kids = node.get("calls") or []
        rows.append({"action": {"from": node.get("from"), "to": node.get("to"), "input": node.get("input", "0x"), "gas": node.get("gas"),
                                "value": node.get("value", "0x0"), "callType": str(node["type"]).lower()},
                     "result": {"gasUsed": node.get("gasUsed"), "output": node.get("output")},
                     "subtraces": len(kids), "traceAddress": list(address), "type": "call", **ident}
                    | ({"error": node["error"]} if node.get("error") else {}))  # a reverted sub-call is real behaviour; keep it labelled
        for i, kid in enumerate(kids):
            walk(kid, address + [i])
    walk(tree, [])
    return rows


# ---- keyless fetch + pipeline payload -------------------------------------------------------
import json as _json
import urllib.request as _urlreq

EXPLORER_TRACE_INSTANCES = {"eth": ("https://eth.blockscout.com", 1), "optimism": ("https://explorer.optimism.io", 10)}
_MAX_BYTES = 2_000_000
_TX = re.compile(r"0x[0-9a-fA-F]{64}")


def fetch_raw_trace(chain, tx_hash, opener=None):
    """One keyless GET against the verified instance; no retry, no redirect to other hosts, size capped."""
    if chain not in EXPLORER_TRACE_INSTANCES or not _TX.fullmatch(str(tx_hash)):
        raise TraceIdentityError("Explorer trace is not available for this chain or hash.")
    base = EXPLORER_TRACE_INSTANCES[chain][0]
    url = f"{base}/api/v2/transactions/{tx_hash.lower()}/raw-trace"
    request = _urlreq.Request(url, headers={"User-Agent": "faultseeker-console/1", "Accept": "application/json"})
    try:
        with (opener or _urlreq.urlopen)(request, timeout=20) as response:
            if not str(response.geturl()).startswith(base + "/"):
                raise TraceIdentityError("Explorer redirected to an unverified host.")
            data = response.read(_MAX_BYTES + 1)
    except TraceIdentityError:
        raise
    except Exception as exc:
        raise TraceIdentityError(f"Explorer trace request failed: {type(exc).__name__}") from None
    if len(data) > _MAX_BYTES:
        raise TraceIdentityError("Explorer trace is larger than the accepted size.")
    try:
        return _json.loads(data)
    except ValueError:
        raise TraceIdentityError("Explorer trace is not valid JSON.") from None


def payload_from_explorer(chain, tx_hash, tx, rpc_chain_id, fetch=fetch_raw_trace):
    """Structured-trace payload for the pipeline. `tx` must already be RPC-verified (hash and eth_chainId)."""
    try:
        from .trace_identity import sequence_from_parity
    except ImportError:
        from trace_identity import sequence_from_parity
    chain_id = EXPLORER_TRACE_INSTANCES[chain][1] if chain in EXPLORER_TRACE_INSTANCES else None
    if chain_id is None:
        raise TraceIdentityError("Explorer trace is not available for this chain.")
    if not isinstance(rpc_chain_id, int) or isinstance(rpc_chain_id, bool) or rpc_chain_id != chain_id:
        raise TraceIdentityError("RPC eth_chainId is missing or does not match the explorer instance chain.")
    raw = fetch(chain, tx_hash)
    if isinstance(raw, list):
        rows = rows_from_parity(raw, tx, tx_hash, chain_id)
    elif isinstance(raw, dict) and "calls" in raw or isinstance(raw, dict) and "type" in raw:
        rows = rows_from_calltracer(raw, tx, tx_hash, chain_id)
    else:
        raise TraceIdentityError("Explorer trace has an unrecognised shape.")
    seq = sequence_from_parity(rows, tx_hash, chain, verified_chain=chain)
    errored = [r["traceAddress"] for r in rows if r.get("error")]
    for loc in errored:                     # sequence_from_parity drops per-frame errors; keep them on the canonical tree
        node = seq["canonical_trace"]
        for i in loc:
            node = node["children"][i]
        node["error"] = next(r["error"] for r in rows if r["traceAddress"] == loc)
    provenance = {**seq["trace_provenance"], "source": "explorer_raw_trace", "explorer": EXPLORER_TRACE_INSTANCES[chain][0],
                  "identity_cross_check": "eth_getTransactionByHash + eth_chainId",
                  "frame_errors": len(errored), "frame_error_locations": errored,
                  "completeness": ("explorer-reported; parity subtrace counts and child indexes verified consistent" if isinstance(raw, list)
                                   else "explorer-reported nested tree; omitted sub-calls cannot be detected from this shape"),
                  "completeness_proven": False}
    return {"transaction_hash": tx_hash, "chain": chain, "trace": seq["canonical_trace"], "trace_provenance": provenance}
