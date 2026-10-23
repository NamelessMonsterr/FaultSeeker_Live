"""Canonical calldata identities; public selector labels are not contract ABIs."""
import re


class TraceIdentityError(RuntimeError):
    pass


def canonical_to_legacy(node):
    calldata = node.get("input") or "0x"
    selector = calldata[:10].lower() if re.fullmatch(r"0x[0-9a-fA-F]{8,}", calldata) else "0x"
    return {"type": "call", "gas": node.get("gas"), "address": node.get("callee") or node.get("to"),
            "function": selector, "params": calldata[10:],
            "call_type": str(node.get("call_type") or node.get("type") or "call").lower(),
            "value": node.get("value"), "contract_type": None,
            "function_identity": "calldata_selector", "abi_verified": False,
            "children": [canonical_to_legacy(child) for child in node.get("children", [])]}


def check_structured(payload, tx_hash, chain):
    if not isinstance(payload, dict) or str(payload.get("transaction_hash", "")).lower() != tx_hash.lower() or str(payload.get("chain", "")).lower() != chain.lower():
        raise TraceIdentityError("Structured trace cache has a different transaction or chain.")
    if not isinstance(payload.get("trace"), dict):
        raise TraceIdentityError("Structured execution trace is unavailable; function attribution is not verified.")
    return payload


def sequence_from_parity(rows, tx_hash, chain, verified_chain="eth"):
    """Convert real trace_transaction frames while verifying hash/block provenance."""
    if chain != verified_chain or not rows:
        raise TraceIdentityError("Trace chain does not match requested chain.")
    block_hash = rows[0].get("blockHash")
    nodes = {}
    for row in rows:
        if row.get("transactionHash", "").lower() != tx_hash.lower() or row.get("blockHash") != block_hash:
            raise TraceIdentityError("Trace transaction or block provenance does not match.")
        action = row.get("action", {})
        location = tuple(row["traceAddress"])
        nodes[location] = {"callee": action.get("to"), "caller": action.get("from"),
                           "input": action.get("input", "0x"), "gas": action.get("gas"),
                           "value": action.get("value"), "call_type": action.get("callType", row.get("type")),
                           "children": []}
    if () not in nodes:
        raise TraceIdentityError("Trace has no transaction root.")
    for location in sorted(nodes):
        if location:
            if location[:-1] not in nodes:
                raise TraceIdentityError("Trace is missing a parent frame.")
            nodes[location[:-1]]["children"].append(nodes[location])
    return {"transaction_hash": tx_hash, "chain": chain,
            "trace": canonical_to_legacy(nodes[()]), "canonical_trace": nodes[()],
            "trace_provenance": {"source": "trace_transaction", "chain": chain,
                                 "transaction_hash": tx_hash, "block_hash": block_hash,
                                 "block_number": rows[0].get("blockNumber"), "frame_count": len(rows),
                                 "function_identity": "calldata_selector", "abi_verified": False}}
