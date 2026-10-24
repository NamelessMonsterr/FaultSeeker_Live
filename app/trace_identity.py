"""Canonical calldata identities; public selector labels are not contract ABIs."""
import re


class TraceIdentityError(RuntimeError):
    pass


def canonical_to_legacy(node):
    def frame(source):
        calldata = source.get("input") or "0x"
        call_type = str(source.get("call_type") or source.get("type") or "call").lower()
        creation = call_type in ("create", "create2")
        selector = call_type if creation else (calldata[:10].lower() if re.fullmatch(r"0x[0-9a-fA-F]{8,}", calldata) else "0x")
        return {"type": "call", "gas": source.get("gas"), "address": source.get("callee") or source.get("to"),
                "function": selector, "params": calldata if creation else calldata[10:],
                "call_type": call_type, "value": source.get("value"), "contract_type": None,
                "function_identity": "contract_creation" if creation else ("calldata_selector" if selector != "0x" else "no_selector"),
                "abi_verified": False, "children": []}
    result = frame(node)
    pending = [(node, result)]
    while pending:
        source, target = pending.pop()
        for child in source.get("children", []):
            converted = frame(child)
            target["children"].append(converted)
            pending.append((child, converted))
    return result


def validate_trace_root(tx, root, tx_hash, receipt=None):
    """Bind a call to its transaction, or a creation to its matching receipt."""
    if not isinstance(tx, dict) or str(tx.get("hash", "")).lower() != tx_hash.lower():
        raise TraceIdentityError("Transaction identity could not be verified from the chain.")
    fields = [(tx.get("from"), root.get("caller") or root.get("from")),
              (tx.get("input"), root.get("input"))]
    target = root.get("callee") or root.get("to")
    if tx.get("to") is None:
        if str(root.get("call_type") or root.get("type") or "").lower() not in ("create", "create2"):
            raise TraceIdentityError("Contract creation requires a creation trace root.")
        if not isinstance(receipt, dict) or str(receipt.get("transactionHash", "")).lower() != tx_hash.lower():
            raise TraceIdentityError("Creation receipt identity could not be verified.")
        if not receipt.get("contractAddress"):
            raise TraceIdentityError("Creation receipt has no verified deployed address.")
        fields.append((receipt["contractAddress"], target))
    else:
        fields.append((tx["to"], target))
    if any(str(a or "").lower() != str(b or "").lower() for a, b in fields):
        raise TraceIdentityError("Structured trace root differs from on-chain transaction calldata or addresses.")


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
