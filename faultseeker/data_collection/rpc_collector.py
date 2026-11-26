"""Builds the transaction record (status, block, from/to, input, logs, token transfers) from JSON-RPC alone.

The returned dict has the same keys the explorer collector produced, so everything downstream is unchanged, plus a few
extra keys (input_data, value_wei, logs, ...) that only an RPC node can give exactly.
"""
import re
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from typing import Dict, List, Optional

import networkx as nx

from faultseeker import chains
from faultseeker.data_collection.rpc_client import RpcClient, RpcError

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"        # ERC-20 / ERC-721
TRANSFER_SINGLE = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"  # ERC-1155
TRANSFER_BATCH = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb"   # ERC-1155
SEL_DECIMALS = "0x313ce567"
SEL_SYMBOL = "0x95d89b41"
MAX_LOGS_KEPT = 2000
MAX_TOKENS_LOOKED_UP = 40


def _int(value) -> int:
    if value in (None, "", "0x"):
        return 0
    return int(value, 16) if isinstance(value, str) else int(value)


def verify_chain(client: RpcClient, chain: str) -> int:
    """The endpoint's eth_chainId, which must equal the selected network's registry id. Raises RpcError otherwise:
    wrong_chain (a different network), bad_response (missing/malformed answer) or unknown_chain (no registry id to compare with).
    Nothing is fetched from, or cached for, an endpoint that has not passed this check."""
    spec = chains.get(chain)
    if not spec or not isinstance(spec.get("chain_id"), int):
        raise RpcError("unknown_chain", f"The network '{str(chain)[:40]}' has no registered chain ID, so the RPC endpoint cannot be verified.")
    raw = client.call("eth_chainId")
    if not (isinstance(raw, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,64}", raw)):
        raise RpcError("bad_response", "The RPC endpoint did not return a valid chain ID (eth_chainId), so it cannot be verified.")
    actual = int(raw, 16)
    if actual != spec["chain_id"]:
        raise RpcError("wrong_chain", f"This RPC endpoint reports chain ID {actual}, but the selected network ({spec['label']}) is chain ID "
                                      f"{spec['chain_id']}. It is an endpoint for a different network: use one for {spec['label']}, or select the "
                                      "matching network.")
    return actual


def preflight(client: RpcClient, chain: str, txn_hash: str) -> dict:
    """Cheap checks, in order, BEFORE the expensive replay: the endpoint serves the selected network (eth_chainId), it knows the
    transaction, and (for a mined transaction) it can answer a state query at the block BEFORE the transaction, which is what a
    replay needs. A pruned or non-archive endpoint therefore fails here, in seconds, with the archive-RPC message."""
    chain_id = verify_chain(client, chain)
    tx = client.call("eth_getTransactionByHash", [txn_hash])
    if not tx:
        raise RpcError("not_found", "The RPC node does not know this transaction hash. Check the hash and the selected network.")
    block = tx.get("blockNumber")
    if block:
        number = _int(block)
        sender = tx.get("from")
        if number > 0 and isinstance(sender, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", sender):
            client.call("eth_getBalance", [sender, hex(number - 1)])      # history_unavailable if that state has been pruned
    return {"chain_id": chain_id, "block_number": _int(block) if block else None}


def _addr(topic_or_word: str) -> str:
    """Last 20 bytes of a 32-byte hex word, lower-case."""
    h = topic_or_word[2:] if topic_or_word.startswith("0x") else topic_or_word
    return "0x" + h[-40:].lower()


def _words(data: str) -> List[str]:
    h = data[2:] if data.startswith("0x") else data
    return [h[i:i + 64] for i in range(0, len(h) - len(h) % 64, 64)]


def _clean_name(text: str) -> str:
    """Labels are re-parsed downstream by splitting on [ ] ( ), so those characters cannot appear in a name."""
    return "".join(c for c in text if c.isprintable() and c not in "[]()").strip()[:40]


def _decode_string(result: Optional[str]) -> str:
    try:
        raw = bytes.fromhex((result or "0x")[2:])
        if not raw:
            return ""
        if len(raw) == 32:                                  # bytes32 symbol (MKR, SAI, ...)
            return _clean_name(raw.rstrip(b"\x00").decode("utf-8", "ignore"))
        offset = int.from_bytes(raw[:32], "big")
        length = int.from_bytes(raw[offset:offset + 32], "big")
        return _clean_name(raw[offset + 32:offset + 32 + length].decode("utf-8", "ignore"))
    except (ValueError, IndexError):
        return ""


def format_amount(raw: int, decimals: int) -> str:
    """Human amount with thousands separators, the form downstream parsing expects (commas are stripped there)."""
    with localcontext() as ctx:
        ctx.prec = 100
        value = Decimal(raw) / (Decimal(10) ** decimals)
        text = f"{value:,.{decimals}f}" if decimals else f"{value:,.0f}"
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def format_raw_amount(raw: int) -> str:
    """The raw integer of a token whose decimals are not known. Never shown as a plain amount: 'decimals = 0' would be a claim."""
    return f"{raw:,} raw units, decimals unknown"


class _TokenInfo:
    """decimals/symbol lookups, cached, tolerant of tokens that implement neither.

    Metadata is read at the transaction's own block (`block`, a hex number). Only when that state is not available on the endpoint
    (pruned history) does it fall back to "latest", and the result says so (metadata_block == 'latest'). A token whose decimals could
    not be read at all has decimals None, which is NOT zero."""

    def __init__(self, client: RpcClient, block: str = "latest"):
        self.client = client
        self.block = block
        self.cache: Dict[str, dict] = {}

    def _call(self, address: str, selector: str):
        """(result, block_used). Historical first; latest only when the historical state is missing."""
        try:
            return self.client.call("eth_call", [{"to": address, "data": selector}, self.block]), "historical"
        except RpcError as exc:
            if self.block == "latest" or exc.kind != "history_unavailable":
                raise
        return self.client.call("eth_call", [{"to": address, "data": selector}, "latest"]), "latest"

    def get(self, address: str) -> dict:
        if address in self.cache:
            return self.cache[address]
        info = {"symbol": "", "decimals": None, "metadata_block": "historical"}
        if len(self.cache) < MAX_TOKENS_LOOKED_UP:
            for field, selector in (("decimals", SEL_DECIMALS), ("symbol", SEL_SYMBOL)):
                try:
                    out, used = self._call(address, selector)
                    if used == "latest":
                        info["metadata_block"] = "latest"
                except RpcError as exc:
                    if exc.kind in ("unreachable", "no_endpoint"):
                        break
                    continue
                if field == "decimals":
                    try:
                        value = _int(out)
                        info["decimals"] = value if 0 <= value <= 77 and out and out != "0x" else None
                    except ValueError:
                        pass
                else:
                    info["symbol"] = _decode_string(out)
        self.cache[address] = info
        return info


def _transfers(logs: List[dict], tokens: _TokenInfo) -> List[dict]:
    """One entry per transfer event: {token, source, target, amount, standard}."""
    found = []
    for log in logs:
        topics = log.get("topics") or []
        if not topics or log.get("removed"):
            continue
        token = (log.get("address") or "").lower()
        t0 = topics[0].lower()
        try:
            if t0 == TRANSFER and len(topics) == 3:
                words = _words(log.get("data", "0x"))
                if len(words) >= 1:
                    info = tokens.get(token)
                    raw_amount = int(words[0], 16)
                    known = info["decimals"] is not None
                    found.append({"token": token, "source": _addr(topics[1]), "target": _addr(topics[2]),
                                  "amount": format_amount(raw_amount, info["decimals"]) if known else format_raw_amount(raw_amount),
                                  "raw_amount": str(raw_amount), "decimals": info["decimals"], "decimals_known": known,
                                  "metadata_block": info.get("metadata_block", "historical"),
                                  "name": info["symbol"] or "ERC20", "standard": "ERC-20"})
            elif t0 == TRANSFER and len(topics) == 4:
                found.append({"token": token, "source": _addr(topics[1]), "target": _addr(topics[2]), "amount": "1", "raw_amount": "1",
                              "decimals": 0, "decimals_known": True, "name": "ERC721", "standard": "ERC-721"})
            elif t0 == TRANSFER_SINGLE and len(topics) == 4:
                words = _words(log.get("data", "0x"))
                if len(words) >= 2:
                    found.append({"token": token, "source": _addr(topics[2]), "target": _addr(topics[3]),
                                  "amount": format_amount(int(words[1], 16), 0), "raw_amount": str(int(words[1], 16)), "decimals": 0,
                                  "decimals_known": True, "name": "ERC1155", "standard": "ERC-1155"})
            elif t0 == TRANSFER_BATCH and len(topics) == 4:
                words = _words(log.get("data", "0x"))
                ids_at, vals_at = int(words[0], 16) // 32, int(words[1], 16) // 32
                n = int(words[ids_at], 16)
                for i in range(n):
                    found.append({"token": token, "source": _addr(topics[2]), "target": _addr(topics[3]),
                                  "amount": format_amount(int(words[vals_at + 1 + i], 16), 0), "raw_amount": str(int(words[vals_at + 1 + i], 16)),
                                  "decimals": 0, "decimals_known": True, "name": "ERC1155", "standard": "ERC-1155"})
        except (ValueError, IndexError):
            continue                                                  # malformed log: skip, never fail the run
    return found


def _graph(transfers: List[dict]) -> dict:
    graph = nx.MultiDiGraph()
    for t in transfers:
        graph.add_node(t["source"], label=t["source"])
        graph.add_node(t["target"], label=t["target"])
        note = ", latest-block decimals" if t.get("metadata_block") == "latest" and t.get("decimals_known") else ""
        graph.add_edge(t["source"], t["target"], label=f"{t['token']} [{t['name']}] ({t['amount']}{note})")
    return nx.node_link_data(graph, edges="edges")


def _date(timestamp: int) -> dict:
    utc = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return {"original": utc.strftime("%b-%d-%Y %I:%M:%S %p UTC"),
            "local": utc.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")}


def collect(client: RpcClient, txn_hash: str, chain: str) -> dict:
    """Returns the transaction record. Raises RpcError (not_found / bad_response / ...) when it cannot be built.

    A reverted transaction returns a record whose status is 'Fail'; the caller decides what to do with it.
    """
    chain_id = verify_chain(client, chain)               # before anything else is read from this endpoint
    tx = client.call("eth_getTransactionByHash", [txn_hash])
    if not tx:
        raise RpcError("not_found", "The RPC node does not know this transaction. Check the network and that the "
                                    "endpoint is for the same chain.")
    receipt = client.call("eth_getTransactionReceipt", [txn_hash])
    if not receipt:
        if tx.get("blockNumber"):
            # The node returned the transaction WITH a block number, so it is mined: a missing receipt is the endpoint's history
            # limit (pruned / non-archive), not an unmined transaction.
            raise RpcError("history_unavailable",
                           f"The RPC node knows this transaction (block {_int(tx.get('blockNumber'))}) but has no receipt for it. "
                           "That usually means the endpoint has pruned this part of history. Use an archive-capable RPC endpoint.")
        return {"status": "Pending", "transaction_hash": txn_hash}
    status_flag = receipt.get("status")
    status = "Success" if status_flag == "0x1" else "Fail" if status_flag == "0x0" else "Unknown"

    block_number = _int(receipt.get("blockNumber") or tx.get("blockNumber"))
    block = client.call("eth_getBlockByNumber", [hex(block_number), False]) or {}
    try:
        head = _int(client.call("eth_blockNumber"))
        confirmations = max(head - block_number + 1, 0)
    except (RpcError, ValueError):
        confirmations = -1
    timestamp = _int(block.get("timestamp"))

    logs = receipt.get("logs") or []
    created = (receipt.get("contractAddress") or "").lower()
    to_addr = (tx.get("to") or "").lower()
    transfers = _transfers(logs, _TokenInfo(client, hex(block_number)))
    from_addr = (tx.get("from") or "").lower()
    input_data = tx.get("input") or tx.get("data") or "0x"

    return {
        "status": status,
        "gas_consumption": {"gas_used": _int(receipt.get("gasUsed")), "gas_limit": _int(tx.get("gas")),
                            "effective_gas_price_wei": _int(receipt.get("effectiveGasPrice") or tx.get("gasPrice"))},
        "block_number": {"block_number": block_number, "confirmations": confirmations},
        "address_info": {"from_address": from_addr, "to_address": [to_addr or created] if (to_addr or created) else []},
        "transaction_hash": txn_hash,
        "transaction_date": _date(timestamp) if timestamp else "",
        "token_transfer": _graph(transfers),
        # Beyond the explorer record: exact on-chain data.
        "source": "rpc",
        "chain": chain,
        "chain_id": chain_id,
        "transfers": transfers,
        "input_data": input_data,
        "method_selector": input_data[:10] if len(input_data) >= 10 else "",
        "value_wei": _int(tx.get("value")),
        "nonce": _int(tx.get("nonce")),
        "creates_contract": created or None,
        "logs": [{"index": _int(l.get("logIndex")), "address": (l.get("address") or "").lower(),
                  "topics": l.get("topics") or [], "data": l.get("data", "0x")} for l in logs[:MAX_LOGS_KEPT]],
        "logs_truncated": len(logs) > MAX_LOGS_KEPT,
    }
