"""Builds the transaction record (status, block, from/to, input, logs, token transfers) from JSON-RPC alone.

The returned dict has the same keys the explorer collector produced, so everything downstream is unchanged, plus a few
extra keys (input_data, value_wei, logs, ...) that only an RPC node can give exactly.
"""
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from typing import Dict, List, Optional

import networkx as nx

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


class _TokenInfo:
    """decimals/symbol lookups, cached, tolerant of tokens that implement neither."""

    def __init__(self, client: RpcClient):
        self.client = client
        self.cache: Dict[str, dict] = {}

    def get(self, address: str) -> dict:
        if address in self.cache:
            return self.cache[address]
        info = {"symbol": "", "decimals": None}
        if len(self.cache) < MAX_TOKENS_LOOKED_UP:
            for field, selector in (("decimals", SEL_DECIMALS), ("symbol", SEL_SYMBOL)):
                try:
                    out = self.client.call("eth_call", [{"to": address, "data": selector}, "latest"])
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
                    amount = format_amount(int(words[0], 16), info["decimals"] or 0)
                    found.append({"token": token, "source": _addr(topics[1]), "target": _addr(topics[2]),
                                  "amount": amount, "name": info["symbol"] or "ERC20", "standard": "ERC-20"})
            elif t0 == TRANSFER and len(topics) == 4:
                found.append({"token": token, "source": _addr(topics[1]), "target": _addr(topics[2]), "amount": "1",
                              "name": "ERC721", "standard": "ERC-721"})
            elif t0 == TRANSFER_SINGLE and len(topics) == 4:
                words = _words(log.get("data", "0x"))
                if len(words) >= 2:
                    found.append({"token": token, "source": _addr(topics[2]), "target": _addr(topics[3]),
                                  "amount": format_amount(int(words[1], 16), 0), "name": "ERC1155", "standard": "ERC-1155"})
            elif t0 == TRANSFER_BATCH and len(topics) == 4:
                words = _words(log.get("data", "0x"))
                ids_at, vals_at = int(words[0], 16) // 32, int(words[1], 16) // 32
                n = int(words[ids_at], 16)
                for i in range(n):
                    found.append({"token": token, "source": _addr(topics[2]), "target": _addr(topics[3]),
                                  "amount": format_amount(int(words[vals_at + 1 + i], 16), 0), "name": "ERC1155",
                                  "standard": "ERC-1155"})
        except (ValueError, IndexError):
            continue                                                  # malformed log: skip, never fail the run
    return found


def _graph(transfers: List[dict]) -> dict:
    graph = nx.MultiDiGraph()
    for t in transfers:
        graph.add_node(t["source"], label=t["source"])
        graph.add_node(t["target"], label=t["target"])
        graph.add_edge(t["source"], t["target"], label=f"{t['token']} [{t['name']}] ({t['amount']})")
    return nx.node_link_data(graph, edges="edges")


def _date(timestamp: int) -> dict:
    utc = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return {"original": utc.strftime("%b-%d-%Y %I:%M:%S %p UTC"),
            "local": utc.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")}


def collect(client: RpcClient, txn_hash: str, chain: str) -> dict:
    """Returns the transaction record. Raises RpcError (not_found / bad_response / ...) when it cannot be built.

    A reverted transaction returns a record whose status is 'Fail'; the caller decides what to do with it.
    """
    tx = client.call("eth_getTransactionByHash", [txn_hash])
    if not tx:
        raise RpcError("not_found", "The RPC node does not know this transaction. Check the network and that the "
                                    "endpoint is for the same chain.")
    receipt = client.call("eth_getTransactionReceipt", [txn_hash])
    if not receipt:
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
    transfers = _transfers(logs, _TokenInfo(client))
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
        "input_data": input_data,
        "method_selector": input_data[:10] if len(input_data) >= 10 else "",
        "value_wei": _int(tx.get("value")),
        "nonce": _int(tx.get("nonce")),
        "creates_contract": created or None,
        "logs": [{"index": _int(l.get("logIndex")), "address": (l.get("address") or "").lower(),
                  "topics": l.get("topics") or [], "data": l.get("data", "0x")} for l in logs[:MAX_LOGS_KEPT]],
        "logs_truncated": len(logs) > MAX_LOGS_KEPT,
    }
