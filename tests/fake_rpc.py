"""A local JSON-RPC node and a local Sourcify, both served from a thread. OFFLINE: nothing leaves localhost."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TX = "0x" + "ab" * 32
REVERTED = "0x" + "bd" * 32
PENDING = "0x" + "ee" * 32
FROM = "0x" + "11" * 20
TO = "0x" + "22" * 20
TOKEN = "0x" + "33" * 20          # 6-decimals ERC-20 "USDC"
NFT = "0x" + "44" * 20
MULTI = "0x" + "55" * 20
POOL = "0x" + "66" * 20
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SINGLE = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
BATCH = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb"


def w(n):
    return format(n, "064x")


def t(addr):
    return "0x" + "0" * 24 + addr[2:]


def string_result(text):
    raw = text.encode()
    return "0x" + w(32) + w(len(raw)) + raw.hex().ljust(64, "0")


LOGS = [
    {"address": TOKEN, "topics": [TRANSFER, t(FROM), t(POOL)], "data": "0x" + w(1_234_567_890), "logIndex": "0x0"},   # 1,234.56789 USDC
    {"address": TOKEN, "topics": [TRANSFER, t(POOL), t(FROM)], "data": "0x" + w(5), "logIndex": "0x1"},               # 0.000005
    {"address": NFT, "topics": [TRANSFER, t(POOL), t(FROM), "0x" + w(7)], "data": "0x", "logIndex": "0x2"},
    {"address": MULTI, "topics": [SINGLE, t(TO), t(POOL), t(FROM)], "data": "0x" + w(9) + w(25), "logIndex": "0x3"},
    {"address": MULTI, "topics": [BATCH, t(TO), t(POOL), t(FROM)],
     "data": "0x" + w(64) + w(160) + w(2) + w(1) + w(2) + w(2) + w(10) + w(20), "logIndex": "0x4"},
    {"address": POOL, "topics": ["0x" + "99" * 32], "data": "0x", "logIndex": "0x5"},                                # not a transfer
]


def node_state():
    tx = {"hash": TX, "from": FROM, "to": TO, "input": "0xa9059cbb" + "00" * 8, "value": "0x10", "gas": "0x5208",
          "nonce": "0x3", "blockNumber": "0x64", "gasPrice": "0x9"}
    receipts = {
        TX: {"status": "0x1", "blockNumber": "0x64", "gasUsed": "0x4000", "effectiveGasPrice": "0xa", "logs": LOGS,
             "contractAddress": None},
        REVERTED: {"status": "0x0", "blockNumber": "0x64", "gasUsed": "0x1", "logs": []},
        PENDING: None,
    }
    txs = {TX: tx, REVERTED: dict(tx, hash=REVERTED), PENDING: dict(tx, hash=PENDING, blockNumber=None)}
    return txs, receipts


class FakeServer:
    """`self.calls` records (path, method) for every request; `self.mode` can be 'ok', 'forbidden', 'flaky', 'down'."""

    def __init__(self):
        self.calls = []
        self.mode = "ok"
        self.failures_left = 0
        self.sourcify = {}            # "chainId/address" -> response dict (404 when absent)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.calls.append((self.path, "GET"))
                key = self.path.split("/v2/contract/")[-1].split("?")[0]
                if outer.mode == "down":
                    return self._send(503, {})
                if key in outer.sourcify:
                    return self._send(200, outer.sourcify[key])
                self._send(404, {"error": "not found"})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                method, params = body["method"], body.get("params") or []
                outer.calls.append((self.path, method))
                if outer.mode == "forbidden":
                    return self._send(403, {"error": "blocked"})
                if outer.mode == "flaky" and outer.failures_left > 0:
                    outer.failures_left -= 1
                    return self._send(503, {})
                txs, receipts = node_state()
                result = None
                if method == "eth_getTransactionByHash":
                    result = txs.get(params[0])
                elif method == "eth_getTransactionReceipt":
                    result = receipts.get(params[0])
                elif method == "eth_getBlockByNumber":
                    result = {"number": params[0], "timestamp": hex(1_700_000_000)}
                elif method == "eth_blockNumber":
                    result = "0x6e"
                elif method == "eth_call":
                    to, data = params[0]["to"], params[0]["data"]
                    if to == TOKEN and data == "0x313ce567":
                        result = "0x" + w(6)
                    elif to == TOKEN and data == "0x95d89b41":
                        result = string_result("USDC")
                    else:
                        return self._send(200, {"jsonrpc": "2.0", "id": body["id"], "error": {"message": "execution reverted"}})
                self._send(200, {"jsonrpc": "2.0", "id": body["id"], "result": result})

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def http(self):
        return f"http://127.0.0.1:{self.port}"

    @property
    def ws(self):
        return f"ws://127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
