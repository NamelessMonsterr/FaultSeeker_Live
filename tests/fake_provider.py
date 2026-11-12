"""A controllable OpenAI-compatible server on localhost. OFFLINE TEST DOUBLE: no real provider is ever contacted.

Records every request (method, path, headers, JSON body). Behaviour is chosen per instance:
  key_ok        callable(key) -> bool, decides 200 vs 401 on /models and /chat/completions
  chat_status   force a status code for chat completions (e.g. 500, 429, 400)
  chat_error    JSON error body used with chat_status
  delay         seconds to sleep before answering
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeProvider:
    def __init__(self, key_ok=lambda key: True, chat_status=200, chat_error=None, delay=0.0, models_status=None, redirect_to=None):
        self.key_ok, self.chat_status, self.chat_error, self.delay = key_ok, chat_status, chat_error, delay
        self.models_status, self.redirect_to = models_status, redirect_to
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):   # keep test output quiet
                pass

            def _send(self, status, body, headers=None):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _record(self, body=None):
                key = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
                outer.requests.append({"method": self.command, "path": self.path, "key": key, "body": body,
                                       "headers": {k.lower(): v for k, v in self.headers.items()}})
                return key

            def do_GET(self):
                key = self._record()
                if outer.delay:
                    time.sleep(outer.delay)
                if outer.redirect_to:
                    return self._send(307, {}, {"Location": outer.redirect_to})
                if outer.models_status:
                    return self._send(outer.models_status, {"error": {"message": "forced"}})
                if not outer.key_ok(key):
                    return self._send(401, {"error": {"message": "Incorrect API key provided", "code": "invalid_api_key"}})
                self._send(200, {"object": "list", "data": [{"id": "m"}]})

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                key = self._record(body)
                if outer.delay:
                    time.sleep(outer.delay)
                if not outer.key_ok(key):
                    return self._send(401, {"error": {"message": "Incorrect API key provided", "code": "invalid_api_key"}})
                if outer.chat_status != 200:
                    return self._send(outer.chat_status, outer.chat_error or {"error": {"message": "forced failure"}})
                self._send(200, {"id": "x", "object": "chat.completion", "created": 0, "model": body.get("model", "m"),
                                 "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
                                 "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}/v1"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()

    def chat_requests(self):
        return [r for r in self.requests if r["method"] == "POST"]
