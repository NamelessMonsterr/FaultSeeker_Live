"""Public-only transport for visitor RPCs, including clients launched by the pipeline.

A per-worker loopback relay gives Python and cast the same checked transport.
DNS answers are validated and pinned to the connection; TLS still verifies the
original hostname. Redirects are refused, so they cannot bypass the address check.
"""
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MAX_BODY = 32 * 1024 * 1024


class RPCDestinationError(ValueError):
    pass


def public_address(value):
    address = ipaddress.ip_address(value.split("%", 1)[0])
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global and not (address.is_multicast or address.is_reserved or address.is_unspecified)


def parse_endpoint(url):
    try:
        if any(ord(c) < 33 for c in url) or "\\" in url:
            raise ValueError()
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError()
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            if parsed.hostname.lower().rstrip(".") == "localhost" or parsed.hostname.lower().endswith(".localhost"):
                raise RPCDestinationError("Visitor RPC destinations must be public.")
        else:
            if not public_address(parsed.hostname):
                raise RPCDestinationError("Visitor RPC destinations must be public.")
        return parsed, port
    except (ValueError, TypeError) as exc:
        if isinstance(exc, RPCDestinationError):
            raise
        raise RPCDestinationError("RPC URL must be a valid HTTP(S) endpoint without userinfo or a fragment.") from None


def resolve_public(host, port):
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers or any(not public_address(row[4][0]) for row in answers):
        raise RPCDestinationError("RPC DNS resolved to a non-public destination.")
    return answers


def connect_pinned(answers, timeout, source_address=None):
    last_error = None
    for family, kind, proto, _, address in answers:
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(address)  # numeric address from the already-validated DNS answer
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise OSError("Public RPC connection failed") from last_error


def public_post(url, body, timeout=60):
    parsed, port = parse_endpoint(url)
    answers = resolve_public(parsed.hostname, port)
    if parsed.scheme == "https":
        connection = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout, context=ssl.create_default_context())
    else:
        connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    # HTTP(S)Connection retains the original host for Host/SNI/certificate checks.
    # Override only TCP establishment, preventing a second DNS lookup/rebinding.
    connection._create_connection = lambda address, timeout=timeout, source_address=None: connect_pinned(answers, timeout, source_address)
    response = None
    try:
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.request("POST", path, body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise RPCDestinationError("RPC redirects are not accepted; configure the final public endpoint.")
        if not 200 <= response.status < 300:
            raise RPCDestinationError("RPC endpoint returned HTTP %s." % response.status)
        payload = response.read(MAX_BODY + 1)
        if len(payload) > MAX_BODY:
            raise RPCDestinationError("RPC response exceeded the size limit.")
        json.loads(payload)  # Do not pass HTML error pages through as RPC results.
        return payload
    finally:
        if response is not None:
            getattr(response, "close", lambda: None)()
        connection.close()


class PublicRPCRelay:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.server = None
        self.thread = None
        self.url = None

    def start(self):
        parsed, port = parse_endpoint(self.endpoint)
        resolve_public(parsed.hostname, port)  # fail before model preflight/analysis
        endpoint = self.endpoint
        route = "/" + secrets.token_urlsafe(32)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass  # URLs can contain credentials.

            def do_POST(self):
                status = 200
                try:
                    if not secrets.compare_digest(self.path, route):
                        self.send_error(404)
                        return
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                        self.send_error(413)
                        return
                    self.connection.settimeout(60)
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise ValueError("Incomplete request")
                    payload = public_post(endpoint, body)
                except RPCDestinationError as exc:
                    status = 502
                    payload = json.dumps({"error": {"code": -32000, "message": str(exc)}}).encode()
                except Exception:
                    status = 502
                    payload = b'{"error":{"code":-32000,"message":"Public RPC transport failed."}}'
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = "http://127.0.0.1:%s%s" % (self.server.server_port, route)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.url

    def close(self):
        if self.server is not None:
            if self.thread is not None and self.thread.is_alive():
                self.server.shutdown()
            self.server.server_close()
            if self.thread is not None and self.thread.ident is not None:
                self.thread.join(timeout=2)
