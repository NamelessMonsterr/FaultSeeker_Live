"""Minimal JSON-RPC client used to collect transaction data without any block-explorer page.

Standard library only. The endpoint is FAULTSEEKER_RPC_URL (the web console sets it per run for a custom endpoint) or,
failing that, the foundry.toml alias for the chain. WebSocket URLs are rewritten to their HTTP form, because this
client speaks HTTP only. The endpoint URL is never put into an error message or printed: it may embed a provider key.
"""
import http.client
import ipaddress
import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[2]

# Seconds to wait between attempts; tests replace this with zeros.
RETRY_DELAYS = (1.0, 3.0)
if os.environ.get("FAULTSEEKER_RPC_RETRIES", "").strip().isdigit():      # 0 = a single attempt (used by offline tests)
    RETRY_DELAYS = RETRY_DELAYS[:int(os.environ["FAULTSEEKER_RPC_RETRIES"])]
TIMEOUT = 30


# Messages nodes use when the requested block/state/receipt is outside the history they keep (pruned or non-archive nodes). Deliberately
# specific: generic wording such as "header not found", "execution reverted", "method not found", "invalid params" or a rate limit is NOT
# treated as pruned history.
PRUNED_HISTORY = re.compile(
    r"missing trie node|historical state[^.]{0,60}(?:is )?not available|state (?:at|for) block[^.]{0,60}(?:is )?(?:not available|pruned)"
    r"|(?:data|block|state|history)[^.]{0,40}\bpruned|\bpruned\b[^.]{0,40}(?:data|block|state|history)|old data not available"
    r"|not an archive node|requires? (?:an? )?archive|archive (?:node|mode) (?:is )?required|proof window"
    r"|historical (?:data|backend|rpc)[^.]{0,40}not (?:available|supported)", re.I)


def is_pruned_history(text: str) -> bool:
    return bool(PRUNED_HISTORY.search(text or ""))


class RpcError(Exception):
    """kind: no_endpoint | unreachable | rejected | bad_response | not_found | history_unavailable | wrong_chain | unknown_chain."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


def http_url(url: str) -> str:
    """ws:// and wss:// become http:// and https://. Infura-style /ws/ path segments are dropped."""
    parts = urlsplit(url.strip())
    scheme = {"ws": "http", "wss": "https"}.get(parts.scheme.lower(), parts.scheme.lower())
    path = parts.path
    if parts.scheme.lower() in ("ws", "wss"):
        path = re.sub(r"^/ws(/|$)", r"/", path) if path.startswith("/ws") else path
    return urlunsplit((scheme, parts.netloc, path, parts.query, ""))


def _foundry_alias(chain: str) -> str:
    """The endpoint foundry.toml lists for `chain` ('' when there is none)."""
    for base in (Path.cwd(), ROOT):
        toml = base / "foundry.toml"
        if toml.is_file():
            break
    else:
        return ""
    try:
        text = toml.read_text(encoding="utf-8")
    except OSError:
        return ""
    block = re.search(r"rpc_endpoints\s*=\s*\{(.*?)\}", text, re.S)
    if not block:
        return ""
    wanted = {chain.lower()}
    try:
        from faultseeker import chains
        known = chains.get(chain)
        if known:
            wanted.add(known["id"])
    except ImportError:
        pass
    for key, value in re.findall(r"([A-Za-z0-9_\-]+)\s*=\s*\"([^\"]+)\"", block.group(1)):
        if key.lower() in wanted:
            return value
    return ""


def resolve_endpoint(chain: str) -> str:
    """HTTP(S) endpoint for `chain`: FAULTSEEKER_RPC_URL first, then the foundry.toml alias."""
    custom = os.environ.get("FAULTSEEKER_RPC_URL", "").strip()
    url = custom or _foundry_alias(chain)
    if not url:
        raise RpcError("no_endpoint", f"No RPC endpoint is configured for '{chain}'. Provide one under RPC connection.")
    return http_url(url)


def _host(url: str) -> str:
    return urlsplit(url).hostname or "the RPC endpoint"


def _enforce_public() -> bool:
    """The web server sets FAULTSEEKER_ENFORCE_PUBLIC_RPC=1 for its worker unless private endpoints were explicitly allowed."""
    return os.environ.get("FAULTSEEKER_ENFORCE_PUBLIC_RPC", "") == "1"


def _validated_ip(host: str, port: int) -> str:
    """Resolves `host` NOW and returns an address to connect to, refusing the endpoint when ANY answer is not a public address
    (loopback, private, link-local, reserved, multicast, unspecified, shared/CGNAT, cloud metadata). The connection is then made to
    that exact address, so the check and the connection cannot see different DNS answers."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RpcError("unreachable", f"could not resolve {host} ({type(exc).__name__}).") from None
    chosen = None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if not ip.is_global:
            raise RpcError("rejected", f"{host} resolves to a private or reserved address, which this server does not connect to.")
        chosen = chosen or str(ip)
    if not chosen:
        raise RpcError("unreachable", f"{host} did not resolve to any address.")
    return chosen


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.create_connection((_validated_ip(self.host, self.port), self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        sock = socket.create_connection((_validated_ip(self.host, self.port), self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)          # certificate checked against the NAME, not the IP


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A JSON-RPC endpoint has no reason to redirect a POST, and a redirect would send the request (and any key in it) to a host
    nobody validated. Redirects are refused: urllib then raises HTTPError for the 3xx."""

    def redirect_request(self, *args, **kwargs):
        return None


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PinnedHTTPConnection, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req, context=self._context)


def _opener():
    handlers = [_NoRedirect()]
    if _enforce_public():
        handlers += [_PinnedHTTPHandler(), _PinnedHTTPSHandler()]
    return urllib.request.build_opener(*handlers)


class RpcClient:
    def __init__(self, url: str, timeout: float = TIMEOUT):
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: Optional[list] = None) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or []}).encode()
        request = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "faultseeker/1.0"})
        host = _host(self.url)
        last = "no attempt made"
        for attempt in range(len(RETRY_DELAYS) + 1):
            if attempt:
                time.sleep(RETRY_DELAYS[attempt - 1])
            try:
                with _opener().open(request, timeout=self.timeout) as resp:
                    raw = resp.read()
            except urllib.error.HTTPError as exc:
                if 300 <= exc.code < 400:
                    raise RpcError("rejected", f"{host} answered with a redirect (HTTP {exc.code}). Redirects are not followed: "
                                               "use the endpoint's final URL.")
                if exc.code in (401, 403):
                    raise RpcError("rejected", f"{host} refused the request (HTTP {exc.code}). Check the endpoint and its key.")
                if exc.code == 429 or exc.code >= 500:
                    last = f"{host} answered HTTP {exc.code}"
                    continue
                raise RpcError("rejected", f"{host} answered HTTP {exc.code}.")
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                reason = getattr(exc, "reason", exc)
                last = f"could not reach {host} ({type(reason).__name__})"
                continue
            try:
                payload = json.loads(raw)
            except ValueError:
                raise RpcError("bad_response", f"{host} did not return JSON. Is this a JSON-RPC endpoint?")
            if not isinstance(payload, dict):
                raise RpcError("bad_response", f"{host} returned an unexpected JSON-RPC reply.")
            if payload.get("error"):
                err = payload["error"]
                text = str(err.get("message", err) if isinstance(err, dict) else err)[:160]
                if is_pruned_history(text):
                    raise RpcError("history_unavailable", f"{host} does not have the history needed for {method} ({text}). "
                                                          "Use an archive-capable RPC endpoint.")
                if re.search(r"rate|limit|capacity|timeout|busy", text, re.I) and attempt < len(RETRY_DELAYS):
                    last = f"{host} reported: {text}"
                    continue
                raise RpcError("rejected", f"{method} failed: {text}")
            return payload.get("result")
        raise RpcError("unreachable", f"RPC request failed after {len(RETRY_DELAYS) + 1} attempts: {last}.")
