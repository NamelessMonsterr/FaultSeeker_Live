"""Offline transport-boundary tests: DNS, sockets and HTTP responses are simulated."""
import socket
import ssl
import pytest
from app import rpc_transport as rpc


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "0.0.0.0", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1"])
def test_nonpublic_addresses_are_rejected(address):
    assert not rpc.public_address(address)


def test_mixed_public_and_private_dns_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))])
    with pytest.raises(rpc.RPCDestinationError): rpc.resolve_public("rpc.invalid", 443)


def test_connection_pins_checked_dns_and_rechecks_next_request(monkeypatch):
    lookups, connections, tls = [], [], []
    def resolve(*a, **k):
        lookups.append(True)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8" if len(lookups) == 1 else "127.0.0.1", 443))]
    class Socket:
        def settimeout(self, value): pass
        def connect(self, address): connections.append(address)
        def close(self): pass
    class Connection:
        def __init__(self, host, port, timeout, context):
            tls.append((host, context.check_hostname, context.verify_mode))
        def request(self, *a, **k): self._create_connection(("rpc.invalid", 443))
        def getresponse(self): return type("Response", (), {"status":200, "read":lambda self,n:b'{"result":"0x1"}'})()
        def close(self): pass
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", lambda *a: Socket())
    monkeypatch.setattr(rpc.http.client, "HTTPSConnection", Connection)
    assert rpc.public_post("https://rpc.invalid/v1", b'{}') == b'{"result":"0x1"}'
    assert connections == [("8.8.8.8", 443)]
    assert tls == [("rpc.invalid", True, ssl.CERT_REQUIRED)]
    with pytest.raises(rpc.RPCDestinationError): rpc.public_post("https://rpc.invalid/v1", b'{}')
    assert len(connections) == 1


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_are_refused_without_followup_connection(monkeypatch, status):
    monkeypatch.setattr(rpc, "resolve_public", lambda *a: [])
    calls = []
    class Connection:
        def __init__(self, *a, **k): calls.append(True)
        def request(self, *a, **k): pass
        def getresponse(self): return type("Response", (), {"status":status})()
        def close(self): pass
    monkeypatch.setattr(rpc.http.client, "HTTPSConnection", Connection)
    with pytest.raises(rpc.RPCDestinationError, match="redirects"):
        rpc.public_post("https://rpc.invalid/v1", b'{}')
    assert len(calls) == 1


@pytest.mark.parametrize("url", ["http://localhost/", "http://127.1/", "http://2130706433/"])
def test_noncanonical_loopback_names_cannot_bypass_resolver(monkeypatch, url):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))])
    with pytest.raises(rpc.RPCDestinationError): rpc.public_post(url, b'{}')
