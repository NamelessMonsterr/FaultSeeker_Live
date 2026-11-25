"""Audit R01 (RPC redirects / connect-time address) and R02 (latest-only source provenance). OFFLINE: local controlled fixtures only."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

try:
    from faultseeker.data_collection import rpc_client
    from faultseeker.data_collection.rpc_client import RpcClient, RpcError
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    from faultseeker.server import results
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)


class Hits:
    def __init__(self, redirect_to=None, status=307):
        self.requests, hits = [], self
        self.redirect_to, self.status = redirect_to, status

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                hits.requests.append(self.rfile.read(n))
                if hits.redirect_to:
                    self.send_response(hits.status)
                    self.send_header("Location", hits.redirect_to)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


@pytest.fixture()
def servers(monkeypatch):
    monkeypatch.setattr(rpc_client, "RETRY_DELAYS", (0, 0))
    target = Hits()
    front = Hits(redirect_to=target.url)
    yield front, target
    front.close()
    target.close()


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_the_rpc_client_never_follows_a_redirect(monkeypatch, status):
    monkeypatch.setattr(rpc_client, "RETRY_DELAYS", (0, 0))
    target, front = Hits(), None
    front = Hits(redirect_to=target.url, status=status)
    try:
        with pytest.raises(RpcError) as err:
            RpcClient(front.url).call("eth_chainId")
        assert err.value.kind == "rejected" and "redirect" in err.value.message.lower()
        assert target.requests == [], "the redirect destination received nothing: a validated URL cannot be turned into another target"
        assert len(front.requests) == 1, "a redirect is not retried"
    finally:
        front.close()
        target.close()


def test_a_direct_endpoint_still_works(monkeypatch):
    direct = Hits()
    try:
        assert RpcClient(direct.url).call("eth_chainId") == "0x1"
    finally:
        direct.close()


def test_private_addresses_are_refused_at_connect_time_when_enforcement_is_on(monkeypatch):
    direct = Hits()
    try:
        monkeypatch.setenv("FAULTSEEKER_ENFORCE_PUBLIC_RPC", "1")
        with pytest.raises(RpcError) as err:
            RpcClient(direct.url).call("eth_chainId")
        assert err.value.kind == "rejected" and "private" in err.value.message.lower()
        assert direct.requests == [], "no request left the process"
        monkeypatch.delenv("FAULTSEEKER_ENFORCE_PUBLIC_RPC")
        assert RpcClient(direct.url).call("eth_chainId") == "0x1", "enforcement is off by default (private endpoints are an explicit opt-in)"
    finally:
        direct.close()


@pytest.mark.parametrize("answer", ["10.0.0.5", "169.254.169.254", "127.0.0.1", "::1", "fd00::1", "0.0.0.0"])
def test_a_hostname_that_resolves_to_a_non_public_address_is_refused_at_connect_time(monkeypatch, answer):
    monkeypatch.setenv("FAULTSEEKER_ENFORCE_PUBLIC_RPC", "1")
    import socket
    monkeypatch.setattr(rpc_client.socket, "getaddrinfo", lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answer, 80))])
    with pytest.raises(RpcError) as err:
        RpcClient("http://rebind.example/rpc").call("eth_chainId")
    assert err.value.kind == "rejected" and "private" in err.value.message.lower()


def test_one_private_answer_among_public_ones_refuses_the_endpoint(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_ENFORCE_PUBLIC_RPC", "1")
    import socket
    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 80))]
    monkeypatch.setattr(rpc_client.socket, "getaddrinfo", lambda *a, **k: answers)
    with pytest.raises(RpcError):
        RpcClient("http://mixed.example/rpc").call("eth_chainId")


def test_the_server_turns_enforcement_on_for_the_worker_unless_private_rpc_is_allowed(make_client, monkeypatch):
    from faultseeker.server import runs, settings
    make_client()
    reg = settings.registry()
    provider = reg.providers["openai"]
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_RPC", False)
    assert runs.RunManager._worker_env(reg, provider, "k", "https://rpc.example/x")["FAULTSEEKER_ENFORCE_PUBLIC_RPC"] == "1"
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_RPC", True)
    monkeypatch.setenv("FAULTSEEKER_ENFORCE_PUBLIC_RPC", "1")
    assert "FAULTSEEKER_ENFORCE_PUBLIC_RPC" not in runs.RunManager._worker_env(reg, provider, "k", "http://127.0.0.1:8545")


# ------------------------------------------------------------------------------------------------ R02

def raw(**kw):
    base = {"transaction_hash": "0x" + "1" * 64, "chain": "eth", "ranked_suspicious_functions": [], "potentially_vulnerable_functions": {},
            "transaction_understanding": "t"}
    base.update(kw)
    return base


def test_retrieved_source_is_reported_as_latest_not_pinned_to_the_transaction_block():
    out = results.normalize(raw(source_provenance={"sources_used": 2, "pinned_to_transaction_block": False}))
    text = " ".join(out["warnings"])
    assert "2 contract" in text and "not pinned to the transaction block" in text and "upgradeable" in text
    assert "latest" in text.lower()


@pytest.mark.parametrize("value", [None, "x", 5, [], {}, {"sources_used": 0}, {"sources_used": -1}, {"sources_used": "many"}, {"sources_used": True}])
def test_no_provenance_warning_without_sources_or_with_malformed_data(value):
    out = results.normalize(raw(source_provenance=value))
    assert not any("pinned" in w for w in out["warnings"])


def test_the_analysis_counts_the_contracts_whose_source_it_actually_used():
    a = object.__new__(FunctionAnalyzer)
    a.contract_info = {"0xaa": {"Vault": {"source": "x"}}, "0xbb": {}, "0xcc": {"Token": {"source": "y"}}}
    assert a.source_provenance_report() == {"sources_used": 2, "pinned_to_transaction_block": False}
    a.contract_info = {}
    assert a.source_provenance_report() == {"sources_used": 0, "pinned_to_transaction_block": False}
    del a.contract_info
    assert a.source_provenance_report()["sources_used"] == 0
