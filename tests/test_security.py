"""Input validation, SSRF guard and secret redaction."""
import socket

import pytest

from faultseeker.server import security

# Other tests reload these modules in place, so always go through the module object.


def test_validate_hash():
    good = "0x" + "aB" * 32
    assert security.validate_hash("  " + good + " ") == good.lower()
    for bad in ("", None, "0x12", "ab" * 32, "0x" + "g" * 64, "0x" + "a" * 65, "0X" + "a" * 64):
        with pytest.raises(security.ValidationError) as e:
            security.validate_hash(bad)
        assert e.value.field == "txn_hash"


def test_validate_secret():
    assert security.validate_secret("k", None, "Key") == "" and security.validate_secret("k", "  abc  ", "Key") == "abc"
    for bad in ("a b", "a\nb", "x" * 513, "a\x00b"):
        with pytest.raises(security.ValidationError):
            security.validate_secret("k", bad, "Key")


@pytest.fixture()
def public_dns(monkeypatch):
    monkeypatch.setattr(security.settings, "ALLOW_PRIVATE_RPC", False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *_: [(2, 1, 6, "", ("93.184.216.34", 0))])


def test_rpc_url_rules(public_dns):
    assert security.resolve_rpc("", "") == ""
    assert security.resolve_rpc("https://rpc.example/v3/abc", "") == "https://rpc.example/v3/abc"
    assert security.resolve_rpc("wss://rpc.example/ws", "") == "wss://rpc.example/ws"
    assert security.resolve_rpc("https://rpc.example/v3/{key}", "a/b") == "https://rpc.example/v3/a%2Fb"
    cases = [("", "key", "rpc_key"), ("https://x.example/{key}", "", "rpc_key"), ("https://x.example/v3", "key", "rpc_key"),
             ("ftp://x.example", "", "rpc_url"), ("file:///etc/passwd", "", "rpc_url"), ("https://", "", "rpc_url"),
             ("https://x.example/ a", "", "rpc_url"), ("https://x.example/" + "a" * 2100, "", "rpc_url")]
    for url, key, field in cases:
        with pytest.raises(security.ValidationError) as e:
            security.resolve_rpc(url, key)
        assert e.value.field == field, (url, key)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9", "169.254.169.254", "0.0.0.0", "::1", "fe80::1"])
def test_private_addresses_are_blocked(monkeypatch, ip):
    monkeypatch.setattr(security.settings, "ALLOW_PRIVATE_RPC", False)
    fam = 10 if ":" in ip else 2
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *_: [(fam, 1, 6, "", (ip, 0))])
    with pytest.raises(security.ValidationError) as e:
        security.resolve_rpc("https://rpc.example/x", "")
    assert "private" in e.value.message


def test_dns_failure_and_private_override(monkeypatch):
    monkeypatch.setattr(security.settings, "ALLOW_PRIVATE_RPC", False)

    def boom(*_):
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(security.ValidationError) as e:
        security.resolve_rpc("https://nowhere.invalid/x", "")
    assert "resolve" in e.value.message
    monkeypatch.setattr(security.settings, "ALLOW_PRIVATE_RPC", True)
    assert security.resolve_rpc("http://127.0.0.1:8545", "") == "http://127.0.0.1:8545"


def test_redactor_masks_every_form_of_a_secret():
    url = "https://mainnet.infura.io/v3/0123456789abcdef0123?apikey=QUERYSECRET1"
    r = security.Redactor("sk-proj-ABCDEFGHIJKLMNOPQRST", url, "", None, "abc")
    text = (f"key=sk-proj-ABCDEFGHIJKLMNOPQRST url={url} host-path=mainnet.infura.io/v3/0123456789abcdef0123?apikey=QUERYSECRET1 "
            "tail=0123456789abcdef0123 q=apikey=QUERYSECRET1 other sk-abcdefghijklmnopqrstuvwxyz abc")
    cleaned = r.clean(text)
    for secret in ("sk-proj", "0123456789abcdef0123", "QUERYSECRET1", "sk-abcdefghijklmnop", "infura"):
        assert secret not in cleaned
    assert cleaned.endswith("abc"), "secrets shorter than 4 characters are left alone"
    assert security.Redactor().clean("nothing to hide") == "nothing to hide"
