"""Regression tests: unkeyed endpoints are skipped; 402 is an auth error.

A keyed endpoint with no key configured must not be called at all - the
placeholder key only produces guaranteed auth failures, once per address,
for a whole run. HTTP 402 (credential/payment failure on keyed APIs) must
classify as an auth error so the circuit breaker treats it like 401/403.
"""
import logging

from faultseeker.utils import explorer_provider as xp


def test_classify_402_as_auth():
    assert xp._classify_http(402) is xp._AuthError
    assert xp._classify_http(401) is xp._AuthError
    assert xp._classify_http(403) is xp._AuthError
    assert xp._classify_http(429) is xp._RateLimitError


def test_has_configured_key(monkeypatch):
    ep = xp._ExplorerEndpoint('https://api.blockscout.com/v2/api',
                              'BLOCKSCOUT_API_KEY', 65)
    monkeypatch.delenv('BLOCKSCOUT_API_KEY', raising=False)
    assert not ep.has_configured_key
    monkeypatch.setenv('BLOCKSCOUT_API_KEY', 'k')
    assert ep.has_configured_key
    monkeypatch.setenv('BLOCKSCOUT_API_KEY', '   ')
    assert not ep.has_configured_key
    keyless = xp._ExplorerEndpoint('https://example.invalid/api', '', 50)
    assert keyless.has_configured_key


def test_unkeyed_endpoints_make_no_requests(monkeypatch, caplog):
    calls = []
    class FakeResp:
        def read(self):
            return b'{"status":"1","result":[]}'
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    def fake_urlopen(req, timeout=0):
        calls.append(req.full_url)
        return FakeResp()
    monkeypatch.delenv('ETHERSCAN_API_KEY', raising=False)
    monkeypatch.delenv('ETHERSCAN_API_KEY_2', raising=False)
    monkeypatch.delenv('BLOCKSCOUT_API_KEY', raising=False)
    monkeypatch.setattr(xp.urllib.request, 'urlopen', fake_urlopen)
    # fresh registry state: reset circuits/scores by rebuilding endpoints
    xp._registry._chains.pop('eth', None)
    with caplog.at_level(logging.DEBUG, logger='faultseeker.explorer'):
        result = xp.explorer_call('eth', {'module': 'contract',
                                          'action': 'getsourcecode',
                                          'address': '0xabc'})
    assert result is None
    assert calls == [], f'unkeyed endpoints were called: {calls}'
    assert 'lack configured API keys' in caplog.text


def test_keyed_endpoint_is_used_when_key_present(monkeypatch):
    calls = []
    class FakeResp:
        def read(self):
            return b'{"status":"1","result":[]}'
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    def fake_urlopen(req, timeout=0):
        calls.append(req.full_url)
        return FakeResp()
    monkeypatch.delenv('ETHERSCAN_API_KEY', raising=False)
    monkeypatch.delenv('ETHERSCAN_API_KEY_2', raising=False)
    monkeypatch.setenv('BLOCKSCOUT_API_KEY', 'k123')
    monkeypatch.setattr(xp.urllib.request, 'urlopen', fake_urlopen)
    xp._registry._chains.pop('eth', None)
    result = xp.explorer_call('eth', {'module': 'contract',
                                      'action': 'getsourcecode',
                                      'address': '0xabc'})
    assert result is not None
    assert len(calls) == 1
    assert 'api.blockscout.com' in calls[0] and 'chain_id=1' in calls[0]
