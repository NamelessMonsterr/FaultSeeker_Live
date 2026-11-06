"""Regression tests: keyed Blockscout V2 endpoint for eth source acquisition.

Covers commit 75493fd: the eth registry gains a documented programmatic
Blockscout endpoint (api.blockscout.com/v2/api) keyed by BLOCKSCOUT_API_KEY
with chain_id=1 carried via endpoint extra_params, and existing tuple-style
registry entries keep working.
"""
import os

from faultseeker.utils.explorer_provider import _ExplorerEndpoint, _ExplorerRegistry


def test_build_url_merges_extra_params_and_key(monkeypatch):
    monkeypatch.setenv('BLOCKSCOUT_API_KEY', 'testkey123')
    ep = _ExplorerEndpoint(
        'https://api.blockscout.com/v2/api', 'BLOCKSCOUT_API_KEY', 65,
        {'chain_id': '1'},
    )
    url = ep.build_url({'module': 'contract', 'action': 'getsourcecode',
                        'address': '0xabc'})
    assert url == ('https://api.blockscout.com/v2/api?module=contract'
                   '&action=getsourcecode&address=0xabc&chain_id=1'
                   '&apikey=testkey123')


def test_caller_params_win_over_extra_params(monkeypatch):
    monkeypatch.setenv('BLOCKSCOUT_API_KEY', 'k')
    ep = _ExplorerEndpoint('https://api.blockscout.com/v2/api',
                           'BLOCKSCOUT_API_KEY', 65, {'chain_id': '1'})
    assert 'chain_id=56' in ep.build_url({'module': 'x', 'chain_id': '56'})


def test_eth_registry_uses_v2_endpoints_with_chain_params():
    eps = _ExplorerRegistry()._endpoints('eth')
    assert len(eps) == 3
    assert eps[0].base_url == 'https://api.etherscan.io/v2/api'
    assert eps[0].extra_params == {'chainid': '1'}
    assert eps[1].base_url == 'https://api.etherscan.io/v2/api'
    assert eps[1].extra_params == {'chainid': '1'}
    blockscout = eps[-1]
    assert blockscout.base_url == 'https://api.blockscout.com/v2/api'
    assert blockscout.extra_params == {'chain_id': '1'}
    assert blockscout.api_key_env == 'BLOCKSCOUT_API_KEY'


def test_other_chain_registries_unaffected():
    reg = _ExplorerRegistry()
    for chain in ('bsc', 'polygon', 'aurora'):
        assert len(reg._endpoints(chain)) >= 1


def test_unset_key_degrades_to_placeholder(monkeypatch):
    monkeypatch.delenv('BLOCKSCOUT_API_KEY', raising=False)
    ep = _ExplorerEndpoint('https://api.blockscout.com/v2/api',
                           'BLOCKSCOUT_API_KEY', 65, {'chain_id': '1'})
    # No key configured: request still forms and will auth-fail into the
    # existing circuit breaker, exactly like an unkeyed etherscan slot.
    assert 'apikey=' in ep.build_url({'module': 'contract'})
