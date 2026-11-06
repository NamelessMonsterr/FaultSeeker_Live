"""Offline JSON-RPC protocol integrity; all transport calls are mocked."""
from unittest.mock import Mock
import pytest
from faultseeker.utils import rpc_provider as rpc

@pytest.mark.parametrize("reply", [{}, [], None, {"error": None}, {"result": 1, "error": {"message": "bad"}}])
def test_malformed_response_is_not_a_null_success(reply):
    with pytest.raises(RuntimeError):
        rpc._check_rpc_error(reply)

def test_explicit_null_is_valid():
    assert rpc._check_rpc_error({"result": None}) is None

@pytest.mark.parametrize("reply", [[], [{"id": 0, "result": 1}],
    [{"id": 0, "result": 1}, {"id": 0, "result": 2}],
    [{"id": 0, "result": 1}, {"id": 9, "result": 2}],
    [{"id": 0, "result": 1}, {"id": 1}]])
def test_invalid_batch_never_rewards_or_caches_partial_results(monkeypatch, reply):
    provider = Mock(url="https://rpc.invalid", is_circuit_open=False)
    monkeypatch.setattr(rpc._registry, "sorted_providers", lambda chain: [provider])
    monkeypatch.setattr(rpc, "_http_post", lambda *a, **k: reply)
    cache = Mock()
    cache.get.return_value = (False, None)
    monkeypatch.setattr(rpc, "_cache", cache)
    fallback = Mock(side_effect=RuntimeError("unavailable"))
    monkeypatch.setattr(rpc, "rpc_call", fallback)
    with pytest.raises(RuntimeError):
        rpc.rpc_batch("eth", [("first", []), ("second", [])], cacheable=True)
    provider.reward.assert_not_called()
    cache.set.assert_not_called()
    fallback.assert_called_once()

def test_valid_out_of_order_batch_preserves_order_and_null(monkeypatch):
    provider = Mock(url="https://rpc.invalid", is_circuit_open=False)
    monkeypatch.setattr(rpc._registry, "sorted_providers", lambda chain: [provider])
    monkeypatch.setattr(rpc, "_http_post", lambda *a, **k: [{"id": 1, "result": None}, {"id": 0, "result": "ok"}])
    assert rpc.rpc_batch("eth", [("first", []), ("second", [])]) == ["ok", None]
    provider.reward.assert_called_once()


def test_builtin_providers_do_not_embed_quicknode_credentials():
    import inspect
    source = inspect.getsource(rpc)
    embedded = "quiknode.pro/" in source.lower()
    assert embedded is False, "Tracked provider credential must be removed"
