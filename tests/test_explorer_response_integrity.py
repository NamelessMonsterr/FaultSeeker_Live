"""Offline explorer API classification and safe diagnostics."""
import json
from unittest.mock import Mock
import pytest
from faultseeker.utils import explorer_provider as ep

class Response:
    def __init__(self, payload): self.payload = payload
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self): return json.dumps(self.payload).encode()

@pytest.mark.parametrize("result", ["Invalid API Key", "Max rate limit reached", "Upstream backend unavailable"])
def test_notok_does_not_mask_result_failure_or_reward_failed_endpoint(monkeypatch, result):
    endpoints = [Mock(base_url=f"https://{name}.invalid", is_circuit_open=False) for name in ("first", "second")]
    for endpoint in endpoints: endpoint.build_url.return_value = endpoint.base_url
    monkeypatch.setattr(ep._registry, "sorted_endpoints", lambda chain: endpoints)
    responses = iter([{"status": "0", "message": "NOTOK", "result": result}, {"status": "1", "message": "OK", "result": []}])
    requests = []
    def get(request, **kwargs):
        requests.append(request.full_url)
        return Response(next(responses))
    monkeypatch.setattr(ep.urllib.request, "urlopen", get)
    data = ep.explorer_call("eth", {"action": "getabi"})
    assert data["status"] == "1"
    assert len(requests) == 2
    endpoints[0].reward.assert_not_called()
    endpoints[0].penalize.assert_called_once()
    endpoints[1].reward.assert_called_once()


def test_normal_no_records_response_is_not_endpoint_failure(monkeypatch):
    endpoint = Mock(base_url="https://source.invalid", is_circuit_open=False)
    endpoint.build_url.return_value = endpoint.base_url
    monkeypatch.setattr(ep._registry, "sorted_endpoints", lambda chain: [endpoint])
    payload = {"status": "0", "message": "No transactions found", "result": []}
    monkeypatch.setattr(ep.urllib.request, "urlopen", lambda *a, **k: Response(payload))
    assert ep.explorer_call("eth", {}) == payload
    endpoint.reward.assert_called_once()
    endpoint.penalize.assert_not_called()


def test_valid_source_text_is_not_classified_as_an_auth_error(monkeypatch):
    endpoint = Mock(base_url="https://source.invalid", is_circuit_open=False)
    endpoint.build_url.return_value = endpoint.base_url
    monkeypatch.setattr(ep._registry, "sorted_endpoints", lambda chain: [endpoint])
    payload = {"status": "1", "message": "OK", "result": [{"SourceCode": 'string constant X = "invalid api key";'}]}
    monkeypatch.setattr(ep.urllib.request, "urlopen", lambda *a, **k: Response(payload))
    assert ep.explorer_call("eth", {}) == payload


def test_endpoint_diagnostics_do_not_expose_url_credentials_or_path(caplog, capsys, monkeypatch):
    endpoint = ep._ExplorerEndpoint("https://dummy-user:dummy-password@source.invalid/dummy-path-key?apikey=dummy-query-key")
    monkeypatch.setattr(ep._registry, "sorted_endpoints", lambda chain: [endpoint])
    for _ in range(3): endpoint.penalize(1, endpoint.PENALTY_AUTH)
    ep.print_explorer_stats("eth")
    observed = repr(endpoint) + caplog.text + capsys.readouterr().out
    for secret in ("dummy-user", "dummy-password", "dummy-path-key", "dummy-query-key"):
        assert secret not in observed
