"""HTTP API behaviour: validation, run lifecycle, results, history, static files, headers."""
import os
import re

from tests.conftest import HASH, payload, start_run, wait_final


def test_static_files_and_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "FAULTSEEKER" in r.text
    csp = r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "script-src 'self'" in csp and "style-src 'self'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/assets/console.js").status_code == 200
    assert client.get("/assets/console.css").status_code == 200
    assert client.get("/assets/console.js").headers["cache-control"] == "no-cache"
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/api/health").headers["cache-control"] == "no-store"
    assert client.get("/favicon.ico").status_code == 204
    assert client.get("/assets/../settings.py").status_code in (404, 400)


def test_config_contents(client):
    cfg = client.get("/api/config").json()
    assert len(cfg["chains"]) == 16
    assert {c["id"] for c in cfg["chains"] if c["support"] == "full"} == {"eth", "bsc"}
    assert len(cfg["presets"]["eth"]) == 101 and len(cfg["presets"]["bsc"]) == 13
    assert cfg["models"][0]["key_required"] is True and sum(m["default"] for m in cfg["models"]) == 1
    assert cfg["environment"]["ready"] is True and cfg["active_run"] is None


def test_validation_errors(client):
    def err(**kw):
        return client.post("/api/runs", json=payload(**kw)).json()["error"]

    assert err(txn_hash="0x12")["field"] == "txn_hash"
    assert err(txn_hash="0x" + "g" * 64)["field"] == "txn_hash"
    assert err(chain="nope")["field"] == "chain"
    assert "cast" in err(chain="zksync")["message"]
    assert err(mode="nope")["field"] == "mode"
    assert err(model_key="")["field"] == "model_key"
    assert err(model_key="has space")["field"] == "model_key"
    assert err(model_key="x" * 600)["field"] == "model_key"
    assert err(rpc_key="k")["field"] == "rpc_key"
    assert err(rpc_url="https://x.example/{key}")["field"] == "rpc_key"
    assert err(rpc_url="ftp://x.example/rpc")["field"] == "rpc_url"
    assert err(rpc_url="https://x.example/a b")["field"] == "rpc_url"
    assert client.post("/api/runs", content=b"nope").status_code == 400
    assert client.post("/api/runs", json=["list"]).status_code == 400
    assert client.post("/api/runs", content=b"x" * 20000).status_code == 413
    assert client.get("/api/runs").json()["runs"] == []   # nothing was started by invalid input


def test_hash_is_normalised_to_lowercase(client):
    rid = start_run(client, txn_hash="0x" + "AB" * 32)
    assert client.get(f"/api/runs/{rid}").json()["run"]["txn_hash"] == HASH
    wait_final(client, rid)


def test_success_flow_and_cursors(client):
    rid = start_run(client)
    data = wait_final(client, rid)
    run = data["run"]
    assert run["state"] == "completed" and [s["status"] for s in run["stages"]] == ["done"] * 6
    assert run["summary"] == {"findings": 2, "top_function": "mint", "warnings": 0, "duration": 1.2}
    messages = [e["message"] for e in data["events"]]
    assert "Pipeline started" in messages and "Report ready" in messages
    assert any("Analyzing mint (1/2)" in m for m in messages)
    assert [e["seq"] for e in data["events"]] == list(range(1, len(data["events"]) + 1))
    again = client.get(f"/api/runs/{rid}?e={data['event_cursor']}&l={data['log_cursor']}").json()
    assert again["events"] == [] and again["logs"] == []
    half = client.get(f"/api/runs/{rid}?e=2&l=3").json()
    assert half["events"][0]["seq"] == 3 and half["logs"] == data["logs"][3:]
    assert client.get(f"/api/runs/{rid}?e=-5&l=-5").json()["logs"] == data["logs"]


def test_result_shape_download_and_history(client):
    rid = start_run(client)
    wait_final(client, rid)
    res = client.get(f"/api/runs/{rid}/result").json()
    assert [f["function"] for f in res["ranking"]] == ["mint", "burn"]
    assert res["ranking"][0]["address"] == "0xc342774492b54ce5f8ac662113ed702fc1b34972"
    assert res["ranking"][0]["evidence"] == ["Signature not bound to the caller"]
    assert res["run"]["id"] == rid and res["warnings"] == []
    raw = client.get(f"/api/runs/{rid}/result?download=raw")
    assert raw.headers["content-disposition"].startswith("attachment")
    assert "ranked_suspicious_functions" in raw.json()
    hist = client.get("/api/runs").json()["runs"]
    assert hist[0]["id"] == rid and hist[0]["summary"]["top_function"] == "mint"
    cfg = client.get("/api/config").json()
    assert {"hash": HASH, "chain": "bsc"} in cfg["recent"]


def test_history_is_newest_first(client):
    ids = []
    for h in ("11", "22", "33"):
        rid = start_run(client, txn_hash="0x" + h * 32)
        wait_final(client, rid)
        ids.append(rid)
    assert [r["id"] for r in client.get("/api/runs").json()["runs"]] == ids[::-1]


def test_unknown_and_malformed_run_ids(client):
    for bad in ("0123456789abcdef", "nothex", "..%2F..%2Fetc%2Fpasswd", "A" * 16):
        assert client.get(f"/api/runs/{bad}").status_code == 404
        assert client.get(f"/api/runs/{bad}/result").status_code == 404
        assert client.post(f"/api/runs/{bad}/cancel").status_code == 404
    rid = start_run(client, txn_hash="0x" + "fa11" + "0" * 60)
    wait_final(client, rid)
    assert client.get(f"/api/runs/{rid}/result").status_code == 404   # failed run has no report


def test_capture_endpoint(client):
    cap = client.get("/api/capture").json()
    assert cap["kind"] == "capture" and cap["ranking"][0]["function"] == "mint"
    assert re.match(r"^0x[0-9a-f]{64}$", cap["transaction_hash"]) and cap["chain"] == "bsc"
    assert "No model was run" in cap["warnings"][0]


def test_environment_not_ready_blocks_runs(make_client, monkeypatch):
    c = make_client()
    import shutil
    from faultseeker.server import settings
    monkeypatch.setattr(shutil, "which", lambda name: None)
    report = settings.environment_report()
    assert report["ready"] is False and len(report["issues"]) >= 3
    r = c.post("/api/runs", json=payload())
    assert r.status_code == 503 and r.json()["error"]["code"] == "environment_not_ready"
    assert r.json()["error"]["issues"]


def test_env_file_keys_are_seen_by_the_server(make_client, tmp_path, monkeypatch):
    pytest = __import__("pytest")
    pytest.importorskip("dotenv")
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=sk-from-dotenv-" + "d" * 20 + "\n")
    c = make_client(FAULTSEEKER_ENV_FILE=env_file)
    try:
        assert c.get("/api/config").json()["models"][0]["key_required"] is False
        assert c.get("/api/config").json()["environment"]["server_model_key"] is True
    finally:
        os.environ.pop("OPENAI_API_KEY", None)
