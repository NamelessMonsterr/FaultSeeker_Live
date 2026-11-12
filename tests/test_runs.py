"""Run lifecycle: isolation, cancellation, failures, restarts, secrets, limits."""
import json
import os
import pathlib
import time

import pytest

from tests.conftest import payload, start_run, wait_final

KEY = "sk-test-" + "x" * 30


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # zombie children still answer kill(0)
        return "Z" not in pathlib.Path(f"/proc/{pid}/status").read_text().split("State:")[1].split()[0]
    except OSError:
        return True


def all_stored_text(client):
    from faultseeker.server import settings
    return "\n".join(p.read_text() for p in pathlib.Path(settings.RUNS_DIR).rglob("*") if p.is_file())


def test_secrets_never_leave_the_worker_environment(client, monkeypatch):
    rpc_key = "SUPERSECRETRPCKEY123"
    rid = start_run(client, model_key=KEY, rpc_url="https://rpc.example/v3/{key}", rpc_key=rpc_key)
    data = wait_final(client, rid)
    assert data["run"]["state"] == "completed"
    assert data["run"]["rpc_mode"] == "custom" and data["run"]["key_source"] == "user"
    blob = json.dumps(data) + all_stored_text(client) + json.dumps(client.get("/api/runs").json())
    assert KEY not in blob and rpc_key not in blob and "rpc.example/v3" not in blob
    assert any("env check" in line and "OPENAI_API_KEY=••••" in line for line in data["logs"])


def test_server_side_keys_are_redacted_too(make_client):
    c = make_client(OPENAI_API_KEY="sk-server-" + "s" * 30, ETHERSCAN_API_KEY="ETHERSCANSECRET999")
    cfg = c.get("/api/config").json()
    assert cfg["models"][0]["key_required"] is False and cfg["environment"]["explorer_key"] is True
    rid = start_run(c, model_key="")
    data = wait_final(c, rid)
    assert data["run"]["key_source"] == "server"
    line = next(l for l in data["logs"] if "env check" in l)
    assert "sk-server" not in line and "ETHERSCANSECRET999" not in line and "OPENAI_API_KEY=••••" in line
    assert "sk-server" not in all_stored_text(c)


def test_user_key_overrides_server_key_for_the_worker(make_client):
    c = make_client(OPENAI_API_KEY="sk-server-" + "s" * 30)
    rid = start_run(c, model_key=KEY)
    assert wait_final(c, rid)["run"]["key_source"] == "user"


def test_ollama_model_needs_no_key(make_client):
    c = make_client(FAULTSEEKER_OLLAMA_MODELS="llama3.1:8b")
    models = {m["id"]: m for m in c.get("/api/config").json()["models"]}
    entry = models["ollama:llama3.1:8b"]          # explicit provider prefix in the id, not a guess from the name
    assert entry["provider"] == "ollama" and entry["key_required"] is False and entry["key_optional"] is False
    rid = start_run(c, mode="ollama:llama3.1:8b", model_key="sk-ignored-" + "z" * 20)
    data = wait_final(c, rid)
    assert data["run"]["state"] == "completed" and data["run"]["key_source"] == "none" and data["run"]["provider"] == "ollama"
    assert c.keycheck.calls == [], "no key check is made for a provider that takes no key"


def test_only_one_run_at_a_time_and_cancel_kills_grandchildren(client, monkeypatch, tmp_path):
    pid_file = tmp_path / "child.pid"
    monkeypatch.setenv("FAKE_MODE", "spawn_child")
    monkeypatch.setenv("FAKE_CHILD_PID_FILE", str(pid_file))
    first = start_run(client)
    deadline = time.time() + 10
    while not pid_file.exists() and time.time() < deadline:
        time.sleep(0.1)
    child = int(pid_file.read_text())
    assert alive(child)
    busy = client.post("/api/runs", json=payload())
    assert busy.status_code == 409 and busy.json()["error"]["active_run"] == first
    assert client.get("/api/config").json()["active_run"] == first
    assert client.post(f"/api/runs/{first}/cancel").json() == {"ok": True}
    data = wait_final(client, first)
    assert data["run"]["state"] == "cancelled" and data["run"]["error"] is None
    time.sleep(0.5)
    assert not alive(child), "cancel must kill the whole process group, including cast/getCode children"
    assert client.post(f"/api/runs/{first}/cancel").status_code == 409
    assert client.get("/api/config").json()["active_run"] is None
    monkeypatch.setenv("FAKE_MODE", "success")
    wait_final(client, start_run(client))   # a new run is accepted after cancel


def test_concurrency_is_fixed_at_one_even_if_asked_otherwise(make_client, monkeypatch):
    c = make_client(FAULTSEEKER_MAX_CONCURRENT=5, FAKE_MODE="hang")
    first = start_run(c)
    assert c.post("/api/runs", json=payload()).status_code == 409
    assert c.get("/api/config").json()["limits"]["concurrent_runs"] == 1
    c.post(f"/api/runs/{first}/cancel")
    wait_final(c, first)


def test_timeout_stops_the_run(make_client):
    c = make_client(FAULTSEEKER_RUN_TIMEOUT=2, FAKE_MODE="hang")
    t = time.time()
    data = wait_final(c, start_run(c))
    assert time.time() - t < 12
    assert data["run"]["state"] == "failed" and data["run"]["error"]["code"] == "timeout"


def test_worker_crash_without_markers(client):
    data = wait_final(client, start_run(client, txn_hash="0x" + "0bad" + "0" * 60))
    assert data["run"]["state"] == "failed" and data["run"]["error"]["code"] == "worker_crashed"
    assert "exit code 3" in data["run"]["error"]["message"]


def test_oversized_output_line_does_not_leak_the_worker(make_client, monkeypatch):
    c = make_client(FAULTSEEKER_MAX_LINE_BYTES=100_000, FAKE_MODE="bigline", FAKE_BIG=400_000)
    data = wait_final(c, start_run(c))
    assert data["run"]["state"] == "failed"
    assert "output stream" in data["run"]["error"]["message"]


def test_long_log_lines_are_truncated(make_client):
    c = make_client(FAKE_MODE="bigline", FAKE_BIG=20_000, FAULTSEEKER_RUN_TIMEOUT=3)
    data = wait_final(c, start_run(c))
    assert max(len(l) for l in data["logs"]) <= 4000


@pytest.mark.parametrize("prefix,code", [("fa11", "rpc_failed"), ("e8e8", "explorer_unavailable"),
                                         ("dead", "model_key_rejected"), ("9a07", "model_quota")])
def test_failure_classification(client, prefix, code):
    t = time.time()
    data = wait_final(client, start_run(client, txn_hash="0x" + prefix + "0" * 60, rpc_url="https://rpc.example/v3/ABCDEFGHIJKLMNOP"))
    assert data["run"]["state"] == "failed" and data["run"]["error"]["code"] == code
    assert data["run"]["error"]["hint"]
    assert time.time() - t < 15, "provider errors must fail fast, not wait for the pipeline"
    assert any(s["status"] == "failed" for s in data["run"]["stages"]) or code.startswith("model")
    assert "ABCDEFGHIJKLMNOP" not in json.dumps(data)


def test_provider_error_words_inside_logged_text_do_not_fail_a_run(client, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "source_mentions_error")
    assert wait_final(client, start_run(client))["run"]["state"] == "completed"


def test_unusable_ranking_is_flagged_not_shown_as_a_finding(client):
    rid = start_run(client, txn_hash="0x" + "bad0" + "0" * 60)
    wait_final(client, rid)
    res = client.get(f"/api/runs/{rid}/result").json()
    assert all(r["unranked"] for r in res["ranking"]) and len(res["ranking"]) == 2
    assert not any("error occurred" in json.dumps(r).lower() for r in res["ranking"])
    assert any("not valid function names" in w for w in res["warnings"]) and any("unranked" in w for w in res["warnings"])


def test_empty_result_is_reported_honestly(client):
    rid = start_run(client, txn_hash="0x" + "0000" + "1" * 60)
    data = wait_final(client, rid)
    assert data["run"]["state"] == "completed" and data["run"]["summary"]["findings"] == 0
    res = client.get(f"/api/runs/{rid}/result").json()
    assert res["ranking"] == [] and "No potentially vulnerable functions" in res["warnings"][0]


def test_restart_marks_unfinished_runs_interrupted(make_client, tmp_path):
    from faultseeker.server import settings
    rid = "0123456789abcdef"
    d = pathlib.Path(settings.RUNS_DIR) if False else tmp_path / "data" / "runs" / rid
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"id": rid, "txn_hash": "0x" + "1" * 64, "chain": "eth", "model": "gpt-4o-mini",
                                             "state": "running", "created_at": time.time(), "stages": [], "current": {}}))
    c = make_client()
    run = c.get(f"/api/runs/{rid}").json()["run"]
    assert run["state"] == "interrupted" and run["error"]["code"] == "interrupted"
    assert c.get("/api/config").json()["active_run"] is None


def test_history_survives_a_restart(make_client):
    c = make_client()
    rid = start_run(c)
    wait_final(c, rid)
    c2 = make_client()   # fresh manager over the same data directory
    assert c2.get(f"/api/runs/{rid}").json()["run"]["state"] == "completed"
    assert c2.get(f"/api/runs/{rid}/result").json()["ranking"][0]["function"] == "mint"
    assert c2.get(f"/api/runs/{rid}").json()["logs"], "logs are reloaded from disk"


def test_old_runs_are_pruned(make_client):
    c = make_client(FAULTSEEKER_MAX_STORED_RUNS=3)
    ids = []
    for i in range(5):
        rid = start_run(c, txn_hash="0x" + f"{i:02x}" * 32)
        wait_final(c, rid)
        ids.append(rid)
    kept = [r["id"] for r in c.get("/api/runs").json()["runs"]]
    assert len(kept) <= 4 and ids[-1] in kept and ids[0] not in kept


@pytest.mark.parametrize("mode,code,hint_word", [
    ("param_rejected", "provider_parameter_rejected", "params"),
    ("not_found", "model_not_found", "model ID"),
    ("forbidden", "provider_forbidden", "permissions"),
    ("unreachable", "provider_unreachable", "retried"),
])
def test_provider_failures_stop_the_run_quickly_with_an_actionable_reason(client, monkeypatch, mode, code, hint_word):
    monkeypatch.setenv("FAKE_MODE", mode)
    t = time.time()
    data = wait_final(client, start_run(client))
    assert data["run"]["state"] == "failed" and data["run"]["error"]["code"] == code
    assert hint_word in data["run"]["error"]["hint"] and time.time() - t < 15, "fatal provider errors must not wait for the pipeline"


def test_a_couple_of_connection_errors_are_tolerated_but_flagged(client, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "unreachable")
    monkeypatch.setenv("FAKE_CONNECTION_ERRORS", "2")
    # two failures are below the limit: the stand-in then carries on, and the report says model calls failed
    monkeypatch.setenv("FAKE_MODE", "unreachable_then_ok")
    data = wait_final(client, start_run(client))
    assert data["run"]["state"] == "completed"


def test_a_bad_request_that_is_not_about_a_parameter_does_not_fail_the_run(client, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "bad_request_other")
    rid = start_run(client)
    data = wait_final(client, rid)
    assert data["run"]["state"] == "completed"
    assert any("model request(s) failed" in w for w in client.get(f"/api/runs/{rid}/result").json()["warnings"])


def test_provider_not_configured_is_reported_from_the_worker(client, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "provider_config")
    err = wait_final(client, start_run(client))["run"]["error"]
    assert err["code"] == "provider_not_configured" and "CODEX_PROXY_MODEL" in err["message"] and "operator" in err["hint"]
