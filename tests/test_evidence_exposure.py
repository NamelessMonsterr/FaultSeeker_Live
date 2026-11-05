"""Exposure routes of the private call evidence. Offline; no provider requests."""
import json
import os
import stat
from pathlib import Path

import httpx
import pytest
from test_server import server, client, TX  # noqa: F401  (fixtures)
from test_model_endpoint import setup, MODEL, OK

SELF = "0xefd86b62_0xbc452fdc8f851d7c5b72e1fe74dfb63bb793d511"


def _runtime_with_evidence(tmp_path):
    from app.pipeline_guards import PipelineRuntime
    m, session, factory, calls, _, _ = setup([httpx.Response(200, json=dict(OK, choices=[{
        "index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps({SELF: {}})}}]))])
    rt = PipelineRuntime(TX, "eth", session=session)
    rt.bound_source_texts.append("contract A { function f() public {} }")
    session.call(factory, {"model": MODEL, "messages": [
        {"role": "user", "content": "x contract A { function f() public {} } " + SELF}]}, MODEL)
    return rt


def test_evidence_is_not_in_result_json_or_status(tmp_path):
    rt = _runtime_with_evidence(tmp_path)
    result = rt.annotate_result({"transaction_hash": TX, "scored_functions": []})
    assert "call_evidence" not in json.dumps(result)
    assert "last_user_message" not in json.dumps(result)
    assert "call_evidence" not in json.dumps(rt.session.summary())


def test_private_file_is_0600_and_holds_bounded_evidence(tmp_path):
    rt = _runtime_with_evidence(tmp_path)
    path = rt.write_private_evidence(str(tmp_path), "run1")
    assert path and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    body = json.loads(Path(path).read_text())
    (entry,) = body["calls"]
    assert entry["analyzed_bucket"] == "not_recorded_at_transport"
    (src,) = entry["bound_sources"]["listed"]
    assert src["status"] == "included_exact" and src["chars"] == len("contract A { function f() public {} }")
    assert entry["response"]["top_level_keys"] == [SELF]


def test_bound_source_probe_reports_not_found_and_unknown_states(tmp_path):
    rt = _runtime_with_evidence(tmp_path)
    assert rt._probe_bound_sources("nothing here", True)["listed"][0]["status"] == "not_found"
    assert rt._probe_bound_sources("nothing here", False)["listed"][0]["status"] == "unknown_scan_truncated"


def test_export_route_is_off_by_default_and_404s(client, server, monkeypatch, tmp_path):
    monkeypatch.delenv("FAULTSEEKER_EVIDENCE_TOKEN", raising=False)
    Path(server.RUNS_DIR, "runx.evidence.json").write_text('{"calls": []}')
    assert client.get("/api/evidence/runx").status_code == 404


def test_export_route_needs_gate_even_when_enabled(server, monkeypatch):
    import asyncio
    monkeypatch.setenv("FAULTSEEKER_EVIDENCE_TOKEN", "T"*32)
    Path(server.RUNS_DIR, "runx.evidence.json").write_text('{"calls": []}')
    async def go():
        t = httpx.ASGITransport(app=server.app, raise_app_exceptions=False, client=("testclient", 1))
        async with httpx.AsyncClient(transport=t, base_url="http://test") as c:
            return await c.get("/api/evidence/runx")
    assert asyncio.run(go()).status_code == 401  # no gate cookie


def test_export_route_when_enabled_serves_no_store_and_rejects_bad_ids(client, server, monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_EVIDENCE_TOKEN", "T"*32)
    Path(server.RUNS_DIR, "runx.evidence.json").write_text('{"calls": [1]}')
    assert client.get("/api/evidence/runx").status_code == 404  # gate ok, no token
    assert client.get("/api/evidence/runx", headers={"X-Evidence-Token": "wrong"*8}).status_code == 404
    monkeypatch.setenv("FAULTSEEKER_EVIDENCE_TOKEN", "short")
    assert client.get("/api/evidence/runx", headers={"X-Evidence-Token": "short"}).status_code == 404
    monkeypatch.setenv("FAULTSEEKER_EVIDENCE_TOKEN", "T"*32)
    H = {"X-Evidence-Token": "T"*32}
    r = client.get("/api/evidence/runx", headers=H)
    assert r.status_code == 200 and r.json() == {"calls": [1]} and r.headers["cache-control"] == "no-store"
    assert client.get("/api/evidence/..%2Findex", headers=H).status_code == 404
    assert client.get("/api/evidence/missing", headers=H).status_code == 404


def test_result_route_and_history_mirror_never_include_evidence_file(client, server, monkeypatch):
    Path(server.RUNS_DIR, "runy.json").write_text(json.dumps({"transaction_hash": TX, "analysis_status": "completed"}))
    Path(server.RUNS_DIR, "runy.evidence.json").write_text('{"calls": [{"last_user_message": "RAWCONTEXT"}]}')
    server._hist_upsert({"run_id": "runy", "status": "completed"})
    assert "RAWCONTEXT" not in client.get("/api/result/runy").text
    assert "RAWCONTEXT" not in client.get("/api/runs").text
    puts = []
    monkeypatch.setattr(server, "_gh_hist_put", lambda path, content, msg: puts.append((path, content)))
    monkeypatch.setattr(server, "_history_repo_private", lambda: True)
    server._gh_hist_sync("runy", {"run_id": "runy"}, {"transaction_hash": TX})
    import time; time.sleep(0.5)
    assert puts and all("evidence" not in path and b"RAWCONTEXT" not in content for path, content in puts)


def test_worker_writes_evidence_on_success_and_failure_without_raising(server, monkeypatch, tmp_path):
    called = []
    class RT:
        def write_private_evidence(self, d, rid): called.append((d, rid))
    server._write_private_evidence(RT(), "r1")
    assert called == [(server.RUNS_DIR, "r1")]
    class Bad:
        def write_private_evidence(self, d, rid): raise RuntimeError("x")
    server._write_private_evidence(Bad(), "r2")      # never raises
    server._write_private_evidence(object(), "r3")   # runtime without the method


@pytest.fixture(autouse=True)
def _evidence_on(monkeypatch):
    if "disabled_by_env" not in getattr(monkeypatch, "_name", ""):
        monkeypatch.setenv("FAULTSEEKER_CALL_EVIDENCE", "1")


def test_route_rejects_symlink_and_oversize_evidence(client, server, monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_EVIDENCE_TOKEN", "T"*32)
    H = {"X-Evidence-Token": "T"*32}
    real = Path(server.RUNS_DIR, "real.txt"); real.write_text('{"a": 1}')
    os.symlink(real, Path(server.RUNS_DIR, "lnk.evidence.json"))
    assert client.get("/api/evidence/lnk", headers=H).status_code == 404
    Path(server.RUNS_DIR, "big.evidence.json").write_text('{"x": "' + "y" * 3_100_000 + '"}')
    assert client.get("/api/evidence/big", headers=H).status_code == 404
