"""Per-run secret isolation, end to end through the run manager.

OFFLINE / MOCKED: uses the stand-in worker (tests/fake_worker.py), which reports a SHA-256 of every sensitive variable it
received. No real pipeline, provider or key is involved.
"""
import hashlib
import json
import pathlib

import pytest

from tests.conftest import start_run, wait_final

ENV = {"CODEX_PROXY_BASE_URL": "https://codex.private.example.invalid/v1", "CODEX_PROXY_MODEL": "codex-exact",
       "MERCURY_BASE_URL": "https://mercury.private.example.invalid/v1", "MERCURY_MODEL": "mercury-exact"}
SERVER = {"OPENAI_API_KEY": "sk-server-openai-" + "1" * 24, "CODEX_PROXY_API_KEY": "server-codex-" + "2" * 24,
          "MERCURY_API_KEY": "server-mercury-" + "3" * 24, "ETHERSCAN_API_KEY": "ETHERSCAN" + "4" * 20}
ACCESS = "correct horse battery staple"
USER = "user-supplied-key-" + "u" * 24
RPC = "https://rpc.example.invalid/v3/RPCSECRET" + "5" * 16


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture()
def secured(make_client):
    c = make_client(**ENV, **SERVER, FAULTSEEKER_ACCESS_CODE=ACCESS)
    assert c.post("/auth/login", json={"code": ACCESS}).status_code == 200
    return c


def worker_env(client, rid):
    from faultseeker.server import settings
    return json.loads((pathlib.Path(settings.RUNS_DIR) / rid / "env.json").read_text())


def every_stored_and_served_text(client, rid):
    from faultseeker.server import settings
    stored = "\n".join(p.read_text() for p in pathlib.Path(settings.RUNS_DIR).rglob("*") if p.is_file())
    served = "".join(client.get(path).text for path in (
        "/api/config", "/api/runs", f"/api/runs/{rid}", f"/api/runs/{rid}/result", f"/api/runs/{rid}/result?download=raw", "/api/capture"))
    return stored + served


@pytest.mark.parametrize("model,own_env", [("codex-proxy", "CODEX_PROXY_API_KEY"), ("mercury", "MERCURY_API_KEY"), ("gpt-4o", "OPENAI_API_KEY")])
def test_the_worker_receives_only_the_selected_providers_key(secured, model, own_env):
    rid = start_run(secured, mode=model, model_key=USER, rpc_url=RPC.replace("RPCSECRET5555555555555555", "{key}"), rpc_key="RPCSECRET" + "5" * 16)
    wait_final(secured, rid)
    env = worker_env(secured, rid)
    assert env[own_env] == sha(USER), "the user's key replaces the server's for the selected provider"
    for other in ("CODEX_PROXY_API_KEY", "MERCURY_API_KEY", "OPENAI_API_KEY"):
        if other != own_env:
            assert env[other] is None, f"{other} leaked into a {model} run"
    assert env["FAULTSEEKER_ACCESS_CODE"] is None and env["FAULTSEEKER_SESSION_SECRET"] is None
    assert env["FAULTSEEKER_ISOLATED_RUN"] == sha("1"), "workers must not reload .env and bring other keys back"
    assert env["ETHERSCAN_API_KEY"] == sha(SERVER["ETHERSCAN_API_KEY"]), "getCode still needs the explorer key"


def test_without_a_user_key_the_server_key_for_that_provider_only(secured):
    rid = start_run(secured, mode="mercury", model_key="")
    wait_final(secured, rid)
    env = worker_env(secured, rid)
    assert env["MERCURY_API_KEY"] == sha(SERVER["MERCURY_API_KEY"])
    assert env["OPENAI_API_KEY"] is None and env["CODEX_PROXY_API_KEY"] is None


def test_no_secret_appears_in_logs_errors_metadata_or_any_response(secured):
    secrets = [USER, RPC, "RPCSECRET" + "5" * 16, ACCESS, *SERVER.values(),
               "codex.private.example.invalid", "mercury.private.example.invalid"]
    rid = start_run(secured, mode="codex-proxy", model_key=USER, rpc_url=RPC)
    data = wait_final(secured, rid)
    assert data["run"]["state"] == "completed"
    blob = every_stored_and_served_text(secured, rid)
    for secret in secrets:
        assert secret not in blob, f"secret leaked: {secret[:12]}…"
    line = next(l for l in data["logs"] if l.startswith("env check"))
    assert line.count("••••") >= 3, "the worker echoed its keys; every one was masked before storage"


def test_failure_messages_do_not_carry_secrets_either(secured):
    rid = start_run(secured, mode="mercury", model_key=USER, txn_hash="0x" + "fa11" + "0" * 60, rpc_url=RPC)
    data = wait_final(secured, rid)
    assert data["run"]["state"] == "failed"
    blob = every_stored_and_served_text(secured, rid)
    for secret in (USER, RPC, "RPCSECRET" + "5" * 16, *SERVER.values()):
        assert secret not in blob
