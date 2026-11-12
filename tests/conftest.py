"""Shared fixtures. `make_client` boots the real FastAPI app against the stand-in worker.

OFFLINE: nothing here contacts a real provider, explorer or RPC. Provider key checks go to an in-process mock transport
(or to tests/fake_provider.py on localhost), and runs use tests/fake_worker.py instead of the real pipeline.
"""
import importlib
import os
import shutil
import stat
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

HASH = "0x" + "ab" * 32
USER_KEY = "sk-test-" + "x" * 30
# Everything a test run might inherit from the developer's own shell; cleared so results do not depend on it.
CLEARED_ENV = ["OPENAI_API_KEY", "CODEX_PROXY_API_KEY", "CODEX_PROXY_BASE_URL", "CODEX_PROXY_MODEL", "CODEX_PROXY_TEMPERATURE",
               "MERCURY_API_KEY", "MERCURY_BASE_URL", "MERCURY_MODEL", "MERCURY_TEMPERATURE", "ETHERSCAN_API_KEY",
               "FAULTSEEKER_ACCESS_CODE", "FAULTSEEKER_ENABLED_MODELS", "FAULTSEEKER_OLLAMA_MODELS", "FAULTSEEKER_PUBLIC",
               "FAULTSEEKER_ALLOW_UNSAFE_PUBLIC", "FAULTSEEKER_MODELS_FILE", "FAULTSEEKER_DEFAULT_MODEL", "RENDER",
               "FAULTSEEKER_ENV_FILE", "FAULTSEEKER_RPC_URL", "FAULTSEEKER_ISOLATED_RUN", "OLLAMA_HOST", "FAULTSEEKER_SELECTOR_TABLE"]


@pytest.fixture(autouse=True)
def _isolated_cwd(tmp_path, monkeypatch):
    """The pipeline writes ./data and ./logs relative to the working directory; keep that out of the repo."""
    monkeypatch.chdir(tmp_path)


@pytest.fixture()
def shims(tmp_path):
    """Fake `cast` and `getCode` so the environment report says ready on any machine."""
    bin_dir = tmp_path / "shims"
    bin_dir.mkdir()
    for name in ("cast", "getCode"):
        if not shutil.which(name):
            f = bin_dir / name
            f.write_text("#!/bin/sh\nexit 0\n")
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
    return str(bin_dir)


class KeyCheckRecorder:
    """In-process mock transport for key validation. Records (url, bearer) of every check; answers 200 by default."""

    def __init__(self):
        self.calls = []
        self.handler = lambda request: httpx.Response(200, json={"data": []})

    def __call__(self, request):
        self.calls.append({"url": str(request.url), "host": request.url.host, "key": request.headers.get("authorization", "").removeprefix("Bearer ")})
        return self.handler(request)


@pytest.fixture()
def make_client(tmp_path, monkeypatch, shims):
    """make_client(**env) -> started TestClient. Env values are applied before the server modules load."""
    from fastapi.testclient import TestClient
    started = []

    def factory(**env):
        monkeypatch.setenv("PATH", shims + os.pathsep + os.environ["PATH"])
        monkeypatch.setenv("FAULTSEEKER_DATA_DIR", str(tmp_path / "data"))
        monkeypatch.setenv("FAULTSEEKER_WORKER_MODULE", "tests.fake_worker")
        monkeypatch.setenv("FAULTSEEKER_ALLOW_PRIVATE_RPC", "1")
        for name in CLEARED_ENV:
            monkeypatch.delenv(name, raising=False)
        for k, v in env.items():
            if v is None:
                monkeypatch.delenv(k, raising=False)
            else:
                monkeypatch.setenv(k, str(v))
        from faultseeker.server import settings, security, auth, keycheck, runs
        for mod in (settings, security, auth, keycheck, runs):
            importlib.reload(mod)
        from faultseeker.server import app as app_mod
        importlib.reload(app_mod)
        recorder = KeyCheckRecorder()
        app_mod.KEYCHECK_TRANSPORT = httpx.MockTransport(recorder)
        client = TestClient(app_mod.app)
        client.__enter__()            # raises RuntimeError when the server refuses to start
        started.append(client)
        client.app_module = app_mod
        client.keycheck = recorder
        return client

    yield factory
    for c in started:
        c.__exit__(None, None, None)


@pytest.fixture()
def client(make_client):
    return make_client()


def payload(**kw):
    base = {"txn_hash": HASH, "chain": "bsc", "mode": "gpt-4o-mini", "model_key": USER_KEY, "rpc_url": "", "rpc_key": ""}
    base.update(kw)
    return base


def wait_final(client, run_id, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = client.get(f"/api/runs/{run_id}").json()
        if data["run"]["state"] != "running":
            return data
        time.sleep(0.1)
    raise AssertionError(f"run {run_id} did not finish within {timeout}s")


def start_run(client, **kw):
    r = client.post("/api/runs", json=payload(**kw))
    assert r.status_code == 201, r.text
    return r.json()["id"]
