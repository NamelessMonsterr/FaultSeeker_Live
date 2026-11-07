"""Shared fixtures. `make_client` boots the real FastAPI app against the stand-in worker."""
import importlib
import os
import shutil
import stat
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

HASH = "0x" + "ab" * 32


@pytest.fixture(autouse=True)
def _isolated_cwd(tmp_path, monkeypatch):
    """The pipeline writes ./data and ./logs relative to the working directory; keep that out of the repo."""
    monkeypatch.chdir(tmp_path)


async def _always_valid(_key):
    return True


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
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
        for k, v in env.items():
            if v is None:
                monkeypatch.delenv(k, raising=False)
            else:
                monkeypatch.setenv(k, str(v))
        from faultseeker.server import settings, security, runs
        for mod in (settings, security, runs):
            importlib.reload(mod)
        from faultseeker.server import app as app_mod
        importlib.reload(app_mod)
        monkeypatch.setattr(app_mod, "_openai_key_ok", _always_valid)
        client = TestClient(app_mod.app)
        client.__enter__()
        started.append(client)
        client.app_module = app_mod
        return client

    yield factory
    for c in started:
        c.__exit__(None, None, None)


@pytest.fixture()
def client(make_client):
    return make_client()


def payload(**kw):
    base = {"txn_hash": HASH, "chain": "bsc", "mode": "gpt-4o-mini", "model_key": "sk-test-" + "x" * 30,
            "rpc_url": "", "rpc_key": ""}
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
