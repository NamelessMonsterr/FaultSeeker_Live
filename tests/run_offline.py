"""Run local Python regressions with network blocked and disposable run storage."""
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
for name in list(os.environ):
    if any(part in name.upper() for part in ("API_KEY", "RPC_URL", "HISTORY_TOKEN", "GATE_PASSWORD")):
        os.environ.pop(name, None)
os.environ.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHON_DOTENV_DISABLED="true", GITHUB_HISTORY_TOKEN="")
# Integration remains opt-in; its fixture checks the exact Docker SHA.
original_pair = socket.socketpair
pair_scope = threading.local()

def local_pair(*args, **kwargs):
    # Windows implements socketpair using a temporary loopback connection.
    pair_scope.active = True
    try:
        return original_pair(*args, **kwargs)
    finally:
        pair_scope.active = False

socket.socketpair = local_pair

def deny_network(event, args):
    if event in ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname", "socket.sendto"):
        if not getattr(pair_scope, "active", False):
            raise RuntimeError("Offline test runner blocked network access")

sys.addaudithook(deny_network)
with tempfile.TemporaryDirectory(prefix="faultseeker-offline-tests-") as scratch:
    os.environ["FAULTSEEKER_RUNS_DIR"] = str(Path(scratch) / "runs")
    import pytest
    raise SystemExit(pytest.main(["-q", "-p", "no:cacheprovider", "--basetemp", str(Path(scratch) / "pytest"),
                                 "tests", *sys.argv[1:]]))
