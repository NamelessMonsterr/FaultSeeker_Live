"""Contract between the console server (console/app/server.py) and this pipeline."""
import inspect

from faultseeker.main import main as pipeline_main
from faultseeker.utils import rpc_provider


def test_main_accepts_every_keyword_the_console_passes():
    accepted = set(inspect.signature(pipeline_main).parameters)
    # no-LLM call and full-pipeline call made by console/app/server.py worker()
    for name in ("txn_hash", "chain", "no_llm", "output_path",
                 "forensics_model", "function_analysis_model", "track_cost"):
        assert name in accepted, name


def test_configured_rpc_url_is_registered_first(monkeypatch):
    for suffix in ("", "_2", "_3", "_4"):
        monkeypatch.delenv("ETH_RPC_URL" + suffix, raising=False)
    monkeypatch.delenv("TENDERLY_RPC_URL", raising=False)
    monkeypatch.setenv("ETH_RPC_URL", "https://rpc.example.invalid/key")
    providers = rpc_provider._build_providers("eth")
    assert providers[0].url == "https://rpc.example.invalid/key"
    assert len(providers) > 1  # public nodes remain as lower-priority backups
