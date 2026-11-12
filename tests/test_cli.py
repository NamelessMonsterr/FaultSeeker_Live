"""The original command-line interface keeps its flags and defaults; the only change is explicit model routing.

OFFLINE: the pipeline is never reached with a usable model, so nothing contacts a network.
"""
import pytest

try:
    import faultseeker.forensics.orchestrator  # noqa: F401  (pulls in every pipeline dependency)
    from faultseeker import main as cli
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

FLAGS = ["-txn_link", "-txn_hash", "-chain", "-forensics_model", "-function_analysis_model", "-output", "-cache"]


def run_cli(monkeypatch, *argv):
    monkeypatch.setattr("sys.argv", ["faultseeker", *argv])
    cli.main_cli()


def test_help_lists_the_same_flags_as_before(monkeypatch, capsys):
    with pytest.raises(SystemExit) as exit_info:
        run_cli(monkeypatch, "-h")
    assert exit_info.value.code == 0
    out = " ".join(capsys.readouterr().out.split())        # argparse wraps lines
    for flag in FLAGS:
        assert flag in out
    assert "default: gpt-4o-mini" in out and "Chain identifier" in out


def test_no_transaction_given_is_still_a_usage_error(monkeypatch, capsys):
    with pytest.raises(SystemExit) as exit_info:
        run_cli(monkeypatch)
    assert exit_info.value.code == 2 and "Either -txn_link" in capsys.readouterr().err


def test_default_models_resolve_through_the_registry():
    from faultseeker.providers import load_registry
    reg = load_registry()
    for model in ("gpt-4o-mini",):
        assert reg.resolve(model, {}).provider.id == "openai"


def test_an_unregistered_model_name_is_a_clear_error_not_a_silent_ollama_call(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("FAULTSEEKER_ISOLATED_RUN", "1")
    with pytest.raises(SystemExit) as exit_info:
        run_cli(monkeypatch, "-txn_hash", "0x" + "ab" * 32, "-chain", "eth", "-forensics_model", "llama3",
                "-cache", str(tmp_path / "c"), "-output", str(tmp_path / "o"))
    assert exit_info.value.code == 1
    out = capsys.readouterr().out
    assert "not in the provider registry" in out and "ollama:<name>" in out
