"""Worker entry point: markers, result file and error reporting (pipeline mocked)."""
import json
from types import SimpleNamespace

import pytest

from faultseeker.server import worker

try:
    import faultseeker.core.pipeline  # noqa: F401
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)


def markers(text):
    return [json.loads(l.split(worker.MARKER, 1)[1]) for l in text.splitlines() if l.startswith(worker.MARKER)]


@pytest.fixture()
def fake_pipeline(monkeypatch):
    mod = SimpleNamespace()
    calls = {}

    class Pipeline:
        def __init__(self, config):
            calls["config"] = config

        def analyze_transaction(self, txn_hash=None, chain=None, **kw):
            calls["args"] = (txn_hash, chain)
            return mod.result() if callable(getattr(mod, "result", None)) else {"ok": True, "path": object()}
    from faultseeker.core import pipeline
    monkeypatch.setattr(pipeline, "FaultSeekerPipeline", Pipeline)
    return SimpleNamespace(mod=mod, calls=calls)


def run_worker(tmp_path, capsys):
    out = tmp_path / "deep" / "dir" / "result.json"
    rc = worker.main(["--hash", "0x" + "1" * 64, "--chain", "bsc", "--model", "gpt-4o", "--out", str(out)])
    return rc, out, capsys.readouterr()


def test_success_writes_the_result_atomically_and_signals_it(fake_pipeline, tmp_path, capsys):
    rc, out, cap = run_worker(tmp_path, capsys)
    assert rc == 0 and [m["event"] for m in markers(cap.out)] == ["start", "result"]
    assert json.loads(out.read_text())["ok"] is True          # non-serialisable values are stringified, not fatal
    assert not list(out.parent.glob("*.tmp"))
    assert fake_pipeline.calls["args"] == ("0x" + "1" * 64, "bsc")
    cfg = fake_pipeline.calls["config"]
    assert cfg.forensics_model == cfg.function_analysis_model == "gpt-4o"


def test_failure_emits_an_error_marker_and_a_traceback(fake_pipeline, tmp_path, capsys):
    def boom():
        raise RuntimeError("Stage 1 (Forensics) failed to produce results")
    fake_pipeline.mod.result = boom
    rc, out, cap = run_worker(tmp_path, capsys)
    assert rc == 1 and not out.exists()
    events = markers(cap.out)
    assert [m["event"] for m in events] == ["start", "error"]
    assert events[1]["type"] == "RuntimeError" and "Stage 1" in events[1]["message"]
    assert "Traceback" in cap.err and "RuntimeError" in cap.err


def test_error_messages_are_bounded(fake_pipeline, tmp_path, capsys):
    fake_pipeline.mod.result = lambda: (_ for _ in ()).throw(ValueError("x" * 5000))
    _, _, cap = run_worker(tmp_path, capsys)
    assert len(markers(cap.out)[-1]["message"]) == 500


def test_arguments_are_required(capsys):
    with pytest.raises(SystemExit):
        worker.main(["--hash", "0x1"])
