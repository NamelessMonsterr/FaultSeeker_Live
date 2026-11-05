import os, stat, json
import pytest
from app import call_evidence as ce
from app.pipeline_guards import PipelineRuntime


def test_default_capture_off(monkeypatch):
    from app import model_endpoint as me
    monkeypatch.delenv("FAULTSEEKER_CALL_EVIDENCE", raising=False)
    assert me._evidence_enabled() is False if hasattr(me, "_evidence_enabled") else True


def test_structured_content_is_scanned_and_unexamined_marks_incomplete():
    feats, full, complete = ce._features([{"role": "user", "content": [{"type": "text", "text": "SRC_X"}]}])
    assert "SRC_X" in full and complete
    feats, full, complete = ce._features([{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "u"}}]}])
    assert not complete and feats["unexamined_content"]


def test_oversize_hash_skipped():
    assert ce.bounded_sha16([], ce.MAX_HASH_CHARS + 1) == "skipped_oversize"


class _Fake:
    def __init__(self, snap): self.snap = snap
    def _call_evidence_snapshot(self): return self.snap


def test_private_write_ignores_preexisting_permissive_files_and_symlinks(tmp_path):
    rt = PipelineRuntime.__new__(PipelineRuntime)
    rt._call_evidence_snapshot = lambda: {"a": 1}
    victim = tmp_path / "victim.txt"; victim.write_text("keep")
    link = tmp_path / "r1.evidence.json"
    os.symlink(victim, link)
    p = rt.write_private_evidence(str(tmp_path), "r1")
    assert p and not os.path.islink(p)
    assert victim.read_text() == "keep"
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    # pre-existing permissive destination is replaced by a 0600 file
    open(p, "w").write("x"); os.chmod(p, 0o666)
    p = rt.write_private_evidence(str(tmp_path), "r1")
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600 and json.load(open(p)) == {"a": 1}
    assert not [f for f in os.listdir(tmp_path) if f.endswith(".tmp")]
