import os, stat, json
import pytest
from app import call_evidence as ce
from app.pipeline_guards import PipelineRuntime


def test_default_capture_off(monkeypatch):
    from app import model_endpoint as me
    monkeypatch.delenv("FAULTSEEKER_CALL_EVIDENCE", raising=False)
    assert me._evidence_enabled() is False
    for v in ("", "maybe", "0"):
        monkeypatch.setenv("FAULTSEEKER_CALL_EVIDENCE", v)
        assert me._evidence_enabled() is False
    monkeypatch.setenv("FAULTSEEKER_CALL_EVIDENCE", "1")
    assert me._evidence_enabled() is True


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


def test_hash_bound_covers_non_text_fields():
    big = [{"role": "user", "content": "x", "tool_calls": ["y" * 2_000_000]}]
    assert ce.sha16(big) == "skipped_oversize"
    assert ce.sha16([{"role": "user", "content": "x"}]) not in ("skipped_oversize", "unserializable")


def test_unexamined_content_never_yields_not_found():
    rt = PipelineRuntime.__new__(PipelineRuntime)
    rt.bound_source_texts = ["SECRET_SRC_BODY"]
    feats, full, complete = ce._features([{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "u"}}]}])
    out = rt._probe_bound_sources(full, complete)
    assert out["listed"][0]["status"] == "unknown_scan_truncated"
    out = rt._probe_bound_sources("has SECRET_SRC_BODY here", True)
    assert out["listed"][0]["status"] == "included_exact"
    rt.bound_source_texts = ["z" * 300_000]
    assert rt._probe_bound_sources("a", True)["listed"][0]["status"] == "unknown_source_too_large"


def test_replace_failure_cleans_tmp_and_fchmod_failure_closes_fd(tmp_path, monkeypatch):
    rt = PipelineRuntime.__new__(PipelineRuntime)
    rt._call_evidence_snapshot = lambda: {"a": 1}
    def boom(*a, **k): raise OSError("x")
    monkeypatch.setattr(os, "replace", boom)
    assert rt.write_private_evidence(str(tmp_path), "r2") is None
    assert not os.listdir(tmp_path)
    monkeypatch.undo()
    closed = []
    real_close = os.close
    monkeypatch.setattr(os, "fchmod", boom)
    monkeypatch.setattr(os, "close", lambda fd: (closed.append(fd), real_close(fd)))
    assert rt.write_private_evidence(str(tmp_path), "r3") is None
    assert closed and not os.listdir(tmp_path)


def test_hash_precheck_bounds_wide_and_deep_and_big_scalars():
    assert ce.sha16({"k%d" % i: i for i in range(6000)}) == "skipped_oversize"
    deep = cur = []
    for _ in range(50):
        n = []; cur.append(n); cur = n
    assert ce.sha16(deep) == "skipped_oversize"
    assert ce.sha16(["z" * 5_000_000]) == "skipped_oversize"
    assert ce.sha16({"a": 1}) not in ("skipped_oversize", "unserializable")


def test_structured_blocks_consumed_within_scan_budget():
    big = "q" * (ce.MAX_FEATURE_SCAN_CHARS)
    feats, full, complete = ce._features([{"role": "user", "content": [{"type": "text", "text": big}] * 200}])
    assert len(full) <= ce.MAX_FEATURE_SCAN_CHARS + 200 and not complete


@pytest.mark.parametrize("raw", ["token=abcdefghijklmnop", "passwd=abcdefghijklmnop", "id_token=abcdefghijklmnop",
                                 "token: abcdefghijklmnop", 'passwd="abcdefghijklmnop"', "id_token: 'abcdefghijklmnop'"])
def test_unquoted_and_quoted_credential_fields_redacted(raw):
    assert "abcdefghijklmnop" not in ce.redact(raw)


def test_hash_precheck_counts_json_escape_expansion():
    assert ce.sha16(["\x00" * 500_000]) == "skipped_oversize"
    assert ce.sha16(["abc"]) not in ("skipped_oversize", "unserializable")
