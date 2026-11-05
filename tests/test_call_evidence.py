"""Private per-call evidence. Model HTTP stubbed (MockTransport); component tests
of the recorder plus the production ModelEndpointSession.call hook point."""
import json
import httpx
import pytest
from test_model_endpoint import setup, MODEL, OK
from app import call_evidence as ce
from app import model_endpoint as me

SELF = "0xefd86b62_0xbc452fdc8f851d7c5b72e1fe74dfb63bb793d511"
CHILD = "0x095ea7b3_0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"


def resp(content):
    return httpx.Response(200, json=dict(OK, choices=[{"index": 0, "finish_reason": "stop",
                          "message": {"role": "assistant", "content": content}}]))


def vuln_kwargs(extra=""):
    return {"model": MODEL, "messages": [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": me.ENGINE_VULN_ANALYSIS_TEMPLATE + " " + SELF + " " + CHILD + extra}]}


def test_redaction_removes_credential_shapes_but_keeps_call_ids():
    text = ("Authorization: Bearer abcdefghijklmnop api_key=sk-ABCDEFGHIJKLMNOPQRSTUV "
            "eyJhbGciOiJSUzI1.eyJzdWIiOiIxMjM0NTY3.c2lnbmF0dXJl " + SELF)
    out = ce.redact(text)
    assert "abcdefghijklmnop" not in out and "ABCDEFGHIJKLMNOPQRSTUV" not in out
    assert "eyJhbGciOiJSUzI1" not in out
    assert SELF in out


def test_bounded_text_marks_omission_with_exact_counts():
    b = ce.bounded_text("a" * 100, 10, 5)
    assert b["original_chars"] == 100 and b["omitted_chars"] == 85
    assert "OMITTED 85 CHARS" in b["text"]
    assert ce.bounded_text("short", 10, 5)["omitted_chars"] == 0


def test_response_features_distinguish_self_child_wrapper_and_junk():
    f = ce.response_features(json.dumps({SELF: {"evidence": "x"}, CHILD: {"evidence": "y"}}))
    assert f["json_parse"] == "ok" and f["top_level_keys"] == [SELF, CHILD]
    w = ce.response_features(json.dumps({"vulnerable_functions": {CHILD: {}}}))
    assert w["wrapped_keys"] == [CHILD]
    j = ce.response_features("not json " + SELF)
    assert j["json_parse"] == "failed" and j["call_ids_in_text"] == [SELF]
    assert ce.response_features("```json\n{\"a\": 1}\n```")["top_level_keys"] == ["a"]


def test_request_features_report_source_presence_from_adapted_messages():
    with_src = [{"role": "user", "content": "pragma solidity ^0.8.0; contract A { function f(uint a) public {} } " + SELF}]
    without = [{"role": "user", "content": "only calldata " + SELF}]
    a, b = ce.request_features(with_src), ce.request_features(without)
    assert a["source_markers"]["pragma_solidity"] == 1 and a["source_markers"]["function_decl"] == 1
    assert b["source_markers"] == {"pragma_solidity": 0, "contract_decl": 0, "function_decl": 0}
    assert a["call_ids_in_request"] == [SELF]


def test_session_captures_adapted_request_after_augmentation_and_the_response():
    m, session, factory, calls, _, _ = setup([resp(json.dumps({CHILD: {"evidence": "mechanism undetermined"}}))],
                                             codex_zero_retry=True)
    session.call(factory, vuln_kwargs(), MODEL)
    snap = session.evidence_snapshot()
    (entry,) = snap["calls"]
    # post-transform: the contract appended by augmentation is in the capture
    assert me.ABSTENTION_SENTINEL in entry["last_user_message"]["text"] or \
        entry["last_user_message"]["omitted_chars"] > 0
    assert entry["prompt_family"] == "cloud_vuln_update"
    # same payload identity as what hit the mocked wire
    assert entry["adapted_messages_sha256_16"] == ce.sha16(calls[-1]["messages"])
    assert entry["response"]["top_level_keys"] == [CHILD]
    assert SELF not in entry["response"]["top_level_keys"]
    assert entry["response"]["finish_reason"] == "stop"
    assert entry["response"]["text"]["text"].startswith("{")


def test_evidence_is_not_in_public_summary():
    m, session, factory, calls, _, _ = setup([resp("{}")])
    session.call(factory, vuln_kwargs(), MODEL)
    assert "call_evidence" not in json.dumps(session.summary())
    assert "last_user_message" not in json.dumps(session.summary())


def test_capture_failure_never_alters_dispatch(monkeypatch):
    m, session, factory, calls, _, _ = setup([resp("{}")])
    def boom(*a, **k):
        raise RuntimeError("capture bug")
    monkeypatch.setattr(session.call_evidence, "record_request", boom)
    out = session.call(factory, vuln_kwargs(), MODEL)
    assert out is not None and len(calls) == 1 and session.attempts == 1


def test_disabled_by_env(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_CALL_EVIDENCE", "0")
    m, session, factory, calls, _, _ = setup([resp("{}")])
    session.call(factory, vuln_kwargs(), MODEL)
    assert session.evidence_snapshot() is None and len(calls) == 1


def test_call_cap_and_text_budget_leave_explicit_markers(monkeypatch):
    rec = ce.CallEvidence()
    monkeypatch.setattr(ce, "MAX_CALLS", 2)
    for i in range(4):
        rec.record_request(i, "analysis", MODEL, i, [{"role": "user", "content": "x"}])
    s = rec.snapshot()
    assert len(s["calls"]) == 2 and s["dropped_calls"] == 2
    rec2 = ce.CallEvidence()
    monkeypatch.setattr(ce, "TOTAL_TEXT_BUDGET", 10)
    e = rec2.record_request(1, "analysis", MODEL, 1, [{"role": "user", "content": "y" * 500}])
    assert e["last_user_message"]["text"] is None
    assert e["last_user_message"]["omission_reason"] == "total_text_budget_exhausted"
    assert e["last_user_message"]["omitted_chars"] == 500


def test_failed_call_keeps_request_evidence_with_no_response():
    m, session, factory, calls, _, _ = setup([httpx.Response(429, json={"error": {"message": "x"}})],
                                             codex_zero_retry=True)
    with pytest.raises(m.ModelEndpointFailure):
        session.call(factory, vuln_kwargs(), MODEL)
    (entry,) = session.evidence_snapshot()["calls"]
    assert entry["response"] is None and entry["request"]["call_ids_in_request"]


def test_runtime_snapshot_helper_is_failsafe():
    from app.pipeline_guards import PipelineRuntime
    rt = PipelineRuntime.__new__(PipelineRuntime)
    rt.session = object()                       # no recorder: result unaffected
    assert rt._call_evidence_snapshot() is None
    class Bad:
        def evidence_snapshot(self):
            raise RuntimeError("x")
    rt.session = Bad()
    assert rt._call_evidence_snapshot() is None
    m, session, factory, calls, _, _ = setup([resp("{}")])
    session.call(factory, vuln_kwargs(), MODEL)
    rt.session = session
    assert rt._call_evidence_snapshot()["calls"][0]["phase"] == "analysis"
