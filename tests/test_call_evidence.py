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
    b = ce.bounded_text("ab " * 34, 10, 5)      # cuts fall on whitespace
    assert b["original_chars"] == 102 and b["omitted_chars"] == 102 - len(b["text"]) + len("\n[...OMITTED %d CHARS...]\n" % b["omitted_chars"])
    assert "OMITTED %d CHARS" % b["omitted_chars"] in b["text"] and b["omitted_chars"] > 0
    whole = ce.bounded_text("a" * 100, 10, 5)  # a token cut mid-way is dropped, never half shown
    assert whole["omitted_chars"] == 100 and whole["original_chars"] == 100
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


@pytest.mark.parametrize("raw,secret", [
    ('{"api_key": "my confidential credential value"}', "confidential credential"),
    ("{'password': 'hunter two three'}", "hunter two"),
    ("https://user:p4ssw0rd@host.example/v1", "p4ssw0rd"),
    ("https://h.example/x?token=abcdef123456&a=1", "abcdef123456"),
    ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
])
def test_more_credential_shapes_are_redacted(raw, secret):
    assert secret not in ce.redact(raw)


def test_credential_shaped_json_keys_are_redacted_in_features():
    key = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
    f = ce.response_features(json.dumps({key: 1, SELF: 2, "wrap": 3}))
    assert key not in json.dumps(f) and SELF in f["top_level_keys"]
    w = ce.response_features(json.dumps({"functions": {key: {}}}))
    assert key not in json.dumps(w)
    assert len(ce.label("x" * 1000)) == ce.MAX_LABEL


def test_oversized_response_is_not_parsed_and_oversized_request_scan_is_capped(monkeypatch):
    monkeypatch.setattr(ce, "MAX_PARSE_CHARS", 50)
    f = ce.response_features(json.dumps({"k" * 80: 1}))
    assert f["json_parse"] == "skipped_oversize" and "top_level_keys" not in f
    monkeypatch.setattr(ce, "MAX_FEATURE_SCAN_CHARS", 100)
    r = ce.request_features([{"role": "user", "content": "a" * 80},
                             {"role": "user", "content": "b" * 80 + " " + SELF}])
    assert r["total_chars"] == 80 + 80 + 1 + len(SELF) and r["scanned_chars"] == 100 and r["scan_truncated"]
    assert r["call_ids_in_request"] == []  # id lies beyond the scan cap: reported as truncated


def test_retry_attempt_never_inherits_previous_attempts_entry(monkeypatch):
    # attempt 1 fails retryably (captured); attempt 2's request capture raises,
    # attempt 2 gets a 200. Attempt 2's response must NOT be attached to attempt 1.
    m, session, factory, calls, _, _ = setup(
        [httpx.Response(502, text="bad gateway"), resp(json.dumps({CHILD: {}}))], retry_limit=2)
    real = session.call_evidence.record_request
    n = {"i": 0}
    def flaky(*a, **k):
        n["i"] += 1
        if n["i"] == 2:
            raise RuntimeError("capture bug")
        return real(*a, **k)
    monkeypatch.setattr(session.call_evidence, "record_request", flaky)
    session.call(factory, vuln_kwargs(), MODEL)
    (entry,) = session.evidence_snapshot()["calls"]
    assert entry["attempt"] == 1 and entry["response"] is None
    assert len(calls) == 2


def test_response_evidence_recorded_even_if_token_accounting_raises(monkeypatch):
    m, session, factory, calls, _, _ = setup([resp(json.dumps({CHILD: {}}))], codex_zero_retry=True)
    def bad_count(_c):
        raise RuntimeError("usage bug")
    monkeypatch.setattr(session, "_count_tokens", bad_count)
    with pytest.raises(Exception):
        session.call(factory, vuln_kwargs(), MODEL)
    (entry,) = session.evidence_snapshot()["calls"]
    assert entry["response"]["top_level_keys"] == [CHILD]


def test_response_recorder_failure_does_not_alter_result(monkeypatch):
    m, session, factory, calls, _, _ = setup([resp("{}")])
    monkeypatch.setattr(session.call_evidence, "record_response",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    assert session.call(factory, vuln_kwargs(), MODEL) is not None and session.attempts == 1


def test_adapted_model_recorded_separately():
    m, session, factory, calls, _, _ = setup([resp("{}")])
    session.call(factory, vuln_kwargs(), MODEL)
    (entry,) = session.evidence_snapshot()["calls"]
    assert entry["model"] == MODEL and entry["adapted_model"] == calls[-1]["model"]


def test_concurrent_snapshot_while_recording():
    import threading
    rec = ce.CallEvidence()
    errors, stop = [], threading.Event()
    def writer():
        for i in range(200):
            e = rec.record_request(i, "analysis", MODEL, i, [{"role": "user", "content": "x" * 50}])
            rec.record_response(e, "{}", "stop")
        stop.set()
    def reader():
        while not stop.is_set():
            try:
                json.dumps(rec.snapshot())
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
    ts = [threading.Thread(target=writer)] + [threading.Thread(target=reader) for _ in range(3)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert not errors and len(rec.snapshot()["calls"]) == ce.MAX_CALLS


def test_bounded_text_original_length_is_input_length_and_work_is_edge_only():
    secret = "api_key=" + "Z" * 40
    text = secret + " " + "w " * 100 + "tail"
    b = ce.bounded_text(text, 20, 10)
    assert b["original_chars"] == len(text)           # not the redacted length
    assert "Z" * 10 not in b["text"]
    assert b["omitted_chars"] == len(text) - (len(b["text"]) - len("\n[...OMITTED %d CHARS...]\n" % b["omitted_chars"]))
    # a huge input is cut without redacting the middle (middle content absent)
    big = "A" * 10_000_000
    out = ce.bounded_text(big, 100, 100)
    assert out["original_chars"] == 10_000_000 and len(out["text"]) < 400


def test_secret_straddling_the_cut_leaves_no_partial_token():
    secret = "sk-" + "Q" * 30
    text = "x " * 4 + secret + " " + "y " * 40
    for head in range(5, 40):
        b = ce.bounded_text(text, head, 4)
        assert "QQQQ" not in b["text"], (head, b["text"])


def test_roles_are_capped_before_processing():
    msgs = [{"role": "user", "content": "x"}] * 500
    assert len(ce.request_features(msgs)["roles"]) == 60 and ce.request_features(msgs)["message_count"] == 500


def test_message_processing_is_bounded_and_flagged(monkeypatch):
    monkeypatch.setattr(ce, "MAX_MESSAGES_SCAN", 3)
    msgs = [{"role": "user", "content": "m%d" % i} for i in range(10)]
    r = ce.request_features(msgs)
    assert r["message_count"] == 10 and r["messages_not_scanned"] == 7 and r["scan_truncated"]
    rec = ce.CallEvidence()
    e = rec.record_request(1, "analysis", MODEL, 1, msgs)
    assert e["last_user_message"]["text"] == "m9"  # last-user search stays within the last 3 messages


@pytest.fixture(autouse=True)
def _evidence_on(monkeypatch):
    if "disabled_by_env" not in getattr(monkeypatch, "_name", ""):
        monkeypatch.setenv("FAULTSEEKER_CALL_EVIDENCE", "1")
