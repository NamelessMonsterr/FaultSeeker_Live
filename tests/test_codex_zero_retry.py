"""Codex proxy route: no retry/rotation per dispatched model, whatever the env says.
Model HTTP is stubbed (MockTransport); no network. Component tests."""
import httpx
import pytest
from test_model_endpoint import setup, MODEL, OK
from app import model_endpoint as me

def setup_z(responses, **options):
    return setup(responses, codex_zero_retry=True, **options)
OTHER = "other-model-1"
OTHER_OK = dict(OK, model=OTHER)


def test_model_constant_is_codex_and_matching():
    assert MODEL.startswith("gpt-6.1-sol-") and me.is_codex_model(MODEL)
    assert me.is_codex_model("gpt-6.1-sol-high") and not me.is_codex_model(OTHER)
    assert not me.is_codex_model(None) and not me.is_codex_model("gpt-4o-mini")


BAD = [httpx.Response(429, json={"error": {"message": "x"}}),
       httpx.Response(502, text="bad gateway"),
       httpx.Response(500, json={"error": {"message": "x"}}),
       httpx.Response(401, json={"error": {"message": "x"}}),
       httpx.ReadTimeout("t"), httpx.ConnectError("c")]


@pytest.mark.parametrize("bad", BAD)
def test_codex_analysis_failure_single_attempt_even_with_large_allowance(monkeypatch, bad):
    monkeypatch.setenv("FAULTSEEKER_MODEL_RETRY_LIMIT", "5")
    m, session, factory, calls, events, _ = setup_z([httpx.Response(200, json=OK)] + [bad] * 6, retry_limit=5)
    session.register_keys("https://model.invalid/v1", ["key-one", "key-two"])
    session.preflight(factory, MODEL, timeout=20)
    with pytest.raises(m.ModelEndpointFailure):
        session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    assert len(calls) == 2  # preflight + exactly one analysis attempt
    assert not any(e.get("key_rotation") for e in events)
    assert session.retries_left == 5  # allowance untouched
    pool = next(iter(session.key_pools.values()))
    assert pool["rejected"] == set() and pool["active"] == "key-one"


@pytest.mark.parametrize("bad", [httpx.ReadTimeout("t"), httpx.ConnectError("c"),
                                 httpx.Response(502, text="bad gateway"),
                                 httpx.Response(429, json={"error": {"message": "x"}})])
def test_codex_preflight_single_attempt_even_with_coldstart_optin(monkeypatch, bad):
    monkeypatch.setenv("FAULTSEEKER_PREFLIGHT_COLD_START_RETRIES", "1")
    m, session, factory, calls, _, _ = setup_z([bad] * 6, retry_limit=5)
    with pytest.raises(m.ModelEndpointFailure):
        session.preflight(factory, MODEL, timeout=20)
    assert len(calls) == 1


def test_non_codex_preflight_optin_unchanged(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_PREFLIGHT_COLD_START_RETRIES", "1")
    m, session, factory, calls, _, _ = setup_z([httpx.Response(502, text="x"), httpx.Response(200, json=OTHER_OK)], retry_limit=2)
    session.preflight(factory, OTHER, timeout=20)
    assert len(calls) == 2


def test_non_codex_analysis_retry_and_rotation_unchanged():
    m, session, factory, calls, events, _ = setup_z(
        [httpx.Response(200, json=OTHER_OK), httpx.Response(502, text="x"), httpx.Response(200, json=OTHER_OK)], retry_limit=2)
    session.preflight(factory, OTHER, timeout=20)
    session.call(factory, {"model": OTHER, "messages": []}, OTHER)
    assert len(calls) == 3 and session.retries_left == 1


def test_mixed_session_codex_zero_other_keeps_allowance():
    m, session, factory, calls, events, _ = setup_z(
        [httpx.Response(502, text="x"), httpx.Response(200, json=OTHER_OK),
         httpx.Response(502, text="x")], retry_limit=2)
    # other model: one retry succeeds and consumes shared allowance
    session.call(factory, {"model": OTHER, "messages": []}, OTHER)
    assert len(calls) == 2 and session.retries_left == 1
    # codex model in the same session: first failure is terminal, allowance untouched
    with pytest.raises(m.ModelEndpointFailure):
        session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    assert len(calls) == 3 and session.retries_left == 1


def test_server_callsite_unchanged_models_still_passed(monkeypatch):
    # make_runtime wiring is unchanged by this policy (enforced per dispatched model).
    from app import server
    import app.pipeline_guards as g
    import queue
    seen = []
    monkeypatch.setattr(g, "make_runtime", lambda *a, **kw: seen.append(kw["models"]))
    server._prepare_pipeline({"txn_hash": "0x1", "chain": "eth", "mode": MODEL}, MODEL, queue.Queue())
    assert seen == [(MODEL, None)]


def test_make_runtime_turns_the_switch_on(monkeypatch):
    import app.pipeline_guards as g
    seen = {}
    class S:
        def __init__(self, **kw): seen.update(kw)
    class R:
        def __init__(self, *a, **kw): pass
        def install(self): return self
        def close(self): pass
    monkeypatch.setattr(g, "ModelEndpointSession", S)
    monkeypatch.setattr(g, "PipelineRuntime", R)
    g.make_runtime("0x1", "eth", True, lambda e: None, models=(MODEL, None))
    assert seen["codex_zero_retry"] is True


def test_switch_off_leaves_generic_machinery_untouched():
    m, session, factory, calls, _, _ = setup([httpx.Response(502, text="x"), httpx.Response(200, json=OK)], retry_limit=2)
    session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    assert len(calls) == 2


def test_codex_blank_completion_never_uses_mercury_reask(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_MERCURY_BLANK_REASK", "1")
    blank = httpx.Response(200, json={"id": "m", "object": "chat.completion", "created": 0, "model": MODEL,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}]})
    m, session, factory, calls, _, _ = setup_z([blank, httpx.Response(200, json=OK)], retry_limit=5)
    with pytest.raises(m.ModelEndpointFailure):
        session.call(factory, {"model": MODEL, "messages": []}, MODEL)
    assert len(calls) == 1 and session.blank_answer_retries == 0


def test_codex_preflight_401_multi_key_no_rotation():
    m, session, factory, calls, events, _ = setup_z([httpx.Response(401, json={"error": {"message": "x"}})] * 3, retry_limit=5)
    session.register_keys("https://model.invalid/v1", ["key-one", "key-two"])
    with pytest.raises(m.ModelEndpointFailure):
        session.preflight(factory, MODEL, timeout=20)
    assert len(calls) == 1
    pool = next(iter(session.key_pools.values()))
    assert pool["rejected"] == set() and pool["active"] == "key-one"


def test_adapted_model_codex_restricts_even_if_requested_name_is_not(monkeypatch):
    monkeypatch.setattr(me, "adapt_request", lambda model, kwargs: dict(kwargs, model=MODEL))
    m, session, factory, calls, events, _ = setup_z(
        [httpx.Response(502, text="x"), httpx.Response(200, json=OK)], retry_limit=5)
    with pytest.raises(m.ModelEndpointFailure):
        session.call(factory, {"model": OTHER, "messages": []}, OTHER)
    assert len(calls) == 1 and session.retries_left == 5


def test_pending_mercury_reask_cannot_reach_codex_dispatch(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_MERCURY_BLANK_REASK", "1")
    blank = httpx.Response(200, json={"id": "m", "object": "chat.completion", "created": 0, "model": "mercury-3",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}]})
    state = {"n": 0}
    def adapt(model, kwargs):
        state["n"] += 1
        return dict(kwargs, model="mercury-3" if state["n"] == 1 else MODEL)
    monkeypatch.setattr(me, "adapt_request", adapt)
    m, session, factory, calls, _, _ = setup_z([blank, httpx.Response(200, json=OK)], retry_limit=5)
    with pytest.raises(m.ModelEndpointFailure):
        session.call(factory, {"model": "mercury-3", "messages": []}, "mercury-3")
    assert len(calls) == 1 and session.blank_answer_retries == 0


def test_only_make_runtime_constructs_session_in_production():
    import pathlib, re
    repo = pathlib.Path(me.__file__).resolve().parent.parent
    hits = []
    for p in repo.rglob("*.py"):
        rel = p.relative_to(repo).parts
        if rel[0] in ("tests", "venv", ".git", "node_modules") or p.name == "model_endpoint.py" \
                or p.name == "test_codex_zero_retry.py":
            continue
        txt = p.read_text(errors="ignore")
        if re.search(r"ModelEndpointSession\b\s*(\(|as\b)|import\s+.*ModelEndpointSession.*\bas\b|getattr\([^)]*ModelEndpointSession", txt):
            hits.append("/".join(rel))
    assert hits == ["app/pipeline_guards.py"], hits
    src = (repo / "app" / "pipeline_guards.py").read_text()
    assert src.count("ModelEndpointSession(") == 1 and "codex_zero_retry=True" in src
