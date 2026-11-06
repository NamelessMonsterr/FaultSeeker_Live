"""Focused proof: FAULTSEEKER_MODEL_RETRY_LIMIT=0 means exactly one attempt
per phase on 429 / 5xx / timeout - preflight included (branch fix)."""
import os, sys, types
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import httpx
from model_endpoint import ModelEndpointSession, ModelEndpointFailure


class FakeCompletions:
    def __init__(self, exc):
        self.exc = exc
        self.calls = 0
    def create(self, **kwargs):
        self.calls += 1
        if self.exc is not None:
            raise self.exc
        msg = types.SimpleNamespace(content="ok")
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)], usage=None)


class FakeClient:
    def __init__(self, comp):
        self.chat = types.SimpleNamespace(completions=comp)
        self.base_url = "https://example.invalid/v1"
    def with_options(self, **kw):
        return self
    def close(self):
        pass


def make(exc):
    comp = FakeCompletions(exc)
    session = ModelEndpointSession(emit=lambda e: None, retry_limit=0,
                                   time_budget=600, call_timeout=30,
                                   sleep=lambda s: None)
    return session, comp, (lambda: FakeClient(comp))


def expect_one_attempt(name, exc, phase):
    session, comp, factory = make(exc)
    try:
        if phase == "preflight":
            session.preflight(factory, "gpt-6.1-sol-low", timeout=300)
        else:
            session.call(factory, {"model": "m", "messages": []}, "m", phase="analysis")
    except ModelEndpointFailure:
        pass
    else:
        raise AssertionError(f"{name}: expected ModelEndpointFailure")
    assert comp.calls == 1, f"{name}: {comp.calls} attempts, expected 1"
    print(f"PASS {name}: exactly 1 attempt, sticky failure={session.failure.kind!r}")


class StatusError(Exception):
    def __init__(self, code):
        self.status_code = code
        self.response = types.SimpleNamespace(headers={})


expect_one_attempt("preflight 429", StatusError(429), "preflight")
expect_one_attempt("preflight 500", StatusError(500), "preflight")
expect_one_attempt("preflight timeout", httpx.ConnectTimeout("boom"), "preflight")
expect_one_attempt("analysis 429", StatusError(429), "analysis")
expect_one_attempt("analysis 500", StatusError(500), "analysis")
expect_one_attempt("analysis timeout", httpx.ReadTimeout("boom"), "analysis")

# Control: retry_limit=1 allows exactly one retry (2 attempts) on analysis 429
comp = FakeCompletions(StatusError(429))
session = ModelEndpointSession(emit=lambda e: None, retry_limit=1,
                               time_budget=600, call_timeout=30, sleep=lambda s: None)
try:
    session.call(lambda: FakeClient(comp), {"model": "m", "messages": []}, "m", phase="analysis")
except ModelEndpointFailure:
    pass
assert comp.calls == 2, f"control retry_limit=1: {comp.calls} attempts, expected 2"
print("PASS control retry_limit=1 analysis 429: exactly 2 attempts")

# Control: success path returns the completion
comp = FakeCompletions(None)
session = ModelEndpointSession(emit=lambda e: None, retry_limit=0,
                               time_budget=600, call_timeout=30, sleep=lambda s: None)
r = session.preflight(lambda: FakeClient(comp), "gpt-6.1-sol-low", timeout=300)
assert comp.calls == 1 and r.choices[0].message.content == "ok"
print("PASS control success: 1 attempt, completion returned")
print("ALL FOCUSED TESTS PASS")
