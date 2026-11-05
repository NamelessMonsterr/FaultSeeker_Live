"""Fork-layer abstention-contract augmentation (input-side repair)."""
import importlib

import pytest

me = importlib.import_module("app.model_endpoint")

# The real pinned engine template plus representative appended data, exactly
# as engine construction assembles it (template first, untrusted data after).
VULN_PROMPT = (me.ENGINE_VULN_ANALYSIS_TEMPLATE
               + "The following function calls have been confirmed to be vulnerable: []"
               "Current understanding:{\"calls\": []}")


def kwargs_with(content, role="user"):
    return {"model": "mercury-3", "messages": [{"role": role, "content": content}]}


def test_vuln_prompt_is_augmented():
    kw = kwargs_with(VULN_PROMPT)
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented
    assert me.ABSTENTION_SENTINEL in out["messages"][0]["content"]
    assert "mechanism undetermined" in out["messages"][0]["content"]
    assert "observed_anomalies" not in out["messages"][0]["content"]  # engine discards extra fields
    assert me.ABSTENTION_SENTINEL not in kw["messages"][0]["content"]  # original untouched


def test_local_model_template_not_augmented_but_signalled():
    # The local-model prompt variant is out of the repair's scope (cloud
    # template only): no augmentation, but its 3-of-3 signature near-miss is
    # an observable mismatch, never a silent skip.
    kw = kwargs_with("Identify any vulnerable functions from the analysis below. "
                     'Keys are "<functionname>_<address>" with "confidence_score": <float>.')
    out, augmented, mismatch = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and mismatch


def test_topic_without_schema_signature_is_not_augmented():
    # A quoted phrase alone (e.g. transaction content discussing the topic)
    # must not trigger augmentation.
    kw = kwargs_with("The report mentioned potentially vulnerable code paths.")
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw


def test_non_vuln_prompts_untouched():
    kw = kwargs_with("Rank these functions from most to least likely to contain the vulnerability.")
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw


def test_other_phases_untouched():
    out, augmented, _ = me.augment_vulnerability_prompt(kwargs_with(VULN_PROMPT), "preflight")
    assert not augmented


@pytest.mark.parametrize("messages", [None, (), [], "text", 123])
def test_malformed_messages_never_crash_never_augment(messages):
    out, augmented, _ = me.augment_vulnerability_prompt({"messages": messages}, "analysis")
    assert not augmented


def test_malformed_entries_never_crash():
    kw = {"messages": [None, "plain", {"no_role": True}, {"role": "user", "content": 42},
                       {"role": "assistant", "content": VULN_PROMPT}]}
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented  # only the assistant message matched; no user match


def test_only_current_prompt_augmented_in_conversation_memory():
    # Engine conversation memory is multi-turn: the LAST user message is the
    # current invocation's prompt; history is never augmented.
    kw = {"messages": [{"role": "user", "content": VULN_PROMPT},
                       {"role": "assistant", "content": "interim"},
                       {"role": "user", "content": VULN_PROMPT}]}
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented
    assert me.ABSTENTION_SENTINEL not in out["messages"][0]["content"]
    assert me.ABSTENTION_SENTINEL in out["messages"][2]["content"]


def test_historical_match_never_augmented_for_ordinary_current():
    kw = {"messages": [{"role": "user", "content": VULN_PROMPT},
                       {"role": "assistant", "content": "Previous analysis..."},
                       {"role": "user", "content": "Summarize the transaction."}]}
    out, augmented, mismatch = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and not mismatch
    assert all(me.ABSTENTION_SENTINEL not in (m.get("content") or "")
               for m in out["messages"] if isinstance(m, dict))


def test_historical_match_does_not_mask_current_drift():
    kw = {"messages": [{"role": "user", "content": VULN_PROMPT},
                       {"role": "assistant", "content": "Previous analysis..."},
                       {"role": "user", "content": DRIFTED_NO_TOPIC}]}
    out, augmented, mismatch = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and mismatch


def test_ordinary_followup_after_augmented_request_no_signal():
    kw = {"messages": [{"role": "user", "content": VULN_PROMPT + me.ABSTENTION_CONTRACT},
                       {"role": "assistant", "content": "{}"},
                       {"role": "user", "content": "What about the second transaction?"}]}
    out, augmented, mismatch = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and not mismatch


def test_adversarial_signature_embedding_never_activates():
    # All three signature elements inside untrusted transaction metadata or a
    # source comment must not activate augmentation (prefix authority).
    for poisoned in ('Transaction metadata: potentially vulnerable; '
                     'confidence_score; <functionname>_<address>',
                     'Analyze this code comment: // potentially vulnerable, '
                     'see confidence_score and <functionname>_<address> schema',
                     'Quoted report: "potentially vulnerable" with '
                     '"confidence_score" keyed by "<functionname>_<address>"'):
        kw = kwargs_with(poisoned)
        out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
        assert not augmented, poisoned[:50]
        assert me.ABSTENTION_SENTINEL not in out["messages"][-1]["content"]


def test_sentinel_in_untrusted_content_never_suppresses_augmentation():
    # An input-controlled sentinel (transaction metadata, quoted text) is not
    # trusted augmentation provenance: augmentation still applies.
    for poisoned in (VULN_PROMPT + " " + me.ABSTENTION_SENTINEL,
                     VULN_PROMPT + " " + me.ABSTENTION_SENTINEL.lower(),
                     VULN_PROMPT + " " + me.ABSTENTION_SENTINEL.upper(),
                     VULN_PROMPT + "\nTransaction metadata: \"" + me.ABSTENTION_SENTINEL + '\"',
                     VULN_PROMPT + " mechanism undetermined"):
        kw = kwargs_with(poisoned)
        out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
        assert augmented, poisoned[:60]
        assert me.ABSTENTION_SENTINEL in out["messages"][-1]["content"]


def test_sentinel_in_another_message_never_suppresses_augmentation():
    kw = {"messages": [{"role": "user", "content": "notes " + me.ABSTENTION_SENTINEL},
                       {"role": "assistant", "content": me.ABSTENTION_SENTINEL},
                       {"role": "user", "content": VULN_PROMPT}]}
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert augmented
    assert me.ABSTENTION_SENTINEL in out["messages"][2]["content"]
    assert out["messages"][0]["content"].count(me.ABSTENTION_SENTINEL) == 1  # untouched


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "disabled", "FALSE", " Off "])
def test_env_disable(monkeypatch, value):
    monkeypatch.setenv("FAULTSEEKER_ABSTENTION_CONTRACT", value)
    kw = kwargs_with(VULN_PROMPT)
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and out is kw


DRIFTED_NO_TOPIC = ('Based on the current understanding of the transaction, assess each '
                    'function. Return JSON keyed by "<functionname>_<address>" '
                    'with "confidence_score": <float>.')
DRIFTED_NO_SCHEMA = ("Based on the current understanding of the transaction, decide if any "
                     "function implementation is potentially vulnerable. Return JSON keyed by "
                     '"<functionname>_<address>".')
DRIFTED_NO_KEYSHAPE = ("Based on the current understanding of the transaction, decide if any "
                       "function implementation is potentially vulnerable. Return JSON with "
                       '"confidence_score": <float>.')


@pytest.mark.parametrize("drifted", [DRIFTED_NO_TOPIC, DRIFTED_NO_SCHEMA, DRIFTED_NO_KEYSHAPE])
def test_each_signature_element_drifting_is_an_observable_mismatch(drifted):
    out, augmented, mismatch = me.augment_vulnerability_prompt(kwargs_with(drifted), "analysis")
    assert not augmented and mismatch


def test_ordinary_analysis_prompt_is_no_mismatch():
    for prompt in ("Rank these functions from most to least likely to contain the vulnerability.",
                   "Summarize the transaction.",
                   "The report mentioned potentially vulnerable code paths."):
        _, augmented, mismatch = me.augment_vulnerability_prompt(kwargs_with(prompt), "analysis")
        assert not augmented and not mismatch


def test_env_disable_reports_no_mismatch(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_ABSTENTION_CONTRACT", "off")
    _, augmented, mismatch = me.augment_vulnerability_prompt(kwargs_with(DRIFTED_NO_TOPIC), "analysis")
    assert not augmented and not mismatch


def test_pinned_engine_template_matches_embedded_identity():
    # Drift tripwire: the embedded trusted template is verified against the
    # REAL pinned engine prompt source, so upstream prompt rewording fails
    # this suite loudly instead of silently disabling the repair. This check
    # is the release verification of the repair's targeting authority: it
    # FAILS when the pinned checkout is unavailable (a skipped tripwire is
    # not a verified one), and it proves the imported module resolved from
    # the pinned checkout, not a previously cached import.
    import os
    location = os.getenv("FAULTSEEKER_TEST_PIPELINE_REPO")
    assert location, ("pinned engine checkout required: set "
                      "FAULTSEEKER_TEST_PIPELINE_REPO (release verification "
                      "of the abstention repair's targeting authority)")
    import pathlib
    import sys
    root = pathlib.Path(location).resolve()
    assert (root / "faultseeker/prompts/function_analysis/"
            "vulnerability_analysis_prompts.py").is_file(), \
        f"no engine prompt source under pinned checkout {root}"
    # Purge any previously imported engine modules so the import below
    # cannot silently resolve to a different cached checkout; restore the
    # original import state afterwards so the test leaves no global mutation.
    saved = {n: sys.modules[n] for n in list(sys.modules)
             if n == "faultseeker" or n.startswith("faultseeker.")}
    for name in saved:
        del sys.modules[name]
    original_path = sys.path[:]
    sys.path.insert(0, str(root))
    try:
        from faultseeker.prompts.function_analysis import vulnerability_analysis_prompts as vap
        resolved = pathlib.Path(vap.__file__).resolve()
        assert resolved.is_relative_to(root), \
            f"engine module resolved outside pinned checkout: {resolved}"
        actual = vap.VulnerabilityAnalysisPrompts().update_potentially_vulnerable_function
    finally:
        sys.path[:] = original_path
        for name in [n for n in list(sys.modules)
                     if n == "faultseeker" or n.startswith("faultseeker.")]:
            del sys.modules[name]
        sys.modules.update(saved)
    assert me.ENGINE_VULN_ANALYSIS_TEMPLATE == actual
    lowered = actual.lower()
    assert any(topic in lowered for topic in me._VULN_PROMPT_TOPICS)
    assert me._VULN_PROMPT_SCHEMA in lowered
    assert me._VULN_PROMPT_KEYSHAPE in lowered


# --- Dispatch-level integration through ModelEndpointSession.call ----------

import json as _json

import httpx as _httpx
from openai import OpenAI as _OpenAI

_EP = importlib.import_module("app.model_endpoint")
VULN_CALL = {"model": "mercury-3",
             "messages": [{"role": "user", "content": VULN_PROMPT}]}
_BLANK = {"id": "m", "object": "chat.completion", "created": 0, "model": "mercury-3",
          "choices": [{"index": 0, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}]}
_OK = {"id": "m", "object": "chat.completion", "created": 0, "model": "mercury-3",
       "choices": [{"index": 0, "message": {"role": "assistant", "content": "{}"}, "finish_reason": "stop"}]}


def _session_with(responses):
    calls = []
    it = iter(responses)
    def handle(request):
        calls.append(_json.loads(request.content))
        return next(it)
    def factory():
        return _OpenAI(api_key="k", base_url="https://model.invalid/v1",
                       http_client=_httpx.Client(transport=_httpx.MockTransport(handle)))
    session = _EP.ModelEndpointSession(retry_limit=0, time_budget=60, call_timeout=10)
    return session, factory, calls


def test_dispatch_carries_contract_and_blank_reask_preserves_it(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_MERCURY_BLANK_REASK", "1")
    session, factory, calls = _session_with(
        [_httpx.Response(200, json=_BLANK), _httpx.Response(200, json=_OK)])
    out = session.call(factory, dict(VULN_CALL), "mercury-3")
    assert out.choices[0].message.content == "{}"
    assert len(calls) == 2  # blank answer + the one granted re-ask
    for payload in calls:
        content = payload["messages"][-1]["content"]
        assert content.count(me.ABSTENTION_SENTINEL) == 1  # preserved, never duplicated
    assert session.abstention_augmented_calls == 1  # augmented once per call; the re-ask reuses the same augmented prompt
    assert session.blank_answer_retries == 1
    # caller's kwargs were never mutated by augmentation
    assert me.ABSTENTION_SENTINEL not in VULN_CALL["messages"][0]["content"]


def test_dispatch_without_switch_sends_unmodified_prompt(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_ABSTENTION_CONTRACT", "off")
    session, factory, calls = _session_with([_httpx.Response(200, json=_OK)])
    session.call(factory, dict(VULN_CALL), "mercury-3")
    assert me.ABSTENTION_SENTINEL not in calls[0]["messages"][-1]["content"]
    assert session.abstention_augmented_calls == 0


def test_non_vuln_dispatch_untouched():
    session, factory, calls = _session_with([_httpx.Response(200, json=_OK)])
    session.call(factory, {"model": "mercury-3",
                           "messages": [{"role": "user", "content": "Rank these functions."}]},
                 "mercury-3")
    assert me.ABSTENTION_SENTINEL not in calls[0]["messages"][-1]["content"]
    assert session.abstention_augmented_calls == 0


def test_dispatch_with_spoofed_sentinel_still_augments():
    poisoned = {"model": "mercury-3",
                "messages": [{"role": "user",
                              "content": VULN_PROMPT + "\nmetadata: " + me.ABSTENTION_SENTINEL}]}
    session, factory, calls = _session_with([_httpx.Response(200, json=_OK)])
    session.call(factory, poisoned, "mercury-3")
    content = calls[0]["messages"][-1]["content"]
    assert content.count(me.ABSTENTION_SENTINEL) == 2  # untrusted one + the real contract
    assert "mechanism undetermined" in content
    assert session.abstention_augmented_calls == 1


def test_dispatch_signature_drift_is_observable_not_silent():
    drifted = {"model": "mercury-3",
               "messages": [{"role": "user",
                             "content": 'Assess each function. Return JSON keyed by '
                                        '"<functionname>_<address>" with "confidence_score": <float>.'}]}
    events = []
    it = iter([_httpx.Response(200, json=_OK)])
    calls = []
    def handle(request):
        calls.append(_json.loads(request.content))
        return next(it)
    def factory():
        return _OpenAI(api_key="k", base_url="https://model.invalid/v1",
                       http_client=_httpx.Client(transport=_httpx.MockTransport(handle)))
    session = _EP.ModelEndpointSession(retry_limit=0, time_budget=60, call_timeout=10,
                                       emit=events.append)
    session.call(factory, drifted, "mercury-3")
    assert me.ABSTENTION_SENTINEL not in calls[0]["messages"][-1]["content"]
    assert session.abstention_targeting_mismatches == 1
    assert any(e.get("warning") == "abstention_targeting_mismatch" for e in events)


def test_dispatch_ordinary_prompt_raises_no_mismatch():
    session, factory, calls = _session_with([_httpx.Response(200, json=_OK)])
    session.call(factory, {"model": "mercury-3",
                           "messages": [{"role": "user", "content": "Rank these functions."}]},
                 "mercury-3")
    assert session.abstention_targeting_mismatches == 0


@pytest.mark.parametrize("bad_content", [None, 42, [{"type": "text", "text": "New request"}],
                                         {"nested": True}])
def test_unsupported_current_message_never_falls_back_to_history(bad_content):
    kw = {"messages": [{"role": "user", "content": VULN_PROMPT},
                       {"role": "assistant", "content": "Previous analysis"},
                       {"role": "user", "content": bad_content}]}
    out, augmented, mismatch = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and not mismatch
    assert me.ABSTENTION_SENTINEL not in out["messages"][0]["content"]


def test_missing_content_key_current_message_no_fallback():
    kw = {"messages": [{"role": "user", "content": VULN_PROMPT},
                       {"role": "assistant", "content": "Previous analysis"},
                       {"role": "user"}]}
    out, augmented, mismatch = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented and not mismatch
    assert me.ABSTENTION_SENTINEL not in out["messages"][0]["content"]


def _pinned_root():
    # The repair's targeting authority depends on the EXACT pinned engine, so
    # the checkout's identity is anchored to the authoritative build config:
    # HEAD must equal Dockerfile ARG FAULTSEEKER_SHA and the tree must be
    # clean. Fail closed when identity cannot be established.
    import os
    location = os.getenv("FAULTSEEKER_TEST_PIPELINE_REPO")
    assert location, ("pinned engine checkout required: set "
                      "FAULTSEEKER_TEST_PIPELINE_REPO (release verification "
                      "of the abstention repair's trusted boundary)")
    import pathlib
    import subprocess
    root = pathlib.Path(location).resolve()
    dockerfile = pathlib.Path(__file__).resolve().parents[1] / "Dockerfile"
    pin = next(l.split("=", 1)[1].strip() for l in dockerfile.read_text().splitlines()
               if l.startswith("ARG FAULTSEEKER_SHA="))
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    assert head == pin, f"engine checkout {head[:12]} != pinned {pin[:12]}"
    dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                           capture_output=True, text=True, check=True).stdout.strip()
    assert not dirty, f"engine checkout is dirty: {dirty[:200]}"
    return root


def test_pinned_engine_constructs_vuln_prompt_template_first():
    # Boundary tripwire, construction half: in the pinned engine the
    # vulnerability prompt is the template with data only ever APPENDED, so
    # untrusted content can never precede or replace the template.
    import re
    src = (_pinned_root() / "faultseeker/function_analysis/function_analyzer.py").read_text()
    body = re.search(r"def _update_potentially_vulnerable_function\(self\):(.*?)\n    def ",
                     src, re.S)
    assert body, "pinned engine: _update_potentially_vulnerable_function not found"
    lines = [l for l in body.group(1).splitlines() if l.strip().startswith("prompt")]
    assert lines and lines[0].strip().startswith(
        "prompt = self.vulnerability_prompts.update_potentially_vulnerable_function"), \
        f"template is not the construction base: {lines[:2]}"
    for later in lines[1:]:
        assert later.strip().startswith("prompt +="), \
            f"prompt reassigned after template (provenance broken): {later.strip()[:80]}"


def test_pinned_engine_dispatches_constructed_prompt_as_last_user_message():
    # Boundary tripwire, dispatch half: the agent layer appends the built
    # prompt as a user message immediately before dispatch, and model output
    # enters memory only under the assistant role - so the LAST user message
    # at dispatch is always engine-constructed, never model- or data-built.
    src = (_pinned_root() / "faultseeker/utils/agent.py").read_text()
    user_append = src.find('_append_memory({"role": "user", "content": user_message})')
    dispatch = src.find("messages=self._truncate_history(self.memory)")
    assert 0 <= user_append < dispatch, "user prompt is not appended before dispatch"
    assert '"role": "assistant"' in src[dispatch:], "model replies must enter as assistant"


def test_fork_installs_session_call_only_as_engine_internal_hook():
    # Boundary tripwire, fork half: session.call reaches the pipeline ONLY as
    # a replacement for the engine's internal _llm_call_with_retry; no
    # request/network path in the fork calls it directly.
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1] / "app" / "pipeline_guards.py").read_text()
    assert 'self.replace(agent_module, "_llm_call_with_retry", self.session.call)' in src
    import subprocess
    hits = subprocess.run(["grep", "-rn", "session\\.call", "app/", "--include=*.py"],
                          capture_output=True, text=True,
                          cwd=pathlib.Path(__file__).resolve().parents[1]).stdout
    callers = [l for l in hits.splitlines()
               if "call_timeout" not in l and not l.lstrip().startswith(("app/model_endpoint.py")) ]
    assert len(callers) == 1 and "_llm_call_with_retry" in callers[0], \
        f"unexpected session.call callers: {hits}"


def test_template_embedded_mid_message_never_activates():
    # The full template present anywhere except the very start of the current
    # prompt (e.g. quoted inside data) is not provenance.
    kw = kwargs_with("Analyze this quoted engine prompt: " + me.ENGINE_VULN_ANALYSIS_TEMPLATE)
    out, augmented, _ = me.augment_vulnerability_prompt(kw, "analysis")
    assert not augmented
    assert me.ABSTENTION_SENTINEL not in out["messages"][-1]["content"]


def test_pinned_engine_dispatch_boundary_integration():
    # R8-F2: behavioral proof, not source-text assertions. The pinned
    # engine's agent is driven through two real query() calls with the
    # dispatch hook instrumented exactly where the fork installs session.call
    # (over _llm_call_with_retry). Asserts the control flow: constructed
    # prompt -> appended as last user message -> dispatched -> model reply
    # enters memory under the assistant role.
    import os
    import sys
    root = str(_pinned_root())
    os.environ["OPENAI_API_KEY"] = "test-only-key"
    saved = {n: sys.modules[n] for n in list(sys.modules)
             if n == "faultseeker" or n.startswith("faultseeker.")}
    for n in saved:
        del sys.modules[n]
    original_path = sys.path[:]
    sys.path.insert(0, root)
    try:
        from faultseeker.utils import agent as agent_module
        captured = []

        class _Msg:
            content = "{}"
        class _Choice:
            message = _Msg()
        class _Completion:
            choices = [_Choice()]

        def spy(create_client, kwargs, model):
            captured.append([dict(m) for m in kwargs["messages"]])
            return _Completion()

        agent_module._llm_call_with_retry = spy  # the fork's install point
        a = agent_module.GPTAgent("boundary test", model_name="gpt-4o")
        a.query("CONSTRUCTED-PROMPT-ONE", format="str")
        a.query("CONSTRUCTED-PROMPT-TWO", format="str")
        assert len(captured) == 2
        first, second = captured
        assert first[-1] == {"role": "user", "content": "CONSTRUCTED-PROMPT-ONE"}
        assert second[-1] == {"role": "user", "content": "CONSTRUCTED-PROMPT-TWO"}
        # the model reply to prompt one entered history as assistant, and no
        # user message ever carries model output
        roles = [m["role"] for m in second]
        assert "assistant" in roles
        assert all(m["content"] != "{}" for m in second if m["role"] == "user")
    finally:
        sys.path[:] = original_path
        for n in [n for n in list(sys.modules)
                  if n == "faultseeker" or n.startswith("faultseeker.")]:
            del sys.modules[n]
        sys.modules.update(saved)


def test_summary_exposes_abstention_counters_on_real_dispatch():
    # Observability contract: a run's serialized model_endpoint summary must
    # carry the augmentation counters, so a production run can prove whether
    # the abstention contract actually reached the wire (activation evidence),
    # instead of relying on construction arguments alone.
    import json as _json
    import httpx
    from openai import OpenAI
    sent = []
    def reply(request):
        sent.append(_json.loads(request.content))
        return httpx.Response(200, json={"id": "mock", "object": "chat.completion",
                                         "created": 0, "model": "mercury-3",
                                         "choices": [{"index": 0, "message":
                                                      {"role": "assistant", "content": "{}"},
                                                      "finish_reason": "stop"}]})
    def factory():
        return OpenAI(api_key="test-secret-never-output", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    session = me.ModelEndpointSession(retry_limit=0, time_budget=60, call_timeout=10)
    session.register_keys("https://model.invalid/v1", ["k"], model="mercury-3")
    vuln_kwargs = {"model": "mercury-3",
                   "messages": [{"role": "user", "content": me.ENGINE_VULN_ANALYSIS_TEMPLATE + "ctx"}]}
    session.call(factory, vuln_kwargs, "mercury-3")
    summary = session.summary()
    assert summary["abstention_augmented_calls"] == 1
    assert summary["abstention_targeting_mismatches"] == 0
    # wire proof: the request that left for the provider carried the contract
    assert me.ABSTENTION_CONTRACT.strip()[-40:] in sent[0]["messages"][-1]["content"]
    # per-call correlation: the log names the exact call, its phase, and a
    # non-secret hash + structural contract-presence check captured at the
    # provider request boundary
    log = summary["abstention_calls"]
    assert len(log) == 1
    entry = log[0]
    assert entry["seq"] == 1 and entry["phase"] == "analysis"
    assert entry["model"] == "mercury-3" and entry["augmented"] is True
    assert entry["targeting_mismatch"] is False
    assert entry["contract_in_adapted_payload"] is True
    assert len(entry["adapted_messages_sha256_16"]) == 16
    # an ordinary prompt neither augments nor flags drift
    session.call(factory, {"model": "mercury-3",
                           "messages": [{"role": "user", "content": "rank these"}]}, "mercury-3")
    summary = session.summary()
    assert summary["abstention_augmented_calls"] == 1
    assert summary["abstention_targeting_mismatches"] == 0
    assert len(summary["abstention_calls"]) == 2
    assert summary["abstention_calls"][1]["augmented"] is False
    assert "contract_in_adapted_payload" not in summary["abstention_calls"][1]
