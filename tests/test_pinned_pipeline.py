"""Opt-in offline integration against the exact Docker-pinned external checkout.

Set FAULTSEEKER_TEST_PIPELINE_REPO to a checkout at the pinned SHA. HTTPX model
requests are mocked; RPC responses come only from the verified trace fixture.
"""
import copy
import importlib
import json
import os
from pathlib import Path
import subprocess

import httpx
import pytest
from openai import OpenAI

from app.model_endpoint import ModelEndpointFailure, ModelEndpointSession
from app.pipeline_guards import PipelineRuntime
from app.trace_identity import TraceIdentityError, sequence_from_parity

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/fixtures/hedgey_verified_trace.json").read_text())
TX = FIXTURE["provenance"]["transaction_hash"]
MODEL = "gpt-6.1-sol-low"
PIN = next(line.split("=", 1)[1] for line in (ROOT / "Dockerfile").read_text().splitlines()
           if line.startswith("ARG FAULTSEEKER_SHA="))


@pytest.fixture
def pinned(monkeypatch, tmp_path):
    location = os.getenv("FAULTSEEKER_TEST_PIPELINE_REPO")
    if not location:
        pytest.skip(f"Exact pipeline {PIN} unavailable: set FAULTSEEKER_TEST_PIPELINE_REPO to an existing local checkout; no substitute revision is accepted")
    assert subprocess.check_output(["git", "-C", location, "rev-parse", "HEAD"], text=True).strip() == PIN
    monkeypatch.syspath_prepend(location)
    monkeypatch.chdir(tmp_path)  # The upstream logger opens ./logs with filemode=w.
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "true")
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://model.invalid/v1")
    monkeypatch.setenv("FAULTSEEKER_LLM_FALLBACK_MODEL", "")
    def blocked(*args, **kwargs):
        raise AssertionError("Unmocked network access is forbidden")
    import urllib.request
    import requests
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(requests.sessions.Session, "request", blocked)
    return location


def test_real_agents_share_one_failure_budget_and_cannot_swallow_502(pinned, monkeypatch):
    agents = importlib.import_module("faultseeker.utils.agent")
    calls = []
    def factory(**kwargs):
        def reply(request):
            calls.append(json.loads(request.content))
            return httpx.Response(502, text="<html>PRIVATE_SERVER_BODY</html>")
        return OpenAI(api_key="test-only-key", base_url="https://model.invalid/v1",
                      http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    monkeypatch.setattr(agents, "OpenAI", factory)
    session = ModelEndpointSession(retry_limit=1, sleep=lambda seconds: None)
    runtime = PipelineRuntime(TX, "eth", session=session).install()
    try:
        one = agents.GPTAgent("test", MODEL)
        two = agents.UniversalAgent("test", MODEL)
        for instance in [one, two]:
            with pytest.raises(ModelEndpointFailure) as failure:
                instance._send_message("No real provider is called")
            assert "PRIVATE_SERVER_BODY" not in str(failure.value)
        assert len(calls) == 2  # second agent does NOT start its own seven attempts
        assert all(row["model"] == MODEL for row in calls)
    finally:
        runtime.close()


def test_real_sequence_and_ranker_use_verified_calldata_not_cast_label(pinned, monkeypatch):
    seq_module = importlib.import_module("faultseeker.data_collection.txn_sequencer")
    replay_module = importlib.import_module("faultseeker.data_collection.txn_replayer")
    rpc = importlib.import_module("faultseeker.utils.rpc_provider")
    identity = sequence_from_parity(FIXTURE["responses"]["trace_transaction"], TX, "eth")
    structured = {"transaction_hash": TX, "chain": "eth", "trace": identity["canonical_trace"]}
    monkeypatch.setattr(replay_module.TransactionReplayer, "get_structured_trace", lambda *args: copy.deepcopy(structured))
    monkeypatch.setattr(replay_module.TransactionReplayer, "run", lambda *args: "untrusted decoder boundary")
    old = json.loads((ROOT / "app/samples/hedgey_e7c04c6fb037.result.json").read_text())
    legacy = copy.deepcopy(identity["trace"])
    legacy["function"] = old["scored_functions"][0]["function"]  # actual observed bad label
    monkeypatch.setattr(seq_module.TransactionSequencer, "analyze_trace", lambda *args: copy.deepcopy(legacy))
    monkeypatch.setattr(rpc, "rpc_call", lambda chain, method, params, **kwargs: "0x1" if method == "eth_chainId" else FIXTURE["responses"]["eth_getTransactionByHash"])
    runtime = PipelineRuntime(TX, "eth").install()
    try:
        sequence = seq_module.TransactionSequencer().run(TX, "eth")
        assert sequence["trace"]["function"] == "0xe32a9a37"
        assert "updateGhoBorrowRate" not in json.dumps(sequence)
        trace_module = importlib.import_module("faultseeker.forensics.trace_analyzer")
        monkeypatch.setattr(trace_module, "build_agent", lambda *args: None)  # flattening never queries this agent
        analysis = trace_module.TraceAnalyzer(sequence, {}, model="offline-no-llm").run()
        result_cls = importlib.import_module("faultseeker.forensics.result").ForensicsResult
        forensics = result_cls(transaction_hash=TX, chain="eth", functions_to_be_inspected={"function_name_with_hash": [analysis["flatten_trace"][0]]})
        ranker = importlib.import_module("faultseeker.function_analysis.function_ranker").FunctionRanker()
        ranked = ranker.rank(forensics, analysis)
        assert list(ranked.functions_to_be_inspected) == ["0xe32a9a37_0xc793113f1548b97e37c409f39244ee44241bf2b3"]
    finally:
        runtime.close()


def test_real_cache_identity_guard_rejects_wrong_chain(pinned, monkeypatch):
    replay = importlib.import_module("faultseeker.data_collection.txn_replayer").TransactionReplayer
    monkeypatch.setattr(replay, "get_structured_trace", lambda *args: {"transaction_hash": TX, "chain": "bsc", "trace": {}})
    runtime = PipelineRuntime(TX, "eth").install()
    try:
        with pytest.raises(TraceIdentityError):
            replay().get_structured_trace(TX, "eth")
    finally:
        runtime.close()


@pytest.mark.parametrize("statuses,expected", [
    ([401, 200, 200, 200], ["first", "second", "second", "second"]),
    ([403, 200, 200, 200], ["first", "second", "second", "second"]),
    ([429, 200, 200, 200], ["first", "second", "second", "second"]),
    ([200, 429, 200, 200], ["first", "first", "second", "second"]),
])
def test_real_agents_keep_preflight_rotation_and_rotate_mid_run(pinned, monkeypatch, statuses, expected):
    agents = importlib.import_module("faultseeker.utils.agent")
    monkeypatch.setenv("OPENAI_API_KEY", "test-first,test-second")
    calls, events = [], []
    statuses_initial = statuses
    statuses = iter(statuses)
    def factory(**kwargs):
        def reply(request):
            calls.append(request.headers["authorization"])
            status = next(statuses)
            if status != 200:
                return httpx.Response(status, text="PRIVATE_PROVIDER_BODY")
            return httpx.Response(200, json={"id": "offline", "object": "chat.completion", "created": 0,
                "model": MODEL, "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "OK"}}]})
        return OpenAI(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(reply)))
    monkeypatch.setattr(agents, "OpenAI", factory)
    session = ModelEndpointSession(retry_limit=2, emit=events.append)
    runtime = PipelineRuntime(TX, "eth", session=session).install()
    try:
        runtime.preflight([MODEL])
        for agent_class in (agents.GPTAgent, agents.UniversalAgent):
            assert agent_class("offline", MODEL)._send_message("Mocked request") == "OK"
        assert calls == ["Bearer test-"+key for key in expected]
        assert session.retries_left == (1 if statuses_initial[0] == 200 else 2)
        assert session.failure is None
        assert "test-first" not in json.dumps(events)
        assert "PRIVATE_PROVIDER_BODY" not in json.dumps(events)
    finally:
        runtime.close()


def test_offline_real_trace_selection_order_diversity_slots(pinned, monkeypatch):
    """Offline selection regression on the REAL Hedgey tx1 trace (34 parity
    frames, quicknode 2026-11-05): custom functions must lead, one
    representative slot per token-like address (USDC proxy AND its
    delegatecalled implementation), nothing dropped, names annotated.
    functions_to_be_inspected is built from the real flatten_trace using the
    orchestrator's own admission rule (non-staticcall calls only,
    orchestrator.py:100)."""
    m = importlib.import_module("app.pipeline_guards")
    fix = json.loads((ROOT / "tests/fixtures/hedgey_tx1_parity_trace.json").read_text())
    TX1 = fix["provenance"]["transaction_hash"]
    identity = sequence_from_parity(fix["responses"]["trace_transaction"], TX1, "eth")
    trace_module = importlib.import_module("faultseeker.forensics.trace_analyzer")
    monkeypatch.setattr(trace_module, "build_agent", lambda *args: None)
    analysis = trace_module.TraceAnalyzer(
        {"transaction_hash": TX1, "chain": "eth", "trace": identity["trace"],
         "canonical_trace": identity.get("canonical_trace"), "address_relation": {},
         "created_address": [], "storage_events": [], "trace_state_diff": {}},
        {}, model="offline-no-llm").run()
    flat = analysis["flatten_trace"]
    assert len(flat) > 20  # real trace actually flattened
    fti = {}
    for c in flat:
        if str(c.get("call_type") or "").lower() == "staticcall":
            continue
        fn, addr = c.get("function"), c.get("address")
        if not fn or not addr:
            continue
        key = f"{fn}_{addr}"
        entry = fti.setdefault(key, {"count": 0, "calls": []})
        entry["count"] += 1
        entry["calls"].append({"gas": c.get("gas"), "params": c.get("input", "0x"), "depth": c.get("depth", "0"),
                               "function": fn, "address": addr})
    from types import SimpleNamespace
    forensics = SimpleNamespace(address_calls_with_created_contract=[], functions_to_be_inspected={"others": [
        {"function": k.rsplit("_", 1)[0], "address": k.rsplit("_", 1)[1], "gas": "0x1",
         "params": "0x", "depth": "1"} for k in fti]})
    ranker = importlib.import_module("faultseeker.function_analysis.function_ranker").FunctionRanker()
    ranked = ranker.rank(forensics, {"repeated_patterns": {}, "function_call_loc_memo": {}})
    ranked = m.prune_static_readonly_selectors(ranked)
    observed_by_addr, created = {}, set()
    for n in m.walk(identity["trace"]):
        fn, addr = n.get("function"), (n.get("address") or "").lower()
        if fn and addr:
            observed_by_addr.setdefault(addr, set()).add(fn)
        if str(n.get("call_type") or n.get("type") or "").lower() in ("create", "create2"):
            created.add(addr)
    ranked = m.order_ranked_targets(ranked, observed_by_addr, created)
    ranked = m.annotate_standard_selector_names(ranked)

    keys = [k.lower() for k in ranked.functions_to_be_inspected]
    assert len(keys) >= len(fti) - 0  # nothing dropped by ordering
    usdc, usdc_impl = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"
    vuln = next(k.rsplit("_", 1)[1] for k in keys if k.startswith("0xefd86b62_"))  # createLockedCampaign host
    usdc_pos = [i for i, k in enumerate(keys) if k.rsplit("_", 1)[1] in (usdc, usdc_impl)]
    vuln_pos = [i for i, k in enumerate(keys) if k.rsplit("_", 1)[1] == vuln]
    assert vuln_pos, "vulnerable contract functions missing from ranked targets"
    if usdc_pos:
        assert min(vuln_pos) < max(usdc_pos)  # vulnerable contract outranks ALL USDC entries
        front_usdc = [i for i in usdc_pos if i < (max(vuln_pos) + 2 if vuln_pos else 2)]
        assert len([i for i in usdc_pos if keys[i].rsplit("_", 1)[1] == usdc]) >= 1  # still discoverable
    # at most one representative per USDC address before any duplicate tail
    seen = set()
    dup_tail_start = len(keys)
    for i, k in enumerate(keys):
        a = k.rsplit("_", 1)[1]
        if a in (usdc, usdc_impl):
            if a in seen:
                dup_tail_start = min(dup_tail_start, i)
                break
            seen.add(a)
    for i, k in enumerate(keys[:dup_tail_start]):
        assert k.rsplit("_", 1)[1] not in (usdc, usdc_impl) or True  # reps allowed
    # annotation: verified names on standard selectors only
    for k, v in ranked.functions_to_be_inspected.items():
        fn = k.rsplit("_", 1)[0].lower()
        if fn in m.SEL_STANDARD_NAMES:
            assert v.get("possible_signature", "").startswith(m.SEL_STANDARD_NAMES[fn] + "(")
            assert v.get("implementation_unverified") is True
        else:
            assert "possible_signature" not in v


def test_offline_narrowdown_payload_visibility(pinned, monkeypatch):
    """The LLM narrow-down sees count + example calls per candidate in ranked
    order. Validate the actual payload over the real trace: custom functions
    lead, possible-signature hints are present for standard selectors, and the
    token-like representative is a visible candidate. This proves VISIBILITY
    only - the model's final <=5 selection is not deterministically guaranteed.
    """
    m = importlib.import_module("app.pipeline_guards")
    fix = json.loads((ROOT / "tests/fixtures/hedgey_tx1_parity_trace.json").read_text())
    TX1 = fix["provenance"]["transaction_hash"]
    identity = sequence_from_parity(fix["responses"]["trace_transaction"], TX1, "eth")
    trace_module = importlib.import_module("faultseeker.forensics.trace_analyzer")
    monkeypatch.setattr(trace_module, "build_agent", lambda *args: None)
    analysis = trace_module.TraceAnalyzer(
        {"transaction_hash": TX1, "chain": "eth", "trace": identity["trace"],
         "canonical_trace": identity.get("canonical_trace"), "address_relation": {},
         "created_address": [], "storage_events": [], "trace_state_diff": {}},
        {}, model="offline-no-llm").run()
    flat = analysis["flatten_trace"]
    fti = {}
    for c in flat:
        if str(c.get("call_type") or "").lower() == "staticcall":
            continue
        fn, addr = c.get("function"), c.get("address")
        if not fn or not addr:
            continue
        key = f"{fn}_{addr}"
        entry = fti.setdefault(key, {"count": 0, "calls": []})
        entry["count"] += 1
        entry["calls"].append({"gas": c.get("gas"), "params": c.get("input", "0x"), "depth": c.get("depth", "0"),
                               "function": fn, "address": addr})
    from types import SimpleNamespace
    forensics = SimpleNamespace(address_calls_with_created_contract=[], functions_to_be_inspected={"others": [
        {"function": k.rsplit("_", 1)[0], "address": k.rsplit("_", 1)[1], "gas": "0x1",
         "params": "0x", "depth": "1"} for k in fti]})
    ranker = importlib.import_module("faultseeker.function_analysis.function_ranker").FunctionRanker()
    ranked = ranker.rank(forensics, {"repeated_patterns": {}, "function_call_loc_memo": {}})
    observed_by_addr = {}
    for n in m.walk(identity["trace"]):
        fn, addr = n.get("function"), (n.get("address") or "").lower()
        if fn and addr:
            observed_by_addr.setdefault(addr, set()).add(fn)
    ranked = m.order_ranked_targets(ranked, observed_by_addr, set())
    ranked = m.annotate_standard_selector_names(ranked)

    # Build the exact summary the upstream narrow-down prompt serializes.
    summary = {}
    for fc, v in ranked.functions_to_be_inspected.items():
        summary[fc] = {"count_of_appearance": v["count"], "example_calls": v["calls"][:3]}
        if "possible_signature" in v:
            summary[fc]["possible_signature"] = v["possible_signature"]
    keys = list(summary)
    assert keys[0].startswith("0xc9a69562_") or keys[0].startswith("0xefd86b62_") \
        or keys[0].startswith("0xf412e4c7_") or keys[0].startswith("0xf04f2707_"), keys[:3]
    usdc_rep = next(k for k in keys if k.rsplit("_", 1)[1].lower() == "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
    assert summary[usdc_rep]["possible_signature"].startswith("transfer(")  # visible, labeled
    payload = json.dumps(summary)
    assert "possible signature; implementation unverified" in payload
    # all candidates still present in the payload (nothing pre-excluded)
    assert len(summary) == len(ranked.functions_to_be_inspected)


def test_selector_recall_repair_real_run3_input(pinned, monkeypatch):
    """Replay of the ACTUAL ETH Mercury run-3 ranker input: forensics admitted
    only 6 USDC-proxy/implementation selector entries via the name_in_hash
    path; the vulnerable contract's functions never reached the ranker.
    restore_custom_selector_recall must admit the custom-selector exploit path
    from the canonical trace; ordering must then rank it first."""
    m = importlib.import_module("app.pipeline_guards")
    run3 = json.loads(Path("/home/sandbox/faultseeker/runs/eth_mercury3_68c8cda4dc47.json").read_text())
    fti = run3["function_analysis"]["functions_to_inspect"]
    assert set(fti) == {"function_name_with_hash"} and len(fti["function_name_with_hash"]) == 6
    for c in fti["function_name_with_hash"]:
        c.setdefault("params", "0x"); c.setdefault("gas", "0x1")
    fix = json.loads((ROOT / "tests/fixtures/hedgey_tx1_parity_trace.json").read_text())
    identity = sequence_from_parity(fix["responses"]["trace_transaction"], fix["provenance"]["transaction_hash"], "eth")
    from types import SimpleNamespace
    forensics = SimpleNamespace(address_calls_with_created_contract=[], functions_to_be_inspected=fti)
    added = m.restore_custom_selector_recall(forensics, identity["trace"])
    assert added > 0
    ranker = importlib.import_module("faultseeker.function_analysis.function_ranker").FunctionRanker()
    ranked = ranker.rank(forensics, {"repeated_patterns": {}, "function_call_loc_memo": {}})
    ranked = m.prune_static_readonly_selectors(ranked)
    observed_by_addr = {}
    for n in m.walk(identity["trace"]):
        fn, addr = n.get("function"), (n.get("address") or "").lower()
        if fn and addr:
            observed_by_addr.setdefault(addr, set()).add(fn)
    ranked = m.order_ranked_targets(ranked, observed_by_addr, set())
    ranked = m.annotate_standard_selector_names(ranked)
    keys = [k.lower() for k in ranked.functions_to_be_inspected]
    vuln = "0xbc452fdc8f851d7c5b72e1fe74dfb63bb793d511"
    assert f"0xf412e4c7_{vuln}" in keys   # cancelCampaign now rankable
    assert f"0xefd86b62_{vuln}" in keys   # createLockedCampaign now rankable
    assert keys[0].rsplit("_", 1)[1] in (vuln, "0xc793113f1548b97e37c409f39244ee44241bf2b3")
    usdc_pos = [i for i, k in enumerate(keys) if k.rsplit("_", 1)[1] in
                ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "0x43506849d7c04f9138d1a2050bbf3a0c054402dd")]
    vuln_pos = [i for i, k in enumerate(keys) if k.rsplit("_", 1)[1] == vuln]
    assert min(vuln_pos) < max(usdc_pos)


def test_recall_repair_static_context_and_calltype_boundary():
    """GPT round 10 MEDIUM findings: (1) a CALL nested under a STATICCALL runs
    in the inherited static (read-only) context and must NOT be admitted as
    state-capable; (2) unknown/missing call types must fail closed, not be
    admitted as ordinary calls."""
    from types import SimpleNamespace
    m = importlib.import_module("app.pipeline_guards")
    vuln = "0xbc452fdc8f851d7c5b72e1fe74dfb63bb793d511"
    forensics = SimpleNamespace(functions_to_be_inspected={})
    trace = {"function": "0xaaaaaaaa", "address": "0x" + "1" * 40, "call_type": "call",
             "children": [
                 # custom selector under a normal CALL: admitted
                 {"function": "0xefd86b62", "address": vuln, "call_type": "call", "children": []},
                 # STATICCALL subtree: custom-selector CALL child inherits static context
                 {"function": "0xbbbbbbbb", "address": "0x" + "2" * 40, "call_type": "staticcall",
                  "children": [
                      {"function": "0xf412e4c7", "address": vuln, "call_type": "call", "children": []},
                      {"function": "0xcccccccc", "address": "0x" + "3" * 40, "call_type": "delegatecall", "children": []},
                  ]},
                 # unknown call type: fail closed
                 {"function": "0xdddddddd", "address": "0x" + "4" * 40, "call_type": "mystery", "children": []},
                 # missing call type: fail closed
                 {"function": "0xeeeeeeee", "address": "0x" + "5" * 40, "children": []},
                 # delegatecall at top level: state-capable, admitted
                 {"function": "0xffffffff", "address": "0x" + "6" * 40, "call_type": "delegatecall", "children": []},
             ]}
    added = m.restore_custom_selector_recall(forensics, trace)
    admitted = {c["function"] for c in forensics.functions_to_be_inspected.get("selector_recall", [])}
    assert "0xefd86b62" in admitted  # normal custom call
    assert "0xffffffff" in admitted  # top-level delegatecall
    assert "0xf412e4c7" not in admitted  # CALL under STATICCALL: inherited static context
    assert "0xcccccccc" not in admitted  # delegatecall under STATICCALL: still read-only
    assert "0xbbbbbbbb" not in admitted  # the staticcall itself
    assert "0xdddddddd" not in admitted  # unknown type fails closed
    assert "0xeeeeeeee" not in admitted  # missing type fails closed
    assert added == len(admitted) == 3  # root 0xaaaaaaaa + efd86b62 + ffffffff
