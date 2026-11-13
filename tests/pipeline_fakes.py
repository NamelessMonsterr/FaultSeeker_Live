"""Offline fakes for exercising the REAL ranker -> analyzer -> pipeline path.

Only two external boundaries are replaced: the model provider (build_agent -> FakeAgent) and Stage 1 / source download
(a prebuilt forensics result, no contract source). Everything between - ranking, candidate selection, retries, the
analyzer loop, the pipeline - is the production code.
"""
import os
import re
from types import SimpleNamespace

import networkx as nx

A = "0x" + "aa" * 20
B = "0x" + "bb" * 20
LEAKY = "sk-test-leak-0123456789abcdefghijkl"          # what a provider error might echo back
DECOY_PATH = "0123456789abcdefDECOYPATHSEGMENT"         # a key embedded in an RPC/provider URL path
DECOY_KV = "kv-decoy-98765432100"                       # a key given as api_key=...
DECOYS = [LEAKY, DECOY_PATH, DECOY_KV]


def leaky_text(prefix, secret):
    return (f"{prefix}: {secret}. Bearer {LEAKY} rejected by https://rpc.example/v3/{DECOY_PATH}?apikey=zz "
            f"(api_key={DECOY_KV})")


class ProviderDown(RuntimeError):
    pass


def call(function, address):
    return {"function": function, "address": address, "gas": 1, "params": "p", "depth": [0]}


def pat(function, address):
    return {"pattern": [{"function": function, "address": address, "call_type": "call", "depth": [0]}],
            "repeats": 4, "start_index": 0, "end_index": 3}


# name -> (functions_to_be_inspected candidates, repeated patterns, fail_always, fail_once, fail_in_loop)
SCENARIOS = {
    "allfail": ([("foo", A), ("bar", B)], [], {"foo", "bar"}, set(), set()),
    "mixed": ([("foo", A), ("bar", B)], [], {"bar"}, set(), set()),
    "retry": ([("foo", A)], [("foo", A)], set(), {"foo"}, set()),
    "zero": ([], [], set(), set(), set()),
    "case": ([("Foo", A), ("foo", A)], [], set(), set(), set()),
    "inloop": ([("foo", A)], [], set(), set(), {"foo"}),
    "ok": ([("foo", A), ("bar", B)], [], set(), set(), set()),
}
# Loop-level failures: scenario -> (functions affected, steps that succeed first, candidate attempts affected, record a finding)
LOOP = {
    "capped": ({"foo"}, 1, {1, 2}, False),          # A: one step succeeds, then every provider call fails (iteration cap)
    "finding": ({"foo"}, 1, {1}, True),             # B: a finding is recorded, then the next step raises
    "cappedretry": ({"foo"}, 1, {1}, False),        # first attempt incomplete, the retry is healthy
    "mixedcap": ({"bar"}, 1, {1, 2}, False),        # foo completes, bar never does
}
SCENARIOS.update({
    "capped": ([("foo", A)], [("foo", A)], set(), set(), set()),
    "finding": ([("foo", A)], [], set(), set(), set()),
    "cappedretry": ([("foo", A)], [("foo", A)], set(), set(), set()),
    "mixedcap": ([("foo", A), ("bar", B)], [], set(), set(), set()),
})
HASH_PREFIX = {"allfail": "a1a1", "mixed": "a2a2", "retry": "a3a3", "zero": "a4a4", "inloop": "a5a5", "ok": "a6a6", "case": "a7a7",
               "capped": "b1b1", "finding": "b2b2", "cappedretry": "b3b3", "mixedcap": "b4b4"}


class State:
    def __init__(self, scenario):
        self.scenario = scenario
        self.analyzed = []                 # one tuple of function names per candidate analysis attempt
        self.attempts = {}                 # function name -> attempts seen
        self.current = set()
        self.attempt_n = 0                 # which attempt of the current candidate this is
        self.proc_calls = self.proc_failed = self.pvf_calls = 0
        self.proc_state = None             # outcome of the last processing call: 'ok' / 'failed'
        self.in_attempt = False            # between a candidate's first understanding call and its adequacy check


def names_in(prompt):
    return re.findall(r'"function": "([^"]+)"', prompt)


class FakeAgent:
    def __init__(self, role, state):
        self.role, self.state = role, state

    def query(self, prompt, format=None):
        text, st = str(prompt), self.state
        _, _, fail_always, fail_once, fail_loop = SCENARIOS[st.scenario]
        secret = os.environ.get("OPENAI_API_KEY") or LEAKY
        # A new candidate attempt begins at the first understanding call after the previous attempt ended: either its
        # adequacy check answered yes (in_attempt reset) or its last processing call failed (the loop never got further).
        if self.role == "organization" and names_in(text) and (not st.in_attempt or st.proc_state == "failed"):
            names = tuple(dict.fromkeys(names_in(text)))
            st.in_attempt, st.current = True, set(names)
            st.analyzed.append(names)
            for n in names:
                st.attempts[n] = st.attempts.get(n, 0) + 1
                if n in fail_always or (n in fail_once and st.attempts[n] == 1):
                    st.in_attempt = False
                    raise ProviderDown(leaky_text("401 Incorrect API key provided", secret))
            st.attempt_n, st.proc_calls, st.pvf_calls, st.proc_state = st.attempts[names[0]], 0, 0, None
        loop = LOOP.get(st.scenario)
        hit = bool(loop) and bool(st.current & loop[0]) and st.attempt_n in loop[2]
        if self.role == "processing" and st.current & fail_loop:
            st.proc_state = "failed"
            raise ProviderDown(leaky_text("tool backend unavailable", secret))
        if self.role == "processing" and hit:
            st.proc_calls += 1
            if st.proc_calls > loop[1]:
                st.proc_failed += 1
                st.proc_state = "failed"
                raise ProviderDown(leaky_text("provider outage mid-candidate", secret))
        if self.role == "processing":
            st.proc_state = "ok"
        if self.role == "organization" and hit and loop[3] and format is None and st.pvf_calls == 0:
            st.pvf_calls += 1                                       # the first step records a finding
            return {f"{sorted(st.current)[0]}_{A}": {"evidence": "reentrancy before balance update", "confidence_score": 0.9}}
        if format == "str":
            if "Current understanding:" in text:           # the adequacy check ends the candidate's task loop
                st.in_attempt = False
                return "yes"
            return "understanding ok"
        if self.role == "agent":
            return []
        return {"task_description": "inspect the function"}


class FakeDownloader:
    def __init__(self, chain, addresses, *a, **k):
        pass

    def run(self):
        return {}


class FakeForensics:
    scenario = "ok"

    def __init__(self, *a, **k):
        pass

    def run(self, txn_hash, chain):
        cands, patterns, *_ = SCENARIOS[FakeForensics.scenario]
        graph = nx.node_link_data(nx.DiGraph(), edges="edges")
        result = SimpleNamespace(
            transaction_hash=txn_hash, chain=chain, trace={"children": []}, duration=0.0,
            repeated_patterns={"k": [pat(f, a) for f, a in patterns]} if patterns else {}, function_call_loc_memo={},
            function_calls_to_expand_loc=[], address_calls_with_created_contract=[], flatten_trace=[],
            balance_change={}, address_memo={}, potential_attacker=[], potential_victim=[],
            functions_to_be_inspected={"k": [call(f, a) for f, a in cands]} if cands else {},
            get_function_count=lambda: len(cands))
        return result, {"address_relation": graph, "address_calls": {}, "created_address": []}, {"transaction_hash": txn_hash}


def install(scenario, setattr_):
    """setattr_(obj, name, value): monkeypatch.setattr in tests, plain setattr in the worker process."""
    import faultseeker.forensics.orchestrator as orchestrator
    import faultseeker.function_analysis.function_analyzer as analyzer
    state = State(scenario)
    roles = iter(["reasoning", "generation", "processing", "organization", "filtering", "agent"])
    setattr_(analyzer, "build_agent", lambda task, model: FakeAgent(next(roles, "agent"), state))
    setattr_(analyzer, "ContractDownloader", FakeDownloader)
    FakeForensics.scenario = scenario
    setattr_(orchestrator, "ForensicsOrchestrator", FakeForensics)
    return state
