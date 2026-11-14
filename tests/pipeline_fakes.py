"""Offline fakes for exercising the REAL ranker -> analyzer -> pipeline path.

Only two external boundaries are replaced: the model provider (build_agent -> FakeAgent) and Stage 1 / source download
(a prebuilt forensics result, no contract source). Everything between - ranking, candidate selection, retries, the
analyzer loop, the pipeline - is the production code.
"""
import json
import os
import re
from types import SimpleNamespace

import networkx as nx

from faultseeker.utils.agent import AbstractAgent, GPTAgent

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
        self.adequacy_calls = self.understanding_calls = 0   # provider answers to adequacy / understanding prompts (re-asks included)
        self.task_sent = self.task_queries = 0   # task-selection replies sent in this attempt / in total
        self.processing_prompts = []
        self.in_attempt = False            # between a candidate's first understanding call and its adequacy check


def names_in(prompt):
    return re.findall(r'"function": "([^"]+)"', prompt)


REFORMAT = "The task is not in standard JSON format."
INFO_MARK = "Understand and translate the required additional information"
PVF_MARK = "function implementation is potentially vulnerable"  # matches both the old and the evidence-grounded prompt wording
GOOD_TASK = json.dumps({"task_selected": 1, "task_description": "inspect the function", "information": "", "additional_information": ""})

# Model-reply fixtures (raw TEXT, exactly what a provider would send back): scenario -> {"task": [replies], "info": reply}.
# The last task reply repeats for any further request.
SECRET_NOTE = f"note {LEAKY} api_key={DECOY_KV} https://rpc.example/v3/{DECOY_PATH}"
GEN = {
    "tasklist": {"task": [json.dumps(["inspect the function", SECRET_NOTE])]},          # a list, again and again
    "taskstring": {"task": [f"Inspect the function carefully. {SECRET_NOTE}"]},         # plain prose, never JSON
    "taskretryok": {"task": [json.dumps(["not an object"]), "still not JSON", GOOD_TASK]},
    "taskmissing": {"task": [json.dumps({"task_selected": 1, "information": SECRET_NOTE})]},
    "tasktype": {"task": [json.dumps({"task_description": ["step one", "step two"]})]},
    "taskoutage": {"task": ["An error occurred."]},
    "srcstrings": {"info": json.dumps({"source_code": ["0x" + "aa" * 20, "0xa9059cbb"]})},
    "srcmixed": {"info": json.dumps({
        "source_code": [{"function": "foo", "address": A}, "garbage", ["0x1234", "foo"], [B, "bar"],
                        {"function": "baz", "address": "0"}, {"function": "qux", "address": B.upper().replace("0X", "0x")}, 5, None],
        "balance_change": [A, 5, None],
        "function_call": [["notalist"], {"function": "foo", "address": A}, "x"],
        "children_calls": ["x", ["foo", A], 7]})},
    "infolist": {"info": json.dumps(["source_code", "balance_change"])},                  # whole reply of the wrong shape
    "infotext": {"info": f"Sure! Here is the information. {SECRET_NOTE}"},
}
for _name in GEN:
    SCENARIOS[_name] = ([("foo", A)], [], set(), set(), set())
SCENARIOS["srcmixed"] = ([("foo", A)], [], set(), set(), set())
# Provider null-content injection through the REAL GPTAgent (validation + re-asks): scenario -> {"adequacy": n, "understanding": n}
# = how many of the first provider answers to that kind of prompt arrive as 200 + content=None.
NULLS = {"nullcheckforever": {"adequacy": 999}, "nullcheckonce": {"adequacy": 1}, "nullunderstand": {"understanding": 999}}
for _name in NULLS:
    SCENARIOS[_name] = ([("foo", A)], [], set(), set(), set())
# Healthy analysis that records one finding, then the ranking reply under test (raw text from the provider).
RANK = {"foundok": json.dumps([f"foo_{A}"]), "foundbare": json.dumps(["foo"]), "foundbad": "I believe the foo function is the culprit.",
        "foundunmatched": json.dumps(["bar"]), "foundoutage": "An error occurred.", "foundnull": None}
for _name in RANK:
    SCENARIOS[_name] = ([("foo", A)], [], set(), set(), set())
HASH_PREFIX.update({"nullcheckforever": "bac0", "nullcheckonce": "bac1", "nullunderstand": "bac2",
                    "foundok": "bad0", "foundbare": "bad1", "foundbad": "bad2", "foundunmatched": "bad3", "foundoutage": "bad4",
                    "foundnull": "bad5"})
HASH_PREFIX.update({"tasklist": "b5b5", "taskstring": "b6b6", "taskretryok": "b7b7", "taskmissing": "b8b8", "tasktype": "b9b9",
                    "taskoutage": "bab0", "srcstrings": "bab1", "srcmixed": "bab2", "infolist": "bab3", "infotext": "bab4"})


class FakeAgent(AbstractAgent):
    """A real agent (real strict/lenient JSON parsing and validation) whose only fake part is the provider call: it
    returns raw reply TEXT, and raises ProviderDown where a provider call would fail."""

    def __init__(self, role, state):
        super().__init__("", "fake-model")
        self.role, self.state = role, state

    def _send_message(self, user_message, temperature=0):
        text, st = str(user_message), self.state
        _, _, fail_always, fail_once, fail_loop = SCENARIOS[st.scenario]
        secret = os.environ.get("OPENAI_API_KEY") or LEAKY
        understanding = self.role == "organization" and PVF_MARK not in text and names_in(text)
        # A new candidate attempt begins at the first understanding call after the previous attempt ended: its adequacy
        # check answered yes (in_attempt reset), its last processing call failed, or task selection gave up.
        if understanding and (not st.in_attempt or st.proc_state == "failed"):
            names = tuple(dict.fromkeys(names_in(text)))
            st.in_attempt, st.current = True, set(names)
            st.analyzed.append(names)
            for n in names:
                st.attempts[n] = st.attempts.get(n, 0) + 1
                if n in fail_always or (n in fail_once and st.attempts[n] == 1):
                    st.in_attempt = False
                    raise ProviderDown(leaky_text("401 Incorrect API key provided", secret))
            st.attempt_n, st.proc_calls, st.pvf_calls, st.proc_state, st.task_sent = st.attempts[names[0]], 0, 0, None, 0
        loop = LOOP.get(st.scenario)
        hit = bool(loop) and bool(st.current & loop[0]) and st.attempt_n in loop[2]
        if self.role == "processing":
            st.processing_prompts.append(text)
            if st.current & fail_loop:
                st.proc_state = "failed"
                raise ProviderDown(leaky_text("tool backend unavailable", secret))
            if hit:
                st.proc_calls += 1
                if st.proc_calls > loop[1]:
                    st.proc_failed += 1
                    st.proc_state = "failed"
                    raise ProviderDown(leaky_text("provider outage mid-candidate", secret))
            st.proc_state = "ok"
            return "ok"
        if self.role == "generation":
            gen = GEN.get(st.scenario, {})
            if INFO_MARK in text:
                return gen.get("info", "{}")
            replies = gen.get("task", [GOOD_TASK])
            reply = replies[min(st.task_sent, len(replies) - 1)]
            st.task_sent += 1
            st.task_queries += 1
            if st.task_sent >= 4 and not json_object(replies[-1]):
                st.in_attempt = False                       # the analyzer gives up on this candidate after 4 replies
            return reply
        if self.role == "organization":
            if PVF_MARK in text:
                if st.scenario in RANK and st.pvf_calls == 0:
                    st.pvf_calls += 1
                    return json.dumps({f"foo_{A}": {"evidence": "reentrancy before balance update", "confidence_score": 0.9}})
                if hit and loop[3] and st.pvf_calls == 0:
                    st.pvf_calls += 1                       # the first step records a finding
                    return json.dumps({f"{sorted(st.current)[0]}_{A}": {"evidence": "reentrancy before balance update", "confidence_score": 0.9}})
                return "{}"
            if "Current understanding:" in text:            # the adequacy check ends the candidate's task loop
                st.in_attempt = False
                return "yes"
            return "understanding ok"
        if self.role == "agent":
            return RANK.get(st.scenario, "[]")
        return "understanding ok"


def json_object(text):
    try:
        return isinstance(json.loads(text), dict)
    except ValueError:
        return False


class _Msg:
    def __init__(self, content):
        self.message = type("M", (), {"content": content})()


class _Completions:
    def __init__(self, agent):
        self.agent = agent

    def create(self, messages, model=None, **kw):
        return self.agent.provider_answer(messages[-1]["content"])


class GPTBoundary(GPTAgent):
    """The REAL GPTAgent (validation, bounded re-asks, text-only memory) on top of a fake OpenAI-style client. The fake
    client answers like FakeAgent does, except that the first N answers to adequacy checks / understanding requests
    arrive as HTTP 200 with content=None (the failure seen live)."""

    def __init__(self, role, state):
        AbstractAgent.__init__(self, "", "fake-model")
        self.resolved = SimpleNamespace(extra_params={}, temperature_mode="omit", temperature_value=0)
        self.role, self.state, self.logic = role, state, FakeAgent(role, state)
        self._client = SimpleNamespace(chat=SimpleNamespace(completions=_Completions(self)))

    def provider_answer(self, text):
        st, plan = self.state, NULLS.get(self.state.scenario, {})
        is_adequacy = self.role == "organization" and PVF_MARK not in text and "Current understanding:" in text
        if is_adequacy:
            st.adequacy_calls += 1
            if st.adequacy_calls <= plan.get("adequacy", 0):
                return SimpleNamespace(choices=[_Msg(None)])
        content = self.logic._send_message(text)
        if self.role == "organization" and PVF_MARK not in text and not is_adequacy and names_in(text):
            st.understanding_calls += 1
            if st.understanding_calls <= plan.get("understanding", 0):
                return SimpleNamespace(choices=[_Msg(None)])
        return SimpleNamespace(choices=[_Msg(content)])


class FakeDownloader:
    """Records every contract-source lookup the analyzer makes (class-level, reset by install())."""
    CALLS = []

    def __init__(self, chain, addresses, *a, **k):
        FakeDownloader.CALLS.append((chain, list(addresses)))

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
    FakeDownloader.CALLS.clear()
    roles = iter(["reasoning", "generation", "processing", "organization", "filtering", "agent"])
    if scenario in NULLS:
        import faultseeker.utils.agent as agent_module
        setattr_(agent_module, "CONTENT_RETRY_DELAYS", (0, 0))           # keep the re-asks, skip the waiting
        setattr_(analyzer, "build_agent", lambda task, model: GPTBoundary(next(roles, "agent"), state))
    else:
        setattr_(analyzer, "build_agent", lambda task, model: FakeAgent(next(roles, "agent"), state))
    setattr_(analyzer, "ContractDownloader", FakeDownloader)
    FakeForensics.scenario = scenario
    setattr_(orchestrator, "ForensicsOrchestrator", FakeForensics)
    return state
