"""No executable parsing of model text, and typed contracts for the active forensics consumers (OFFLINE, local fake agents).

The agents here are real AbstractAgent subclasses (real parsing, validation and retry code); only the provider call is fake.
"""
import ast
import os
import pathlib

import pytest

try:
    import faultseeker.utils.agent as agent_module
    from faultseeker.forensics import address_classifier as classifier_module
    from faultseeker.forensics import fund_flow_analyzer as fund_flow_module
    from faultseeker.utils.agent import AbstractAgent, ProviderFailure
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

try:
    from faultseeker.forensics.contracts import ForensicsModelError
except ImportError:                                   # reported by test_the_typed_contract_module_exists, never a silent skip
    ForensicsModelError = None

ROOT = pathlib.Path(agent_module.__file__).resolve().parents[1]
PROBE = "FS_EVAL_PROBE"
ZERO = "0x" + "0" * 40
V1, V2, V3 = "0x" + "a1" * 20, "0x" + "b2" * 20, "0x" + "c3" * 20
HOSTILE = f"__import__('os').environ.__setitem__('{PROBE}', 'executed')"


@pytest.fixture(autouse=True)
def no_probe(monkeypatch):
    monkeypatch.delenv(PROBE, raising=False)
    monkeypatch.setattr(agent_module, "CONTENT_RETRY_DELAYS", (0, 0))          # keep the re-asks, skip the waiting
    yield
    os.environ.pop(PROBE, None)


class Script(AbstractAgent):
    def __init__(self, *replies):
        super().__init__("", "script")
        self.replies, self.prompts = list(replies), []

    def _send_message(self, user_message, temperature=0):
        self.prompts.append(user_message)
        return self.replies[min(len(self.prompts) - 1, len(self.replies) - 1)]


# ------------------------------------------------------------------------------------------ the parser never executes text

def test_the_typed_contract_module_exists():
    assert ForensicsModelError is not None and issubclass(ForensicsModelError, RuntimeError)


def test_no_eval_or_exec_remains_in_the_package():
    offenders = []
    for path in ROOT.rglob("*.py"):
        if "antlrGenerated" in path.parts:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert offenders == []


@pytest.mark.parametrize("fmt", ["json", "dict"])
@pytest.mark.parametrize("payload", [HOSTILE, f"[{HOSTILE}]", f"```python\n{HOSTILE}\n```", f"{{'a': {HOSTILE}}}",
                                     f"['x',\n{HOSTILE}]"])
def test_legacy_query_does_not_execute_model_text(fmt, payload):
    Script(payload).query("p", format=fmt)
    assert PROBE not in os.environ, "model text was executed"


@pytest.mark.parametrize("fmt,reply,expected", [
    ("json", '["a", "b"]', ["a", "b"]), ("json", "['a', 'b']", ["a", "b"]), ("json", '```json\n["a"]\n```', ["a"]),
    ("json", "```python\n['a']\n```", ["a"]), ("dict", "{'a': 1}", {"a": 1}), ("dict", '{"a": [1, 2]}', {"a": [1, 2]}),
    ("json", "('a', 'b')", ("a", "b")),
])
def test_valid_legacy_shapes_still_parse(fmt, reply, expected):
    assert Script(reply).query("p", format=fmt) == expected


@pytest.mark.parametrize("payload", [HOSTILE, f"[{HOSTILE}]", "{'a': __import__('os')}"])
def test_strict_parsers_reject_instead_of_executing(payload):
    from faultseeker.utils.agent import ModelResponseError
    with pytest.raises(ModelResponseError):
        Script(payload).query_json("p")
    with pytest.raises(ModelResponseError):
        Script(payload).query_json_once("p")
    assert PROBE not in os.environ


# ------------------------------------------------------------------------------------------ victims (real caller path)

def txn_info():
    edges = [{"source": V1, "target": V2, "label": "USDT [Tether] (1,000)"},
             {"source": V2, "target": V3, "label": "USDT [Tether] (400)"}]
    return {"transaction_hash": "0x" + "1" * 64, "token_transfer": {"edges": edges},
            "address_info": {"from_address": V3, "to_address": [V2]}}


def fund_flow(monkeypatch, *replies):
    agent = Script(*replies)
    monkeypatch.setattr(fund_flow_module, "build_agent", lambda task, model: agent)
    return fund_flow_module.FundFlowAnalyzer(model="m"), agent


def test_a_valid_victim_list_flows_through_run(monkeypatch):
    f, agent = fund_flow(monkeypatch, f'["{V1}", "{ZERO}", "0x{"d4" * 20}", "{V1.upper().replace("0X", "0x")}"]')
    result = f.run(txn_info())
    assert result["potential_victim"] == [V1] and len(agent.prompts) == 1
    assert V1 not in result["potential_attacker"]


@pytest.mark.parametrize("reply", [f"```json\n['{V1}']\n```", f"['{V1}']", f'["{V1}", null, 5, {{"x": 1}}, ""]'])
def test_victim_replies_in_valid_legacy_shapes_are_accepted(monkeypatch, reply):
    f, _ = fund_flow(monkeypatch, reply)
    assert f.run(txn_info())["potential_victim"] == [V1]


def test_an_explicit_empty_victim_list_is_a_valid_answer(monkeypatch):
    f, _ = fund_flow(monkeypatch, "[]")
    assert f.run(txn_info())["potential_victim"] == []


@pytest.mark.parametrize("reply", ["An error occurred.", None, "", "   "])
def test_a_provider_failure_is_never_an_empty_victim_list(monkeypatch, reply):
    f, agent = fund_flow(monkeypatch, reply)
    with pytest.raises(ProviderFailure):
        f.run(txn_info())
    assert f.potential_victim == [] and len(agent.prompts) <= 3, "the existing content-retry budget is not exceeded"


@pytest.mark.parametrize("reply", [f"The victim is {V1}", "no idea", f'{{"victims": ["{V1}"]}}', "42", HOSTILE, f"[{HOSTILE}]"])
def test_an_unusable_victim_reply_is_a_typed_failure_not_an_empty_list(monkeypatch, reply):
    f, agent = fund_flow(monkeypatch, reply)
    with pytest.raises(ForensicsModelError) as err:
        f.run(txn_info())
    assert reply not in str(err.value) and "victim" in str(err.value).lower()
    assert len(agent.prompts) == 3, "exactly the existing structured-reply budget: no nested retry amplification"
    assert PROBE not in os.environ


def test_victim_identification_makes_one_request_when_the_reply_is_usable(monkeypatch):
    f, agent = fund_flow(monkeypatch, f'["{V2}"]')
    f.run(txn_info())
    assert len(agent.prompts) == 1


# ------------------------------------------------------------------------------------------ address roles (real caller path)

def classifier(monkeypatch, *replies, addresses=(V1,)):
    agent = Script(*replies)
    c = object.__new__(classifier_module.AddressClassifier)
    c.agent, c.prompts = agent, classifier_module.AddressClassificationPrompts()
    c.address_inspected, c.same_funciton_calls = {}, {}
    c.txn_seq = {"chain": "eth"}
    c.address_to_be_inspected = {a: {"function_calls": {"swap": [{"type": "call"}]}, "label": ""} for a in addresses}
    return c, agent


def test_a_plain_role_list_classifies_the_address(monkeypatch):
    c, agent = classifier(monkeypatch, "['lending', 'stablecoin']")
    c._identify_role_of_address()
    assert c.address_inspected[V1]["role"] == ["lending", "stablecoin"] and V1 not in c.address_to_be_inspected
    assert len(agent.prompts) == 1


@pytest.mark.parametrize("reply", ['["unknown"]', '["lending", "vulnerable"]', '["Vulnerable", "lending"]', '["UNKNOWN"]',
                                   "```json\n['flashloan', 'Vulnerable']\n```"])
def test_unknown_or_vulnerable_addresses_stay_to_be_inspected_whatever_the_case(monkeypatch, reply):
    c, _ = classifier(monkeypatch, reply)
    c._identify_role_of_address()
    assert V1 in c.address_to_be_inspected and V1 not in c.address_inspected
    assert c.address_to_be_inspected[V1]["role"]


@pytest.mark.parametrize("reply", ["An error occurred.", None, ""])
def test_a_provider_failure_never_becomes_a_clean_classification(monkeypatch, reply):
    c, agent = classifier(monkeypatch, reply)
    with pytest.raises(ProviderFailure):
        c._identify_role_of_address()
    assert c.address_inspected == {} and V1 in c.address_to_be_inspected and "role" not in c.address_to_be_inspected[V1]
    assert len(agent.prompts) <= 3


@pytest.mark.parametrize("reply", ["This address looks like a lending pool.", "lending, stablecoin", "42", '{"role": "lending"}',
                                   HOSTILE, f"[{HOSTILE}]", "[]x"])
def test_an_unusable_role_reply_is_a_typed_failure_not_a_clean_classification(monkeypatch, reply):
    c, agent = classifier(monkeypatch, reply)
    with pytest.raises(ForensicsModelError) as err:
        c._identify_role_of_address()
    assert reply not in str(err.value)
    assert c.address_inspected == {} and "role" not in c.address_to_be_inspected[V1]
    assert len(agent.prompts) == 3 and PROBE not in os.environ


def test_a_well_formed_list_without_any_role_text_is_unusable_after_one_request(monkeypatch):
    c, agent = classifier(monkeypatch, "[1, 2]")
    with pytest.raises(ForensicsModelError):
        c._identify_role_of_address()
    assert c.address_inspected == {} and len(agent.prompts) == 1, "valid structure is not re-asked: the budget is not amplified"


def test_an_empty_role_list_leaves_the_address_unclassified_as_before(monkeypatch):
    c, _ = classifier(monkeypatch, "[]")
    c._identify_role_of_address()
    assert V1 in c.address_to_be_inspected and V1 not in c.address_inspected


def test_one_failing_address_does_not_leave_earlier_ones_unaccounted(monkeypatch):
    c, agent = classifier(monkeypatch, "['lending']", "not a list", addresses=(V1, V2))
    with pytest.raises(ForensicsModelError):
        c._identify_role_of_address()
    assert V1 in c.address_inspected and V2 not in c.address_inspected, "the failure is surfaced; nothing is faked for the failed address"
