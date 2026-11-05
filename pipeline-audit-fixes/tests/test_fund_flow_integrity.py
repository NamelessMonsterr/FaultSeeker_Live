"""Synthetic transfer/schema regressions with a controlled model boundary."""
from types import SimpleNamespace
import pytest
from decimal import Decimal
from faultseeker.forensics.fund_flow_analyzer import FundFlowAnalyzer
from faultseeker.prompts.forensics.fund_flow_prompts import FundFlowPrompts

A, B, C, TOKEN = ["0x" + digit * 40 for digit in "1234"]

def analyzer(answers):
    item = FundFlowAnalyzer.__new__(FundFlowAnalyzer)
    item.prompts = FundFlowPrompts()
    replies = iter(answers)
    item.agent = SimpleNamespace(query=lambda prompt: next(replies))
    item.potential_attacker = []
    item.potential_victim = []
    return item


def txn(sender=A, target=B, amount="2", token=TOKEN):
    return {"transaction_hash": "synthetic-" + sender, "address_info": {"from_address": sender, "to_address": [target]},
            "token_transfer": {"edges": [{"source": sender, "target": target, "label": f"{token} [TEST] ({amount})"}]}}


def test_reused_analyzer_does_not_leak_previous_roles():
    item = analyzer([[A], []])
    first = item.run(txn())
    second = item.run(txn(C, B))
    assert set(first["potential_attacker"]) == {A, B}
    assert set(second["potential_attacker"]) == {C, B}
    assert second["potential_victim"] == []
    assert A not in second["balance_change"]

@pytest.mark.parametrize("amount", ["NaN", "Infinity", "-Infinity", "-2", "not-a-number"])
def test_invalid_amount_fails_instead_of_becoming_a_normal_partial_flow(amount):
    item = analyzer([[]])
    with pytest.raises(ValueError, match="transfer"):
        item.run(txn(amount=amount))


def test_transfer_from_token_contract_is_not_dropped():
    item = analyzer([[]])
    result = item.run(txn(TOKEN, B))
    assert Decimal(result["balance_change"][TOKEN][TOKEN]["amount"]) == -2
    assert Decimal(result["balance_change"][B][TOKEN]["amount"]) == 2


def test_mixed_case_addresses_share_one_balance_identity():
    source = "0x" + "aB" * 20
    target = "0x" + "cD" * 20
    result = analyzer([[]]).run(txn(source, target))
    assert source.lower() in result["balance_change"]
    assert target.lower() in result["balance_change"]

@pytest.mark.parametrize("reply", [{}, "none", [None], [7]])
def test_malformed_victim_response_is_not_silently_accepted(reply):
    with pytest.raises(ValueError, match="victim"):
        analyzer([reply]).run(txn())



def test_victim_json_object_envelope_supported_for_json_mode_models():
    result = analyzer([{ "victims": [A]}]).run(txn())
    assert result["potential_victim"] == [A]


@pytest.mark.parametrize("reply,valid", [({"victims": [A]}, True), ({"victims": "invalid"}, False)])
def test_real_fund_flow_factory_and_installed_sdk_json_mode_with_mock_http(monkeypatch, reply, valid):
    import json
    import httpx
    from openai import OpenAI
    from faultseeker.utils import agent as module
    requests = []
    def respond(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"id": "offline-mock", "object": "chat.completion", "created": 0,
            "model": "gpt-4o-mini", "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(reply)}}]})
    with httpx.Client(transport=httpx.MockTransport(respond)) as transport:
        client = OpenAI(api_key="dummy-offline-only", base_url="https://model.invalid/v1", http_client=transport, max_retries=0)
        monkeypatch.setenv("OPENAI_API_KEY", "dummy-offline-only")
        monkeypatch.setattr(module, "OpenAI", lambda **kwargs: client)
        item = FundFlowAnalyzer(model="gpt-4o-mini")
        if valid:
            result = item.run(txn())
            assert result["potential_victim"] == [A]
        else:
            with pytest.raises(ValueError, match="victim"):
                item.run(txn())
        assert len(requests) == 1
        assert requests[0]["response_format"] == {"type": "json_object"}
        assert '"victims"' in requests[0]["messages"][-1]["content"]



def test_transfer_arithmetic_preserves_small_change_beside_large_amount():
    from decimal import Decimal
    data = txn(amount="100000000000000000000")
    data["token_transfer"]["edges"].append({"source": B, "target": A, "label": f"{TOKEN} [TEST] (1)"})
    result = analyzer([[]]).run(data)
    amount = result["balance_change"][A][TOKEN]["amount"]
    assert Decimal(str(amount)) == Decimal("-99999999999999999999")
    assert isinstance(amount, str), "Exact token quantities serialize as decimal strings"
