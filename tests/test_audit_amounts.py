"""Audit F09 (unknown decimals / historical metadata) and F10 (exact fund-flow arithmetic). OFFLINE: local fake node only."""
import json
from decimal import Decimal

import pytest

try:
    from faultseeker.data_collection import rpc_client, rpc_collector
    from faultseeker.data_collection.rpc_client import RpcClient
    from faultseeker.forensics.fund_flow_analyzer import FundFlowAnalyzer
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

from tests.fake_rpc import FakeServer, FROM, POOL, TOKEN, TX

RAW = 1_234_567_890


@pytest.fixture()
def node(monkeypatch):
    s = FakeServer()
    monkeypatch.setattr(rpc_client, "RETRY_DELAYS", (0, 0))
    yield s
    s.close()


def edges(info):
    return [e["label"] for e in info["token_transfer"]["edges"]]


def collect(node):
    return rpc_collector.collect(RpcClient(node.http), TX, "eth")


# ------------------------------------------------------------------------------------------------ F09

def test_known_decimals_still_render_the_human_amount(node):
    labels = edges(collect(node))
    assert f"{TOKEN} [USDC] (1,234.56789)" in labels and f"{TOKEN} [USDC] (0.000005)" in labels


def test_unknown_decimals_are_never_displayed_as_a_zero_decimal_amount(node):
    node.token_decimals_fail = True
    labels = edges(collect(node))
    big = [l for l in labels if l.startswith(TOKEN) and "1,234,567,890" in l]
    assert big and "raw units" in big[0] and "decimals unknown" in big[0], labels
    assert not any(l.endswith("(1,234,567,890)") for l in labels), "a bare human-looking amount would claim decimals=0"


def test_the_transfer_record_keeps_the_raw_integer_and_the_decimals_status_separately(node):
    node.token_decimals_fail = True
    info = collect(node)
    t = next(x for x in info["transfers"] if x["token"] == TOKEN and x["raw_amount"] == str(RAW))
    assert t["decimals"] is None and t["decimals_known"] is False and t["amount"] != "1,234,567,890"
    node.token_decimals_fail = False
    t2 = next(x for x in collect(node)["transfers"] if x["token"] == TOKEN and x["raw_amount"] == str(RAW))
    assert t2["decimals"] == 6 and t2["decimals_known"] is True and t2["amount"] == "1,234.56789"


def test_zero_decimals_are_a_known_value_distinct_from_unknown():
    class Zero:
        def get(self, token):
            return {"symbol": "NFTISH", "decimals": 0, "metadata_block": "historical"}
    log = {"address": TOKEN, "topics": [rpc_collector.TRANSFER, "0x" + "0" * 24 + FROM[2:], "0x" + "0" * 24 + POOL[2:]],
           "data": "0x" + format(RAW, "064x")}
    [t] = rpc_collector._transfers([log], Zero())
    assert t["decimals"] == 0 and t["decimals_known"] is True and t["amount"] == "1,234,567,890"


def test_token_metadata_is_read_at_the_transaction_block_not_latest(node):
    collect(node)
    assert node.eth_call_blocks and set(node.eth_call_blocks) == {"0x64"}, node.eth_call_blocks


def test_a_latest_block_fallback_is_used_only_when_history_is_missing_and_is_labelled(node):
    node.historical_calls_fail = True
    info = collect(node)
    assert set(node.eth_call_blocks) >= {"0x64", "latest"}
    t = next(x for x in info["transfers"] if x["token"] == TOKEN and x["raw_amount"] == str(RAW))
    assert t["decimals"] == 6 and t["metadata_block"] == "latest"
    label = next(l for l in edges(info) if l.startswith(TOKEN) and "1,234.56789" in l)
    assert "latest-block decimals" in label


def test_the_token_lookup_cap_yields_unknown_not_zero_decimals(node, monkeypatch):
    monkeypatch.setattr(rpc_collector, "MAX_TOKENS_LOOKED_UP", 0)
    labels = edges(collect(node))
    assert any("raw units" in l and "decimals unknown" in l for l in labels if l.startswith(TOKEN))


def test_labels_stay_parseable_by_the_existing_split_rules(node):
    node.token_decimals_fail = True
    for label in edges(collect(node)):
        assert label.count("[") == 1 and label.count("]") == 1 and label.count("(") == 1 and label.count(")") == 1, label


# ------------------------------------------------------------------------------------------------ F10

def flow(*labels):
    f = object.__new__(FundFlowAnalyzer)
    f.txn_info = {"token_transfer": {"edges": [{"source": s, "target": t, "label": l} for s, t, l in labels]}}
    f._get_balance_change()
    return f.balance_change


A, B, C = "0x" + "a1" * 20, "0x" + "b2" * 20, "0x" + "c3" * 20


def test_values_above_two_to_the_53_keep_their_exact_integer_value():
    bc = flow((A, B, f"{TOKEN} [T] (9,007,199,254,740,993)"))
    assert bc[B][TOKEN]["amount"] == "9007199254740993" and bc[A][TOKEN]["amount"] == "-9007199254740993"
    assert "9007199254740993" in json.dumps(bc), "JSON keeps the exact value"


def test_tiny_fractions_and_near_cancelling_transfers_are_exact():
    bc = flow((A, B, f"{TOKEN} [T] (0.1)"), (A, B, f"{TOKEN} [T] (0.2)"), (B, C, f"{TOKEN} [T] (0.3)"))
    assert Decimal(bc[B][TOKEN]["amount"]) == 0, "0.1 + 0.2 - 0.3 is exactly zero, not 5.55e-17"
    bc = flow((A, B, f"{TOKEN} [T] (0.000000000000000001)"))
    assert Decimal(bc[B][TOKEN]["amount"]) == Decimal("0.000000000000000001")


def test_very_large_totals_and_multiple_tokens_do_not_mix():
    other = "0x" + "dd" * 20
    big = "9" * 60
    bc = flow((A, B, f"{TOKEN} [T] ({big})"), (A, B, f"{TOKEN} [T] (1)"), (A, B, f"{other} [U] (5)"))
    assert Decimal(bc[B][TOKEN]["amount"]) == Decimal(big) + 1 and Decimal(bc[B][other]["amount"]) == 5


def test_raw_unit_amounts_stay_exact_and_are_flagged_as_not_human_amounts():
    bc = flow((A, B, f"{TOKEN} [T] (9,007,199,254,740,993 raw units, decimals unknown)"), (B, C, f"{TOKEN} [T] (1 raw units, decimals unknown)"))
    assert bc[B][TOKEN]["amount"] == "9007199254740992" and bc[B][TOKEN]["unit"] == "raw units (decimals unknown)"
    assert bc[C][TOKEN]["unit"] == "raw units (decimals unknown)"
    known = flow((A, B, f"{TOKEN} [T] (5)"))
    assert known[B][TOKEN]["unit"] == "token units"


def test_a_label_whose_amount_cannot_be_read_is_not_summed_as_zero():
    with pytest.raises(ValueError, match="amount"):
        flow((A, B, f"{TOKEN} [T] (lots)"))


def test_the_existing_two_decimal_scenario_is_preserved(node):
    f = object.__new__(FundFlowAnalyzer)
    f.txn_info = collect(node)
    f._get_balance_change()
    assert Decimal(f.balance_change[FROM][TOKEN]["amount"]) == Decimal("-1234.56789") + Decimal("0.000005")
