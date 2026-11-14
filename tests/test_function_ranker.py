from types import SimpleNamespace

import pytest

from faultseeker.function_analysis.function_ranker import FunctionRanker


def _ranker_input(calls):
    """Build the minimal Stage 1 / transaction-analysis shape consumed by rank()."""
    return (
        SimpleNamespace(
            address_calls_with_created_contract=[],
            functions_to_be_inspected={"calls": calls},
        ),
        {
            "repeated_patterns": {},
            "function_call_loc_memo": {},
        },
    )


def _call(function, address, depth):
    return {
        "function": function,
        "address": address,
        "depth": depth,
        "gas": 1,
        "params": "",
    }


def test_rank_deduplicates_address_prefix_and_case_variants():
    address_hex = "a" * 40
    prefixed_mixed_case = "0x" + "A" * 40
    unprefixed_lower_case = "a" * 40

    forensics, tx_analysis = _ranker_input([
        _call("customAction", prefixed_mixed_case, [1]),
        _call("customAction", unprefixed_lower_case, [2]),
    ])

    result = FunctionRanker().rank(forensics, tx_analysis)

    expected_key = f"customAction_0x{address_hex}"
    assert list(result.functions_to_be_inspected) == [expected_key]
    assert result.functions_to_be_inspected[expected_key]["count"] == 2
    assert len(result.functions_to_be_inspected[expected_key]["calls"]) == 2
    assert result.address_list == [f"0x{address_hex}"]


def test_rank_preserves_case_sensitive_function_names():
    address = "0x" + "b" * 40
    forensics, tx_analysis = _ranker_input([
        _call("customAction", address, [1]),
        _call("CustomAction", address.upper().replace("0X", "0x"), [2]),
    ])

    result = FunctionRanker().rank(forensics, tx_analysis)

    assert set(result.functions_to_be_inspected) == {
        f"customAction_{address}",
        f"CustomAction_{address}",
    }
    assert all(item["count"] == 1 for item in result.functions_to_be_inspected.values())


def test_rank_canonicalizes_fallback_keys_too():
    address_hex = "c" * 40
    forensics, tx_analysis = _ranker_input([])
    tx_analysis["function_call_loc_memo"] = {
        f"customAction::0x{'C' * 40}": [
            {"gas": 1, "params": "", "depth": [1]},
        ],
        f"customAction::{address_hex}": [
            {"gas": 2, "params": "", "depth": [2]},
        ],
    }

    result = FunctionRanker().rank(forensics, tx_analysis)

    expected_key = f"customAction_0x{address_hex}"
    assert list(result.functions_to_be_inspected) == [expected_key]
    assert result.functions_to_be_inspected[expected_key]["count"] == 2
    assert len(result.functions_to_be_inspected[expected_key]["calls"]) == 2
    assert result.address_list == [expected_key.rsplit("_", 1)[1]]
