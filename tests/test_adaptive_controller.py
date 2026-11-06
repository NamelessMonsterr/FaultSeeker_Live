from faultseeker.forensics.adaptive_controller import AdaptiveFailureAwareController
from faultseeker.forensics.result import ForensicsResult


def _empty_functions():
    return {
        "flashloan_callback": [],
        "function_name_with_hash": [],
        "function_name_with_hash_children": [],
        "call_with_created_contract": [],
        "others": [],
    }


def test_adaptive_controller_expands_empty_function_set_from_trace_graph():
    controller = AdaptiveFailureAwareController()
    functions = _empty_functions()
    tx_analysis = {
        "trace": {
            "type": "call",
            "call_type": "call",
            "address": "0xVictim",
            "function": "withdraw",
            "value": "0x0",
            "children": [
                {
                    "type": "delegatecall",
                    "call_type": "delegatecall",
                    "address": "0xImpl",
                    "function": "withdrawImpl",
                    "children": [],
                },
                {
                    "type": "call",
                    "call_type": "staticcall",
                    "address": "0xOracle",
                    "function": "latestAnswer",
                    "children": [],
                },
            ],
        }
    }

    decision = controller.apply(
        functions,
        tx_analysis,
        {"address_to_be_inspected": {"0ximpl": {}}},
    )

    assert decision["activated"] is True
    assert decision["trigger"] == "functions_to_inspect_count == 0"
    assert "graph_expansion" in decision["modes"]
    assert decision["algorithm_decision"]["algorithm"] == "FAEGL"
    assert decision["algorithm_decision"]["failure_severity"] > 0
    assert decision["functions_added"] == 2
    assert functions["others"][0]["proxy_unwrapped"] is True
    assert functions["others"][0]["_adaptive_algorithm"] == "FAEGL-v1.0"
    assert functions["others"][0]["_faegl_score"] >= functions["others"][1]["_faegl_score"]
    assert all(item.get("_adaptive_fallback") is True for item in functions["others"])


def test_adaptive_controller_does_not_change_existing_candidates():
    controller = AdaptiveFailureAwareController()
    functions = _empty_functions()
    functions["others"].append({"address": "0xExisting", "function": "swap"})

    decision = controller.apply(functions, {"trace": {}}, {})

    assert decision["activated"] is False
    assert decision["before_count"] == 1
    assert decision["after_count"] == 1
    assert functions["others"] == [{"address": "0xExisting", "function": "swap"}]


def test_forensics_result_serializes_adaptive_fallback_metadata():
    result = ForensicsResult(
        transaction_hash="0x" + "1" * 64,
        chain="eth",
        adaptive_fallback={"activated": True, "functions_added": 3},
    )

    data = result.to_dict()
    loaded = ForensicsResult.from_json_dict(data)

    assert data["function_analysis"]["adaptive_fallback"]["activated"] is True
    assert loaded.adaptive_fallback["functions_added"] == 3
