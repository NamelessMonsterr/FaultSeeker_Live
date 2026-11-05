from faultseeker.forensics.signal_extractor import SignalExtractor


def _addr(byte: str) -> str:
    return "0x" + byte * 40


def _word(num: int) -> str:
    return "0x" + format(num, "064x")


def _call(caller: str, callee: str, selector: str, depth: int, call_id: str, call_type: str = "CALL", children=None):
    return {
        "call_id": call_id,
        "depth": depth,
        "caller": caller,
        "callee": callee,
        "function_selector": selector,
        "input": selector + "00" * 4 if selector != "0x" else "0x",
        "value": "0x0",
        "gas": 0,
        "call_type": call_type,
        "success": True,
        "return_data": "0x",
        "children": children or [],
    }


def _write(
    address: str,
    slot: int,
    depth: int,
    event_index: int,
    pc: int,
    after_external_call: bool,
    value_after: int,
    value_before: int | None = None,
):
    return {
        "address": address,
        "slot": _word(slot),
        "value_before": _word(value_before) if value_before is not None else None,
        "value_after": _word(value_after),
        "pc": pc,
        "depth": depth,
        "event_index": event_index,
        "after_external_call": after_external_call,
    }


def _run(canonical_trace: dict, storage_events: list[dict], txn_hash: str) -> dict:
    extractor = SignalExtractor(
        txn_seq={"created_address": []},
        tx_analysis={
            "trace": {},
            "flatten_trace": [],
            "canonical_trace": canonical_trace,
            "storage_events": storage_events,
            "repeated_patterns": {},
        },
        txn_hash=txn_hash,
        chain="eth",
    )
    return extractor.run().raw


def test_classic_withdraw_scores_high():
    vault = _addr("1")
    attacker = _addr("2")

    canonical_trace = _call(
        caller=_addr("a"),
        callee=vault,
        selector="0xdeadbeef",
        depth=0,
        call_id="0",
        children=[
            _call(
                caller=vault,
                callee=attacker,
                selector="0x",
                depth=1,
                call_id="0.0",
                children=[
                    _call(
                        caller=attacker,
                        callee=vault,
                        selector="0xdeadbeef",
                        depth=2,
                        call_id="0.0.0",
                    )
                ],
            )
        ],
    )

    raw = _run(
        canonical_trace,
        [
            _write(vault, slot=1, depth=1, event_index=0, pc=100, after_external_call=False, value_after=10),
            _write(vault, slot=1, depth=3, event_index=1, pc=101, after_external_call=False, value_after=9),
            _write(vault, slot=1, depth=1, event_index=2, pc=102, after_external_call=True, value_after=0),
        ],
        txn_hash="0x" + "f" * 64,
    )

    assert raw["reentrancy_score"] >= 0.75
    assert raw["reentrancy_detected"] is True
    assert raw["reentrancy_confidence_tier"] == "CONFIRMED_REENTRANCY"
    assert raw["reentrancy"]["detected"] is True
    assert raw["reentrancy"]["tier"] == "CONFIRMED_REENTRANCY"
    assert raw["reentrancy"]["signals"]["state_slot_reentry"] is True
    assert raw["reentrancy"]["context"]["storage_trace_available"] is True
    assert raw["reentrancy_signals"]["state_slot_reentry"] is True
    assert raw["reentrancy_context"]["storage_trace_available"] is True
    assert raw["debug"]["state_reentry"] is True
    assert raw["debug"]["same_function_reentered"] is True


def test_no_state_trace_fallback_scores_recursive_call_graph_high():
    vault = _addr("f")
    attacker = _addr("1")

    canonical_trace = _call(
        caller=_addr("0"),
        callee=vault,
        selector="0xdeadbeef",
        depth=0,
        call_id="0",
        children=[
            _call(
                caller=vault,
                callee=attacker,
                selector="0x",
                depth=1,
                call_id="0.0",
                children=[
                    _call(
                        caller=attacker,
                        callee=vault,
                        selector="0xdeadbeef",
                        depth=2,
                        call_id="0.0.0",
                    )
                ],
            )
        ],
    )

    raw = _run(canonical_trace, [], txn_hash="0x" + "a1" * 32)

    assert raw["reentrancy_score"] >= 0.75
    assert raw["reentrancy_detected"] is True
    assert raw["reentrancy_context"]["fallback_mode"] is True
    assert raw["reentrancy_context"]["storage_trace_available"] is False
    assert raw["reentrancy_signals"]["reentry_before_return"] is True
    assert raw["debug"]["external_call_chain"] is True
    assert raw["debug"]["detection_threshold"] == 0.65


def test_cross_function_reentry_scores_high_without_state_trace():
    vault = _addr("2")
    attacker = _addr("3")

    canonical_trace = _call(
        caller=_addr("1"),
        callee=vault,
        selector="0xaaaaaaaa",
        depth=0,
        call_id="0",
        children=[
            _call(
                caller=vault,
                callee=attacker,
                selector="0x",
                depth=1,
                call_id="0.0",
                children=[
                    _call(
                        caller=attacker,
                        callee=vault,
                        selector="0xbbbbbbbb",
                        depth=2,
                        call_id="0.0.0",
                    )
                ],
            )
        ],
    )

    raw = _run(canonical_trace, [], txn_hash="0x" + "a2" * 32)

    assert raw["reentrancy_score"] >= 0.675
    assert raw["reentrancy_detected"] is True
    assert raw["reentrancy_confidence_tier"] == "POSSIBLE_REENTRANCY"
    assert raw["reentrancy_signals"]["cross_function_reentry"] is True
    assert raw["debug"]["same_contract_different_selector"] is True
    assert raw["debug"]["same_function_reentered"] is False


def test_fallback_score_is_hard_capped():
    vault = _addr("4")
    attacker = _addr("5")

    canonical_trace = _call(
        caller=_addr("6"),
        callee=vault,
        selector="0xaaaaaaaa",
        depth=0,
        call_id="0",
        children=[
            _call(
                caller=vault,
                callee=attacker,
                selector="0x",
                depth=1,
                call_id="0.0",
                children=[
                    _call(
                        caller=attacker,
                        callee=vault,
                        selector="0xbbbbbbbb",
                        depth=2,
                        call_id="0.0.0",
                        children=[
                            _call(
                                caller=vault,
                                callee=attacker,
                                selector="0x",
                                depth=3,
                                call_id="0.0.0.0",
                                children=[
                                    _call(
                                        caller=attacker,
                                        callee=vault,
                                        selector="0xaaaaaaaa",
                                        depth=4,
                                        call_id="0.0.0.0.0",
                                    )
                                ],
                            )
                        ],
                    )
                ],
            )
        ],
    )

    raw = _run(canonical_trace, [], txn_hash="0x" + "a7" * 32)

    assert raw["reentrancy_score"] == 0.8
    assert raw["reentrancy_detected"] is True
    assert raw["reentrancy_confidence_tier"] == "HIGH_RISK_REENTRANCY"
    assert raw["debug"]["same_function_reentered"] is True
    assert raw["debug"]["same_contract_different_selector"] is True


def test_checks_effects_interactions_safe_pattern_scores_low():
    vault = _addr("3")
    attacker = _addr("4")

    canonical_trace = _call(
        caller=_addr("b"),
        callee=vault,
        selector="0xdeadbeef",
        depth=0,
        call_id="0",
        children=[_call(caller=vault, callee=attacker, selector="0x", depth=1, call_id="0.0")],
    )

    raw = _run(
        canonical_trace,
        [
            _write(vault, slot=7, depth=1, event_index=0, pc=200, after_external_call=False, value_after=1),
        ],
        txn_hash="0x" + "e" * 64,
    )

    assert raw["reentrancy_score"] < 0.45
    assert raw["reentrancy_detected"] is False
    assert raw["debug"]["state_changes_after_call"] is False


def test_staticcall_only_recursion_stays_low():
    vault = _addr("a")
    oracle = _addr("b")

    canonical_trace = _call(
        caller=_addr("c"),
        callee=vault,
        selector="0x11111111",
        depth=0,
        call_id="0",
        children=[
            _call(
                caller=vault,
                callee=oracle,
                selector="0x22222222",
                depth=1,
                call_id="0.0",
                call_type="STATICCALL",
                children=[
                    _call(
                        caller=oracle,
                        callee=vault,
                        selector="0x11111111",
                        depth=2,
                        call_id="0.0.0",
                        call_type="STATICCALL",
                    )
                ],
            )
        ],
    )

    raw = _run(canonical_trace, [], txn_hash="0x" + "a3" * 32)

    assert raw["reentrancy_score"] < 0.65
    assert raw["reentrancy_detected"] is False
    assert raw["debug"]["external_call_chain"] is False


def test_multicall_style_same_contract_batching_stays_low():
    vault = _addr("d")

    canonical_trace = _call(
        caller=_addr("e"),
        callee=vault,
        selector="0xaaaaaaaa",
        depth=0,
        call_id="0",
        children=[
            _call(
                caller=vault,
                callee=vault,
                selector="0xbbbbbbbb",
                depth=1,
                call_id="0.0",
                call_type="DELEGATECALL",
                children=[
                    _call(
                        caller=vault,
                        callee=vault,
                        selector="0xcccccccc",
                        depth=2,
                        call_id="0.0.0",
                        call_type="DELEGATECALL",
                    )
                ],
            )
        ],
    )

    raw = _run(canonical_trace, [], txn_hash="0x" + "a6" * 32)

    assert raw["reentrancy_score"] < 0.65
    assert raw["reentrancy_detected"] is False
    assert raw["debug"]["same_contract_different_selector"] is False


def test_reentrant_fallback_scores_high():
    vault = _addr("5")
    attacker = _addr("6")

    canonical_trace = _call(
        caller=_addr("c"),
        callee=vault,
        selector="0xaaaaaaaa",
        depth=0,
        call_id="0",
        children=[
            _call(
                caller=vault,
                callee=attacker,
                selector="0x",
                depth=1,
                call_id="0.0",
                children=[
                    _call(
                        caller=attacker,
                        callee=vault,
                        selector="0xaaaaaaaa",
                        depth=2,
                        call_id="0.0.0",
                    )
                ],
            )
        ],
    )

    raw = _run(
        canonical_trace,
        [
            _write(vault, slot=9, depth=1, event_index=0, pc=300, after_external_call=False, value_after=5),
            _write(vault, slot=9, depth=3, event_index=1, pc=301, after_external_call=False, value_after=4),
            _write(vault, slot=9, depth=1, event_index=2, pc=302, after_external_call=True, value_after=0),
        ],
        txn_hash="0x" + "d" * 64,
    )

    assert raw["reentrancy_score"] >= 0.75
    assert raw["reentrancy_detected"] is True
    assert raw["debug"]["same_slot_rewritten"] is True


def test_delegatecall_proxy_scores_medium_but_not_high_confidence():
    proxy = _addr("7")
    library = _addr("8")

    canonical_trace = _call(
        caller=_addr("d"),
        callee=proxy,
        selector="0xbbbbbbbb",
        depth=0,
        call_id="0",
        children=[
            _call(
                caller=proxy,
                callee=library,
                selector="0xcccccccc",
                depth=1,
                call_id="0.0",
                call_type="DELEGATECALL",
            )
        ],
    )

    raw = _run(
        canonical_trace,
        [
            _write(proxy, slot=12, depth=1, event_index=0, pc=400, after_external_call=True, value_after=2),
        ],
        txn_hash="0x" + "c" * 64,
    )

    assert 0.25 <= raw["reentrancy_score"] < 0.45
    assert raw["reentrancy_detected"] is False
    assert raw["debug"]["state_changes_after_call"] is True


def test_plain_proxy_delegatecall_without_callback_stays_low():
    proxy = _addr("4")
    implementation = _addr("5")

    canonical_trace = _call(
        caller=_addr("6"),
        callee=proxy,
        selector="0xbbbbbbbb",
        depth=0,
        call_id="0",
        children=[
            _call(
                caller=proxy,
                callee=implementation,
                selector="0xbbbbbbbb",
                depth=1,
                call_id="0.0",
                call_type="DELEGATECALL",
            )
        ],
    )

    raw = _run(canonical_trace, [], txn_hash="0x" + "81" * 32)

    assert raw["reentrancy_score"] < 0.45
    assert raw["reentrancy_detected"] is False
    assert raw["debug"]["same_function_reentered"] is False
    assert raw["debug"]["nested_depth_reentry"] is False


def test_delegatecall_effective_address_normalization_survives_no_state_trace():
    proxy = _addr("7")
    implementation = _addr("8")
    attacker = _addr("9")

    canonical_trace = _call(
        caller=_addr("d"),
        callee=proxy,
        selector="0xbbbbbbbb",
        depth=0,
        call_id="0",
        children=[
            _call(
                caller=proxy,
                callee=implementation,
                selector="0xbbbbbbbb",
                depth=1,
                call_id="0.0",
                call_type="DELEGATECALL",
                children=[
                    _call(
                        caller=proxy,
                        callee=attacker,
                        selector="0x",
                        depth=2,
                        call_id="0.0.0",
                        children=[
                            _call(
                                caller=attacker,
                                callee=proxy,
                                selector="0xbbbbbbbb",
                                depth=3,
                                call_id="0.0.0.0",
                                children=[
                                    _call(
                                        caller=proxy,
                                        callee=implementation,
                                        selector="0xbbbbbbbb",
                                        depth=4,
                                        call_id="0.0.0.0.0",
                                        call_type="DELEGATECALL",
                                    )
                                ],
                            )
                        ],
                    )
                ],
            )
        ],
    )

    raw = _run(canonical_trace, [], txn_hash="0x" + "91" * 32)

    assert raw["reentrancy_score"] >= 0.75
    assert raw["reentrancy_detected"] is True
    assert raw["debug"]["same_function_reentered"] is True
    assert raw["reentrancy_signals"]["reentry_before_return"] is True


def test_nested_delegatecall_root_storage_context_survives_reentry():
    proxy = _addr("d")
    impl = _addr("e")
    lib = _addr("f")
    attacker = _addr("1")

    canonical_trace = _call(
        caller=_addr("2"),
        callee=proxy,
        selector="0xcccccccc",
        depth=0,
        call_id="0",
        children=[
            _call(
                caller=proxy,
                callee=impl,
                selector="0xcccccccc",
                depth=1,
                call_id="0.0",
                call_type="DELEGATECALL",
                children=[
                    _call(
                        caller=proxy,
                        callee=lib,
                        selector="0xcccccccc",
                        depth=2,
                        call_id="0.0.0",
                        call_type="DELEGATECALL",
                        children=[
                            _call(
                                caller=proxy,
                                callee=attacker,
                                selector="0x",
                                depth=3,
                                call_id="0.0.0.0",
                                children=[
                                    _call(
                                        caller=attacker,
                                        callee=proxy,
                                        selector="0xdddddddd",
                                        depth=4,
                                        call_id="0.0.0.0.0",
                                    )
                                ],
                            )
                        ],
                    )
                ],
            )
        ],
    )

    raw = _run(canonical_trace, [], txn_hash="0x" + "a4" * 32)

    assert raw["reentrancy_score"] >= 0.675
    assert raw["reentrancy_detected"] is True
    assert raw["debug"]["same_contract_different_selector"] is True


def test_mutex_guard_slot_is_filtered():
    vault = _addr("9")
    attacker = _addr("a")

    canonical_trace = _call(
        caller=_addr("e"),
        callee=vault,
        selector="0xdddddddd",
        depth=0,
        call_id="0",
        children=[_call(caller=vault, callee=attacker, selector="0x", depth=1, call_id="0.0")],
    )

    raw = _run(
        canonical_trace,
        [
            _write(vault, slot=99, depth=1, event_index=0, pc=500, after_external_call=False, value_after=2, value_before=1),
            _write(vault, slot=99, depth=1, event_index=1, pc=501, after_external_call=True, value_after=1, value_before=2),
            _write(vault, slot=7, depth=1, event_index=2, pc=502, after_external_call=False, value_after=3),
        ],
        txn_hash="0x" + "b" * 64,
    )

    assert raw["reentrancy_score"] < 0.45
    assert raw["reentrancy_detected"] is False
    assert raw["debug"]["guard_slots_filtered"] >= 1


def test_same_pc_loop_writes_are_deduped():
    vault = _addr("c")

    canonical_trace = _call(
        caller=_addr("e"),
        callee=vault,
        selector="0xeeeeeeee",
        depth=0,
        call_id="0",
    )

    raw = _run(
        canonical_trace,
        [
            _write(vault, slot=5, depth=1, event_index=0, pc=600, after_external_call=False, value_after=1),
            _write(vault, slot=5, depth=1, event_index=1, pc=600, after_external_call=False, value_after=1),
            _write(vault, slot=5, depth=1, event_index=2, pc=600, after_external_call=False, value_after=1),
        ],
        txn_hash="0x" + "92" * 32,
    )

    assert raw["reentrancy_score"] < 0.45
    assert raw["reentrancy_detected"] is False
    assert raw["debug"]["same_slot_rewritten"] is False


def test_same_pc_same_call_id_loop_writes_are_deduped():
    vault = _addr("7")

    canonical_trace = _call(
        caller=_addr("8"),
        callee=vault,
        selector="0xffffffff",
        depth=0,
        call_id="0",
    )

    raw = _run(
        canonical_trace,
        [
            {**_write(vault, slot=6, depth=1, event_index=0, pc=700, after_external_call=False, value_after=1), "call_id": "0.0"},
            {**_write(vault, slot=6, depth=2, event_index=1, pc=700, after_external_call=False, value_after=1), "call_id": "0.0"},
        ],
        txn_hash="0x" + "a5" * 32,
    )

    assert raw["reentrancy_score"] < 0.45
    assert raw["reentrancy_detected"] is False
    assert raw["debug"]["same_slot_rewritten"] is False
