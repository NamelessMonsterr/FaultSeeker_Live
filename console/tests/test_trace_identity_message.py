import pytest

from app.trace_identity import TraceIdentityError, check_structured

TX = "0x" + "1" * 64


def test_missing_trace_reports_rpc_problem_not_cache_mismatch():
    with pytest.raises(TraceIdentityError) as info:
        check_structured(None, TX, "eth")
    message = str(info.value)
    assert "debug_traceTransaction" in message
    assert "different transaction or chain" not in message


def test_wrong_transaction_still_reports_identity_mismatch():
    payload = {"transaction_hash": "0x" + "2" * 64, "chain": "eth", "trace": {}}
    with pytest.raises(TraceIdentityError, match="different transaction or chain"):
        check_structured(payload, TX, "eth")


def test_matching_payload_is_returned_unchanged():
    payload = {"transaction_hash": TX.upper().replace("0X", "0x"), "chain": "ETH", "trace": {"callee": "0x"}}
    assert check_structured(payload, TX, "eth") is payload
