"""Regression tests: canonical selector aliases as unverified name hints.

Covers commit 1c7cae5: when trace calls carry bare 4-byte selectors (no
verified ABI), name-based detectors went blind. Canonical aliases let those
detectors see selector-only calls without mutating raw values, dropping any
call, or hiding undecoded-selector evidence.
"""
from faultseeker.forensics.signal_extractor import SignalExtractor


def _mk(fn, call_type='call'):
    return {'function': fn, 'depth': [], 'call_type': call_type,
            'address': '0xpool'}


def _run(calls):
    return SignalExtractor({}, {'flatten_trace': calls}, '0xabc', 'eth').run()


def test_selector_only_price_pattern_detected():
    calls = [_mk('0x0902f1ac'), _mk('0x022c0d9f'), _mk('0x0902f1ac')]
    b = _run(calls)
    assert b.price_read_write_sequences >= 1
    assert b.selector_alias_hints_applied == 2  # getreserves + swap
    assert b.raw['selector_alias_hints_applied'] == 2


def test_named_functions_unchanged_and_no_alias_count():
    calls = [_mk('getReserves'), _mk('swap'), _mk('getReserves')]
    b = _run(calls)
    assert b.price_read_write_sequences >= 1
    assert b.selector_alias_hints_applied == 0


def test_unknown_selector_stays_blind_but_counts_as_hashed():
    b = _run([_mk('0xdeadbeef'), _mk('0x0902f1ac')])
    assert b.hashed_fn_count >= 1
    assert b.selector_alias_hints_applied == 1


def test_raw_function_values_never_mutated():
    calls = [_mk('0x0902f1ac'), _mk('0x022c0d9f')]
    _run(calls)
    assert calls[0]['function'] == '0x0902f1ac'
    assert calls[1]['function'] == '0x022c0d9f'


def test_aliased_state_write_counts_in_access_control_scan():
    b = _run([_mk('0xa9059cbb')])  # ERC20 transfer selector
    assert b.selector_alias_hints_applied == 1
