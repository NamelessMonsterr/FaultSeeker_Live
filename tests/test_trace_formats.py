"""One transaction, many ways cast can print it: identity and classification must not depend on the format.

OFFLINE FIXTURES: tests/fixtures/cast_traces.json holds REAL `cast run` output captured from Foundry 1.4.4, 1.5.1 and 1.9.0
against a local anvil chain, once with an empty signature cache ("cold") and once with a warm one ("warm", which is what
produces `foo(7)` instead of `2fbebd38(...)`). No Foundry binary or network is needed to run this file.
"""
import json
from pathlib import Path

import pytest

from faultseeker.data_collection.trace_parser import TraceParser
from faultseeker.utils import selectors

try:
    from faultseeker.forensics.trace_analyzer import TraceAnalyzer
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "cast_traces.json").read_text())
VERSIONS = sorted(FIXTURES["versions"])
COVERED = ["erc20_transfer", "univ2_callback", "univ2_swap", "erc3156_flashloan", "nested_flashloan"]   # in the bundled table
UNKNOWN = ["unknown_foo", "nested_unknown_foo"]
CONDITIONS = ("cold", "warm")


def parse(version, condition, name):
    return TraceParser().parse(FIXTURES["versions"][version]["traces"][condition][name])


@pytest.fixture(autouse=True)
def analyzer_env(monkeypatch):
    monkeypatch.setenv("FAULTSEEKER_ISOLATED_RUN", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-offline")


def classify(version, condition, names):
    """The analyzer's own classification of the given calls, placed under one root, exactly as in a real trace."""
    kids = [parse(version, condition, n).to_dict() for n in names]
    root = {"type": "call", "gas": 1, "address": "0x" + "11" * 20, "function": "run", "params": "", "call_type": "call",
            "value": None, "contract_type": None, "selector": None, "children": kids}
    seq = {"trace": root, "transaction_hash": "0x" + "1" * 64, "chain": "eth", "address_relation": {}, "created_address": []}
    loc = TraceAnalyzer(seq, {}, "gpt-4o-mini").run()["function_calls_to_expand_loc"]
    return {bucket: sorted((c["function"], tuple(c["depth"])) for c in calls) for bucket, calls in loc.items()}


def test_fixtures_cover_the_versions_named_in_the_report():
    assert VERSIONS == ["1.4.4", "1.5.1", "1.9.0"]
    for v in VERSIONS:
        assert set(FIXTURES["versions"][v]["traces"]) == set(CONDITIONS)
        assert set(FIXTURES["versions"][v]["traces"]["cold"]) == set(FIXTURES["calls"])


def test_the_reported_problem_is_present_in_the_real_output():
    """foo(7) vs 2fbebd38(...), and 1.9.0 decoding well-known selectors without any cache."""
    raw = FIXTURES["versions"]["1.4.4"]["traces"]["cold"]["unknown_foo"]
    decoded = FIXTURES["versions"]["1.4.4"]["traces"]["warm"]["unknown_foo"]
    assert "::2fbebd38(" in raw and "::foo(7)" in decoded
    assert "::a9059cbb(" in FIXTURES["versions"]["1.4.4"]["traces"]["cold"]["erc20_transfer"]
    assert "::transfer(" in FIXTURES["versions"]["1.9.0"]["traces"]["cold"]["erc20_transfer"]


@pytest.mark.parametrize("name", COVERED)
def test_known_functions_have_the_same_identity_in_every_format(name):
    seen = set()
    for v in VERSIONS:
        for c in CONDITIONS:
            node = parse(v, c, name)
            assert node is not None and node.type == "call"
            seen.add(node.function)
            assert not _is_bare_selector(node.function), f"{v}/{c}: {name} was left as a bare selector"
            expected = selectors.canonicalize(node.function)[1]
            if node.selector and expected:
                assert node.selector == expected
    assert len(seen) == 1, f"{name} got different identities: {seen}"


def _is_bare_selector(token):
    from faultseeker.utils.utils import is_function_hash
    return is_function_hash(token)


def test_decoded_and_raw_selectors_agree_where_a_selector_is_known():
    for v in VERSIONS:
        raw, dec = parse(v, "cold", "erc20_transfer"), parse(v, "warm", "erc20_transfer")
        assert (raw.function, raw.selector) == (dec.function, dec.selector) == ("transfer", "a9059cbb")
        raw, dec = parse(v, "cold", "univ2_callback"), parse(v, "warm", "univ2_callback")
        assert raw.function == dec.function == "uniswapV2Call" and raw.selector == dec.selector == "10d1e85c"


def test_nested_trace_structure_is_the_same_in_every_format():
    shapes = set()
    for v in VERSIONS:
        for c in CONDITIONS:
            root = parse(v, c, "nested_flashloan").to_dict()
            shapes.add(json.dumps(_shape(root)))
            assert root["function"] == "flashLoan" and root["children"][0]["function"] == "flashLoan"
            assert root["children"][0]["address"].lower() == FIXTURES["versions"][v]["contract"].lower()
            assert root["address"].lower() == FIXTURES["versions"][v]["proxy"].lower()
    assert len(shapes) == 1


def _shape(node):
    return [node["type"], node.get("function"), [_shape(c) for c in node["children"]]]


def test_classification_is_identical_across_versions_and_cache_states():
    results = {(v, c): classify(v, c, COVERED) for v in VERSIONS for c in CONDITIONS}
    reference = results[("1.4.4", "cold")]
    for key, got in results.items():
        assert got == reference, f"{key} classified differently"
    assert [f for f, _ in reference["flashloan"]].count("flashLoan") == 3          # direct, and proxy + its forwarded child
    assert {f for f, _ in reference["flashloan_callback"]} == {"uniswapV2Call", "swap"}
    assert reference["name_in_hash"] == [], "every covered call resolves to a name, in every format"


def test_without_the_identity_layer_the_formats_would_classify_differently(monkeypatch):
    """Sensitivity check: with an empty table the same traces diverge. This is the bug that was reported."""
    selectors._load.cache_clear()
    monkeypatch.setattr(selectors, "_load", lambda extra: ({}, {}))
    cold, warm = classify("1.4.4", "cold", COVERED), classify("1.4.4", "warm", COVERED)
    assert cold != warm
    assert cold["flashloan"] == [] and len(warm["flashloan"]) == 3
    assert len(cold["name_in_hash"]) >= 5 and warm["name_in_hash"] == []


def test_unknown_functions_still_differ_between_formats_and_that_is_documented():
    """A selector that is in neither the bundled table nor cast's own database cannot be named from `2fbebd38` alone."""
    for v in VERSIONS:
        cold, warm = classify(v, "cold", UNKNOWN), classify(v, "warm", UNKNOWN)
        assert [f for f, _ in cold["name_in_hash"]] == ["2fbebd38"] * 3      # the direct call, plus the proxy and its forwarded child
        assert warm["name_in_hash"] == []
        assert parse(v, "cold", "unknown_foo").function == "2fbebd38" and parse(v, "warm", "unknown_foo").function == "foo"


def test_adding_the_signature_makes_unknown_functions_equivalent_too(tmp_path, monkeypatch):
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps({"2fbebd38": "foo(uint256)"}))
    monkeypatch.setenv("FAULTSEEKER_SELECTOR_TABLE", str(extra))
    for v in VERSIONS:
        cold, warm = classify(v, "cold", UNKNOWN), classify(v, "warm", UNKNOWN)
        assert cold == warm and cold["name_in_hash"] == []
        a, b = parse(v, "cold", "unknown_foo"), parse(v, "warm", "unknown_foo")
        assert (a.function, a.selector) == (b.function, b.selector) == ("foo", "2fbebd38")


def test_hashed_name_check_is_about_bare_selectors_only():
    from faultseeker.utils.utils import is_function_hash
    assert is_function_hash("2fbebd38") and not is_function_hash("foo") and not is_function_hash("flashLoan")
    assert not is_function_hash("deadbeefHelper"), "a decoded name that merely starts with hex digits is not a selector"


def test_node_dicts_round_trip_with_and_without_the_selector_field():
    from faultseeker.data_collection.trace_parser import TraceNode
    node = parse("1.9.0", "cold", "nested_flashloan")
    assert TraceNode.from_dict(node.to_dict()).to_dict() == node.to_dict()
    legacy = node.to_dict()
    legacy.pop("selector")
    for child in legacy["children"]:
        child.pop("selector", None)
    assert TraceNode.from_dict(legacy).selector is None, "cached traces from before this change still load"
