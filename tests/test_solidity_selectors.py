"""4-byte selectors computed from Solidity source (pure Python Keccak-256). OFFLINE, no tools needed."""
import pytest

from faultseeker.utils.solidity_selectors import (function_matches_selector, is_bare_selector, keccak256, normalize_selector,
                                                  selector_from_function_source, selector_of, signature_candidates)


@pytest.mark.parametrize("signature,selector", [
    ("transfer(address,uint256)", "a9059cbb"),
    ("approve(address,uint256)", "095ea7b3"),
    ("balanceOf(address)", "70a08231"),
    ("performOperations(uint8[],uint256[],bytes[])", "568d8cd9"),      # the selector from the Seneca report
])
def test_known_selectors(signature, selector):
    assert selector_of(signature) == selector


def test_keccak_is_not_sha3_and_matches_the_reference_vectors():
    import hashlib
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"").hex() != hashlib.sha3_256(b"").hexdigest()


def test_keccak_agrees_with_eth_utils_across_block_boundaries():
    eth_utils = pytest.importorskip("eth_utils")
    for n in (0, 1, 55, 135, 136, 137, 271, 272, 300):
        assert keccak256(b"x" * n) == eth_utils.keccak(b"x" * n)


@pytest.mark.parametrize("source,signature", [
    ("function performOperations(uint8[] calldata actions, uint256[] calldata values, bytes[] calldata datas) external payable returns (uint256 a, uint256 b) {",
     "performOperations(uint8[],uint256[],bytes[])"),
    ("function transfer(address to, uint amount) public returns (bool)", "transfer(address,uint256)"),
    ("function  f ( int x , byte b , bool[2] memory flags , string memory s ) external", "f(int256,bytes1,bool[2],string)"),
    ("function g(address payable who) external", "g(address)"),
    ("function h() external view returns (uint256)", "h()"),
    ("function k(\n    uint256 a, // first\n    /* second */ uint256 b\n) external", "k(uint256,uint256)"),
])
def test_unambiguous_signatures(source, signature):
    assert signature_candidates(source) == [signature]
    assert selector_from_function_source(source) == selector_of(signature)


def test_user_defined_types_are_resolved_by_trying_readings_that_the_selector_then_confirms():
    src = "function swap(IToken token, Mode mode, uint256 amount) external"
    assert len(signature_candidates(src)) == 4 and selector_from_function_source(src) is None
    assert function_matches_selector(src, selector_of("swap(address,uint8,uint256)"))
    assert function_matches_selector(src, "0x" + selector_of("swap(address,address,uint256)"))
    assert not function_matches_selector(src, selector_of("swap(address,uint256)"))
    declared = "interface IToken {}\nenum Mode { A, B }\n"
    assert signature_candidates(src, declared) == ["swap(address,uint8,uint256)"]


@pytest.mark.parametrize("bad", ["", "no function here", "function (", "function f(uint a", "event E(uint a);", "function f((uint a) x) {"])
def test_unparsable_text_gives_no_signature_and_no_match(bad):
    assert signature_candidates(bad) == [] and not function_matches_selector(bad, "deadbeef")


def test_bare_selector_detection():
    for yes in ("568d8cd9", "0x568d8cd9", "568D8CD9", " 568d8cd9 "):
        assert is_bare_selector(yes)
    for no in ("performOperations", "568d8cd", "568d8cd90", "0x", "", None, "ghijklmn"):
        assert not is_bare_selector(no)
    assert normalize_selector("0x568D8CD9") == "568d8cd9"
