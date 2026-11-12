"""The bundled selector table and canonicalization. Every selector is re-derived, not trusted."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from faultseeker.utils import selectors

TABLE = Path(selectors.__file__).with_name("known_selectors.json")
ROOT = Path(selectors.__file__).resolve().parents[2]


def keccak_selector(signature: str) -> str:
    try:
        from Crypto.Hash import keccak
        return keccak.new(digest_bits=256, data=signature.encode()).digest().hex()[:8]
    except ImportError:
        eth_utils = pytest.importorskip("eth_utils")
        return eth_utils.keccak(signature.encode()).hex()[:8]


def test_every_bundled_selector_matches_its_signature_by_keccak():
    table = json.loads(TABLE.read_text())
    assert len(table) >= 40
    for selector, signature in table.items():
        assert keccak_selector(signature) == selector, signature


def test_every_bundled_selector_matches_cast_sig_when_foundry_is_installed():
    cast = shutil.which("cast")
    if not cast:
        pytest.skip("cast not installed")
    probe = subprocess.run([cast, "sig", "transfer(address,uint256)"], capture_output=True, text=True)
    if probe.stdout.strip().removeprefix("0x") != "a9059cbb":
        pytest.skip("`cast` here is not Foundry's (a stand-in), so it cannot be used as an oracle")
    for selector, signature in json.loads(TABLE.read_text()).items():
        out = subprocess.run([cast, "sig", signature], capture_output=True, text=True).stdout.strip()
        assert out.removeprefix("0x") == selector, signature


def test_the_table_file_is_exactly_what_the_generator_produces(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "generate_selectors.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    expected = {keccak_selector(sig): sig for sig in gen.SIGNATURES}
    assert json.loads(TABLE.read_text()) == dict(sorted(expected.items(), key=lambda kv: kv[1]))


def test_table_covers_every_flash_loan_name_the_analyzer_looks_for():
    pytest.importorskip("ollama")            # faultseeker.utils.utils imports the agents
    from faultseeker.utils.utils import get_function_calls_to_expand
    names = {sig.split("(")[0] for sig in selectors.table().values()}
    lists = get_function_calls_to_expand()
    for needed in ("flashLoan", "flashLoanSimple", "flashFee", "maxFlashLoan"):
        assert needed in lists["flashloan"] and needed in names
    for needed in ("executeOperation", "onFlashLoan", "uniswapV2Call", "swap", "receiveFlashLoan", "callFunction",
                   "DVMFlashLoanCall", "DPPFlashLoanCall", "onMorphoFlashLoan"):
        assert needed in lists["callback"] and needed in names


@pytest.mark.parametrize("token,expected", [
    ("a9059cbb", ("transfer", "a9059cbb")), ("0xA9059CBB", ("transfer", "a9059cbb")), ("5cffe9de", ("flashLoan", "5cffe9de")),
    ("10d1e85c", ("uniswapV2Call", "10d1e85c")), ("2fbebd38", ("2fbebd38", "2fbebd38")),      # unknown: stays a bare selector
    ("transfer", ("transfer", "a9059cbb")), ("foo", ("foo", None)), ("", ("", None)),
])
def test_canonicalize(token, expected):
    assert selectors.canonicalize(token) == expected


def test_overloaded_names_have_no_single_selector_but_raw_selectors_are_exact():
    assert selectors.canonicalize("flashLoan")[0] == "flashLoan" and selectors.canonicalize("flashLoan")[1] is None
    sels = {s for s, sig in selectors.table().items() if sig.startswith("flashLoan(")}
    assert len(sels) >= 3
    for s in sels:
        assert selectors.canonicalize(s) == ("flashLoan", s)


def test_extra_table_from_the_environment(tmp_path, monkeypatch):
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps({"0x2fbebd38": "foo(uint256)"}))
    monkeypatch.setenv("FAULTSEEKER_SELECTOR_TABLE", str(extra))
    assert selectors.canonicalize("2fbebd38") == ("foo", "2fbebd38")
    assert selectors.canonicalize("foo") == ("foo", "2fbebd38")
    assert selectors.canonicalize("a9059cbb")[0] == "transfer", "the bundled table is still there"
    monkeypatch.delenv("FAULTSEEKER_SELECTOR_TABLE")
    assert selectors.canonicalize("2fbebd38") == ("2fbebd38", "2fbebd38")
