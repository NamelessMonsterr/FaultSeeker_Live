"""Chain registry, foundry.toml aliases, benchmark presets and the frontend contract."""
import re
import tomllib
from pathlib import Path

import pytest

from faultseeker import chains
from faultseeker.server import presets

ROOT = Path(chains.__file__).resolve().parents[1]
REQUESTED = ["eth", "bsc", "polygon", "arbitrum", "optimism", "base", "avalanche", "fantom", "zksync", "linea",
             "scroll", "gnosis", "celo", "cronos", "moonbeam", "aurora"]


def test_all_requested_networks_are_registered():
    assert list(chains.CHAINS) == REQUESTED
    assert {c["id"] for c in chains.CHAINS.values() if c["support"] == "full"} == {"eth", "bsc"}
    assert [c["id"] for c in chains.CHAINS.values() if c["support"] == "unsupported"] == ["zksync"]
    assert [c["id"] for c in chains.CHAINS.values() if c["support"] == "partial"] == ["fantom", "cronos", "aurora"]
    assert all("Stage 2" in chains.CHAINS[c]["note"] for c in ("fantom", "cronos", "aurora"))
    assert chains.CHAINS["zksync"]["note"]
    ids = [c["chain_id"] for c in chains.CHAINS.values()]
    assert len(set(ids)) == 16 and chains.CHAINS["eth"]["chain_id"] == 1 and chains.CHAINS["bsc"]["chain_id"] == 56


def test_lookup_aliases_and_urls():
    assert chains.get("ETH")["id"] == "eth" and chains.get("poly")["id"] == "polygon"
    assert chains.get("arbi")["id"] == "arbitrum" and chains.get("opt")["id"] == "optimism"
    assert chains.get("unknown") is None and chains.get(None) is None
    for c in chains.CHAINS.values():
        assert re.match(r"^https://[a-z.]+/tx/$", c["tx_url"]) and c["address_url"].endswith("/address/")


def test_every_replayable_chain_has_a_foundry_rpc_alias():
    cfg = tomllib.loads((ROOT / "foundry.toml").read_text())["profile"]["default"]["rpc_endpoints"]
    for cid, c in chains.CHAINS.items():
        if c["support"] != "unsupported":
            assert cfg.get(cid, "").startswith(("http", "ws")), f"foundry.toml lacks '{cid}'"


def test_getcode_knows_the_chain_ids():
    import importlib.util
    spec = importlib.util.find_spec("getsourcecode")     # importing the package would parse sys.argv, so load config.py alone
    if spec is None:
        pytest.skip("getSourceCode is not installed")
    cfg_spec = importlib.util.spec_from_file_location("gsc_config", Path(spec.origin).with_name("config.py"))
    gsc = importlib.util.module_from_spec(cfg_spec)
    cfg_spec.loader.exec_module(gsc)
    for cid, c in chains.CHAINS.items():
        if c["support"] in ("full", "beta"):
            assert c["chain_id"] in gsc.chain_to_id.values(), f"getCode does not know {cid} ({c['chain_id']})"
        elif c["support"] == "partial":   # keeps the registry honest if getCode later adds the network
            assert c["chain_id"] not in gsc.chain_to_id.values(), f"{cid} is now supported by getCode: mark it beta"


def test_presets_come_from_the_benchmark():
    by_chain = presets.presets_by_chain()
    assert set(by_chain) >= {"eth", "bsc"} and len(by_chain["eth"]) == 101 and len(by_chain["bsc"]) == 13   # 115 files, 114 unique hashes
    seen = set()
    for chain, items in by_chain.items():
        for p in items:
            assert re.match(r"^0x[0-9a-f]{64}$", p["hash"]) and p["name"]
            assert re.match(r"^\d{4}-\d{2}-\d{2}$", p["date"]), p
            assert p["hash"] not in seen
            seen.add(p["hash"])
        dates = [p["date"] for p in items]
        assert dates == sorted(dates, reverse=True), f"{chain} presets not newest-first"
    assert presets.ground_truth_by_hash("0x9f4ef3cc55b016ea6b867807a09f80d1b2e36f6cd6fccfaf0182f46060332c57")["name"] == "BEGO"
    assert presets.ground_truth_by_hash("0x" + "0" * 64) is None


def test_frontend_references_only_ids_that_exist_in_the_html():
    html = (ROOT / "web/index.html").read_text()
    js = (ROOT / "web/assets/console.js").read_text()
    html_ids = set(re.findall(r'\bid="([^"]+)"', html))
    used = set(re.findall(r"\$\('([^']+)'\)", js)) | set(re.findall(r"getElementById\('([^']+)'\)", js))
    dynamic = {f"preset-{kind}-{c}" for kind in ("btn", "list") for c in ("eth", "bsc")}
    missing = used - html_ids
    assert not missing, f"console.js uses ids missing from index.html: {missing}"
    assert dynamic <= html_ids
    for chain in ("eth", "bsc"):
        assert f"preset-btn-{chain}" in html_ids


def test_frontend_has_no_inline_styles_or_unsafe_html():
    """The server sends a strict CSP (style-src 'self'); inline styles would be silently dropped in a real browser."""
    html = (ROOT / "web/index.html").read_text()
    js = (ROOT / "web/assets/console.js").read_text()
    assert "style=" not in html and "<style" not in html and "onclick=" not in html
    assert not re.search(r"\.style\.|setAttribute\(\s*['\"]style|cssText|insertAdjacentHTML|eval\(|new Function|document\.write", js)
    assert re.findall(r"innerHTML\s*=\s*([^;]+);", js) == ["SUBMIT_HTML"]
    for ref in re.findall(r'(?:src|href)="\./(assets/[^"?]+)', html):
        assert (ROOT / "web" / ref).exists(), ref
