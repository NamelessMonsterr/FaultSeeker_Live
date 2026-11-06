"""Synthetic local Solidity parser contracts; no explorer/model calls."""
import pytest
from pathlib import Path
from faultseeker.utils.solidityParser.loc_parser import get_loc_info, parse

@pytest.mark.parametrize("source", [
    "pragma solidity ^0.8.0; contract C { @ function foo() external {} }",
    "pragma solidity ^0.8.0; contract C { function foo() external {",
])
def test_invalid_source_is_not_published_as_function_locations(source, tmp_path):
    with pytest.raises(ValueError, match="Solidity source could not be parsed"):
        get_loc_info(source)
    path = tmp_path / "C.sol"
    path.write_text(source, encoding="utf-8")
    with pytest.raises(ValueError, match="Solidity source could not be parsed"):
        parse(str(path))

def test_valid_source_locations_remain_available():
    result = get_loc_info("pragma solidity ^0.8.0; contract C { error Bad(); function foo() external { revert Bad(); } }")
    assert "foo" in result["C"]["functions"]


def test_downloader_does_not_cache_recovered_invalid_source(tmp_path, monkeypatch):
    from faultseeker.data_collection.contract_downloader import ContractDownloader
    downloader = ContractDownloader.__new__(ContractDownloader)
    downloader.chain = "eth"
    downloader.address = ["0x" + "1" * 40]
    downloader.cache_dir = str(tmp_path / "cache")
    downloader.output_dir = str(tmp_path / "sources")
    Path(downloader.cache_dir).mkdir()
    def source(*args):
        folder = Path(args[2])
        folder.mkdir(exist_ok=True)
        (folder / "C.sol").write_text("pragma solidity ^0.8.0; contract C { @ function foo() external {} }", encoding="utf-8")
    monkeypatch.setattr(downloader, "get_source_code", source)
    with pytest.raises(ValueError, match="Solidity source could not be parsed"):
        downloader.run()
    assert not list(Path(downloader.cache_dir).glob("*.json"))


def test_download_is_isolated_from_stale_sources_and_preserves_unowned_files(tmp_path, monkeypatch):
    from faultseeker.data_collection.contract_downloader import ContractDownloader
    root = tmp_path / "sources"
    root.mkdir()
    (root / "stale.sol").write_text("contract Stale { function wrong() external {} }")
    unowned = tmp_path / "Implementation"
    unowned.mkdir()
    (unowned / "keep.txt").write_text("keep")
    monkeypatch.chdir(tmp_path)
    downloader = ContractDownloader("eth", ["0x" + "1" * 40, "0x" + "2" * 40], str(root), str(tmp_path / "cache"))
    def source(chain, address, destination):
        if address.endswith("1" * 40):
            Path(destination, "Fresh.sol").write_text("contract Fresh { function right() external {} }")
    monkeypatch.setattr(downloader, "get_source_code", source)
    result = downloader.run()
    assert set(result[downloader.address[0]]) == {"right"}
    assert result[downloader.address[1]] == {}
    assert (root / "stale.sol").exists()
    assert (unowned / "keep.txt").read_text() == "keep"


def test_explorer_contract_name_cannot_escape_source_directory(tmp_path, monkeypatch):
    from faultseeker.data_collection import contract_downloader as module
    monkeypatch.setattr(module, "explorer_call", lambda *a, **k: {"status": "1", "result": [{"SourceCode": "contract C {}", "ContractName": "../../escaped"}]})
    destination = tmp_path / "sources"
    module.ContractDownloader.get_source_code("eth", "0x" + "1" * 40, str(destination))
    assert not (tmp_path / "escaped.sol").exists()
    assert list((destination / "Implementation").glob("*.sol"))


@pytest.mark.parametrize("cached", [
    {"wrong": [{"content": "old unbound source"}]},
    {"schema_version": 2, "address": "0x" + "2" * 40, "chain": "eth", "functions": {"wrong": []}},
    {"schema_version": 2, "address": "0x" + "1" * 40, "chain": "bsc", "functions": {"wrong": []}},
])
def test_unbound_or_mismatched_source_cache_is_not_reused(tmp_path, monkeypatch, cached):
    import json
    from faultseeker.data_collection.contract_downloader import ContractDownloader
    address = "0x" + "1" * 40
    downloader = ContractDownloader("eth", [address], str(tmp_path / "sources"), str(tmp_path / "cache"))
    cache = Path(downloader.cache_dir, f"{address}_eth.json")
    if 'schema_version' in cached:
        # Keep the rest of the envelope valid so these cases exercise the
        # address/chain comparison, not an unrelated missing metadata check.
        cached = {**cached, 'source_kind': 'explorer_current', 'historical_binding': 'unverified',
                  'parser_contract': 'solidity-spans-v1',
                  'functions': {'wrong': [{'content': 'contract C {}', 'path': './C.sol',
                                            'start_line': 1, 'end_line': 1}]}}
    cache.write_text(json.dumps(cached), encoding="utf-8")
    fetched = []
    def source(chain, target, destination):
        fetched.append((chain, target))
        Path(destination, "Fresh.sol").write_text("contract C { function fresh() external {} }", encoding="utf-8")
    monkeypatch.setattr(downloader, "get_source_code", source)
    result = downloader.run()
    assert fetched == [("eth", address)]
    assert set(result[address]) == {"fresh"}
    envelope = json.loads(cache.read_text(encoding="utf-8"))
    assert envelope["schema_version"] == 2
    assert envelope["address"] == address and envelope["chain"] == "eth"
    assert envelope["historical_binding"] == "unverified"
    assert set(envelope["functions"]) == {"fresh"}
    # Newly generated, bound parser schema can be reused without another fetch.
    assert downloader.run() == result
    assert len(fetched) == 1


def test_corrupt_source_cache_refetches_instead_of_crashing(tmp_path, monkeypatch):
    from faultseeker.data_collection.contract_downloader import ContractDownloader
    address = "0x" + "1" * 40
    downloader = ContractDownloader("eth", [address], str(tmp_path / "sources"), str(tmp_path / "cache"))
    Path(downloader.cache_dir, f"{address}_eth.json").write_text("{broken", encoding="utf-8")
    monkeypatch.setattr(downloader, "get_source_code", lambda *args: None)
    assert downloader.run() == {address: {}}


@pytest.mark.parametrize("chain,address", [("../escape", "0x" + "1" * 40), ("eth", "../escape"), ("eth", "0xshort")])
def test_cache_identity_cannot_be_used_as_a_filesystem_path(tmp_path, chain, address):
    from faultseeker.data_collection.contract_downloader import ContractDownloader
    with pytest.raises(ValueError):
        ContractDownloader(chain, [address], str(tmp_path / "sources"), str(tmp_path / "cache"))



def test_overloads_and_same_line_definitions_keep_exact_distinct_spans(tmp_path):
    from faultseeker.data_collection.contract_downloader import ContractDownloader
    source = "contract C { function foo(uint x) external pure returns(uint) { return x; } function foo(address x) external pure returns(address) { return x; } }"
    functions = get_loc_info(source)["C"]["functions"]
    overloads = functions["foo"]["overloads"]
    assert len(overloads) == 2
    assert [source[loc["start_offset"]:loc["end_offset"]] for loc in overloads] == [
        "function foo(uint x) external pure returns(uint) { return x; }",
        "function foo(address x) external pure returns(address) { return x; }"]
    (tmp_path / "C.sol").write_text(source, encoding="utf-8")
    extracted = ContractDownloader.parse_contract(str(tmp_path))
    assert len(extracted["foo"]) == 2
    assert all(item["content"].startswith("function foo(") for item in extracted["foo"])
    assert "uint x" in extracted["foo"][0]["content"]
    assert "address x" in extracted["foo"][1]["content"]
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)
    address = "0x" + "1" * 40
    analyzer.contract_info = {address: extracted}
    candidates = analyzer._retrieve_source_code(address, "foo")
    assert len(candidates) == 2
    assert all(item["source_binding"] == "unverified" and item["source_alternatives"] for item in candidates)


@pytest.mark.parametrize("name", ["constructor", "receive", "fallback"])
def test_special_function_definitions_are_not_omitted(name):
    source = "pragma solidity ^0.8.0; contract C { constructor() {} receive() external payable {} fallback() external payable {} }"
    functions = get_loc_info(source)["C"]["functions"]
    loc = functions[name]
    assert loc["kind"] == name
    assert source[loc["start_offset"]:loc["end_offset"]].startswith(name + "(")


def test_single_line_function_source_reaches_actual_analyzer_retrieval(tmp_path):
    from faultseeker.data_collection.contract_downloader import ContractDownloader
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    address = "0x" + "1" * 40
    source = "contract C { function foo() external {} }"
    (tmp_path / "C.sol").write_text(source, encoding="utf-8")
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)
    analyzer.contract_info = {address: ContractDownloader.parse_contract(str(tmp_path))}
    result = analyzer._retrieve_source_code(address, "foo")
    assert len(result) == 1
    assert result[0]["source_code"] == "function foo() external {}"
    assert result[0]["source_binding"] == "unverified"


def test_multifile_explorer_paths_cannot_overwrite_each_other(tmp_path, monkeypatch):
    import json
    from faultseeker.data_collection import contract_downloader as module
    sources = {"a/b.sol": {"content": "contract A { function alpha() external {} }"},
               "a_b.sol": {"content": "contract B { function beta() external {} }"}}
    source = "{" + json.dumps({"language": "Solidity", "sources": sources}) + "}"
    monkeypatch.setattr(module, "explorer_call", lambda *a, **k: {"status": "1", "result": [{"SourceCode": source, "ContractName": "C"}]})
    module.ContractDownloader.get_source_code("eth", "0x" + "1" * 40, str(tmp_path))
    assert set(module.ContractDownloader.parse_contract(str(tmp_path))) == {"alpha", "beta"}



def test_line_only_parser_cache_is_not_reused_after_span_fix(tmp_path, monkeypatch):
    import json
    from faultseeker.data_collection.contract_downloader import ContractDownloader
    address = "0x" + "1" * 40
    downloader = ContractDownloader("eth", [address], str(tmp_path / "sources"), str(tmp_path / "cache"))
    path = Path(downloader.cache_dir, f"{address}_eth.json")
    old = {"schema_version": 2, "address": address, "chain": "eth", "source_kind": "explorer_current",
           "historical_binding": "unverified", "parser_contract": "line-only-v0",
           "functions": {"lost_overload": [{"content": "old line-only data", "path": "./C.sol", "start_line": 1, "end_line": 1}]}}
    path.write_text(json.dumps(old), encoding="utf-8")
    def source(chain, address, destination):
        Path(destination, "C.sol").write_text("contract C { function fresh() external {} }", encoding="utf-8")
    monkeypatch.setattr(downloader, "get_source_code", source)
    assert set(downloader.run()[address]) == {"fresh"}
    assert json.loads(path.read_text(encoding="utf-8"))["parser_contract"] == "solidity-spans-v1"
