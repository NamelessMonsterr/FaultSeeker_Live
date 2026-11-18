"""Evidence-to-verdict path of Stage 2, reproduced OFFLINE on a Seneca-shaped transaction.

Provenance: a live ETH run of the Seneca exploit completed with zero findings although the analysis had reached the vulnerable
contract and selector (0x568d8cd9 = performOperations(uint8[],uint256[],bytes[])). These tests reproduce MECHANISMS found
by reading the code; they are not a statement about the live model and prove nothing about live accuracy:

  1. A call the trace shows as a bare selector never got the source of the function it calls: source is indexed by function
     NAME, so `_retrieve_source_code(address, "568d8cd9")` returned [] although the contract was verified and downloaded.
  2. The verdict prompt required "the supplied fault-localization information" (nothing supplies it) and a "complete
     function-name-and-address identifier present in the supplied information" (the analyzer never printed one), so a model
     following it literally had nothing to return but {}.
  3. A finding the model did return could be dropped without a trace (a third list element, a numeric string, a string value).
  4. "No finding" was reported the same whether or not the analyzed function's source was available.

The fake model here reads its prompt literally: it returns a finding only when the identifier it is asked to use AND the function
source are both in the prompt. That models what the prompt demands, not what any real model does.
"""
import json
import re
from types import SimpleNamespace

import networkx as nx
import pytest

try:
    from faultseeker.core.config import FaultSeekerConfig
    from faultseeker.core.pipeline import FaultSeekerPipeline
    import faultseeker.function_analysis.function_analyzer as fa
    from faultseeker.data_collection.contract_downloader import ContractDownloader
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    from faultseeker.server import results
    from faultseeker.utils.agent import AbstractAgent, ModelResponseError
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

VULN = "0x45e15d1e4f92f28a916f4f2971ad9adc278e148b"          # the evaluation address from the report (lower-case)
OTHER = "0x65c210c59b43eb68112b7a4f75c8393c36491f06"
SELECTOR = "568d8cd9"
KEY = f"{SELECTOR}_{VULN}"
FIXTURE = "tests/fixtures/chamber_like.sol"
HASH = "0x" + "d1d1" + "0" * 60


# ------------------------------------------------------------------------------------------ parsed source, the real parser

@pytest.fixture(scope="module")
def parsed(tmp_path_factory):
    d = tmp_path_factory.mktemp("src")
    import shutil
    shutil.copy(FIXTURE, d / "ChamberLike.sol")
    return ContractDownloader.parse_contract(str(d))


def analyzer_with_source(parsed, monkeypatch):
    a = object.__new__(FunctionAnalyzer)
    a.contract_info = {VULN: parsed}
    a.analysis_result = SimpleNamespace(chain="eth")
    monkeypatch.setattr(fa, "ContractDownloader", lambda *x, **k: SimpleNamespace(run=lambda: {}))   # nothing else is downloadable
    return a


# ------------------------------------------------------------------------------------------ 1. selector-named source

def test_the_fixture_is_parsed_by_name_as_the_downloader_does(parsed):
    assert "performOperations" in parsed and SELECTOR not in parsed


def test_the_source_of_a_selector_named_function_is_supplied(parsed, monkeypatch):
    a = analyzer_with_source(parsed, monkeypatch)
    got = a._retrieve_source_code(VULN, SELECTOR)
    assert got and "function performOperations" in got[0]["source_code"], "verified source exists but was not matched to the selector"
    assert a._retrieve_source_code(VULN, "0x" + SELECTOR) == got, "0x-prefixed selectors resolve the same way"


def test_selector_resolution_is_exact_never_a_guess(parsed, monkeypatch):
    a = analyzer_with_source(parsed, monkeypatch)
    assert a._retrieve_source_code(VULN, "deadbeef") == []            # a selector no function hashes to
    assert a._retrieve_source_code(VULN, "performOperations")         # names still resolve directly
    assert a._retrieve_source_code(OTHER, SELECTOR) == []             # another contract: nothing downloaded for it


def test_overloaded_functions_resolve_to_the_overload_the_selector_names(monkeypatch):
    from faultseeker.utils.solidity_selectors import selector_of
    def entry(src):
        return {"path": "./A.sol", "start_line": 1, "end_line": 5, "content": src}
    by_name = {"f": [entry("function f(uint256 a) external {\n}"), entry("function f(address a, uint256 b) external {\n}")]}
    a = object.__new__(FunctionAnalyzer)
    a.contract_info = {VULN: by_name}
    a.analysis_result = SimpleNamespace(chain="eth")
    monkeypatch.setattr(fa, "ContractDownloader", lambda *x, **k: SimpleNamespace(run=lambda: {}))
    got = a._retrieve_source_code(VULN, selector_of("f(address,uint256)"))
    assert len(got) == 1 and "address a, uint256 b" in got[0]["source_code"]
    assert a._retrieve_source_code(VULN, selector_of("f(uint256)"))[0]["source_code"].startswith("function f(uint256 a)")
    assert a._retrieve_source_code(VULN, selector_of("f(bool)")) == []


# ------------------------------------------------------------------------------------------ 2. verdict prompt

class Recorder(AbstractAgent):
    def __init__(self, reply="{}"):
        super().__init__("", "rec")
        self.reply, self.prompts = reply, []

    def _send_message(self, user_message, temperature=0):
        self.prompts.append(user_message)
        return self.reply


def verdict_prompt(summary, reply="{}"):
    a = object.__new__(FunctionAnalyzer)
    from faultseeker.prompts.function_analysis import VulnerabilityAnalysisPrompts
    a.vulnerability_prompts = VulnerabilityAnalysisPrompts()
    a.understanding_result, a.processing_result, a.cheatsheet = "U", "P", []
    a.current_task, a.potentially_vulnerable_functions = {"task_description": "t"}, {}
    a.function_call_info_summary = summary
    a.organization_agent = Recorder(reply)
    a.tx_analysis = {"function_call_loc_memo": {}}
    a._update_potentially_vulnerable_function()
    return a, a.organization_agent.prompts[0]


SOURCE = [{"path": "./ChamberLike.sol", "source_code": "function performOperations(uint8[] calldata actions) external {}"}]


def test_the_verdict_prompt_names_the_candidate_with_the_exact_key_to_return():
    _, prompt = verdict_prompt({"function": SELECTOR, "address": VULN, "function_source_code": SOURCE})
    assert KEY in prompt, "the identifier the model is told to use as the key must appear in what it is given"


def test_the_verdict_prompt_does_not_demand_inputs_the_analyzer_never_supplies():
    _, prompt = verdict_prompt({"function": SELECTOR, "address": VULN})
    assert "fault-localization information" not in prompt


def test_the_verdict_prompt_says_missing_information_is_not_evidence_of_safety_and_states_source_availability():
    _, with_source = verdict_prompt({"function": SELECTOR, "address": VULN, "function_source_code": SOURCE})
    _, without = verdict_prompt({"function": SELECTOR, "address": VULN})
    assert re.search(r"absence of (evidence|information)[^.]*not[^.]*safe|missing[^.]*not evidence[^.]*safe", without, re.I)
    assert "NOT available" in without and "NOT available" not in with_source


@pytest.mark.parametrize("summary,expected", [
    ({"function": "foo", "address": VULN}, ["foo_" + VULN]),
    ({"pattern": [{"function": "a", "address": VULN}, {"function": "b", "address": OTHER}]}, [f"a_{VULN}", f"b_{OTHER}"]),
    ({"function": "g", "address_related_info": {VULN: {}, OTHER: {}}}, [f"g_{VULN}", f"g_{OTHER}"]),
])
def test_candidate_identifiers_cover_every_candidate_shape(summary, expected):
    _, prompt = verdict_prompt(summary)
    for key in expected:
        assert key in prompt


def test_the_prompt_keeps_its_evidence_discipline():
    """guard: the v6 hallucination controls stay (evidence required, hypotheses labelled, {} when unsupported)"""
    _, prompt = verdict_prompt({"function": SELECTOR, "address": VULN})
    for phrase in ("MUST include evidence", "hypothesis", "Do not invent", "Return {}"):
        assert phrase in prompt


# ------------------------------------------------------------------------------------------ 3. verdict parsing

def verdict(reply, summary=None):
    a, _ = verdict_prompt(summary or {"function": SELECTOR, "address": VULN}, reply)
    return a


def test_a_third_list_element_does_not_discard_the_finding():
    a = verdict(json.dumps({KEY: ["Observed: delegatecall-free call with caller data", 0.8, "hypothesis: unchecked target"]}))
    assert KEY in a.potentially_vulnerable_functions and a.potentially_vulnerable_functions[KEY]["confidence_score"] == [0.8]


def test_a_numeric_string_confidence_is_accepted_but_non_numeric_is_not():
    assert KEY in verdict(json.dumps({KEY: {"evidence": "e", "confidence_score": "0.85"}})).potentially_vulnerable_functions
    with pytest.raises(ModelResponseError):
        verdict(json.dumps({KEY: {"evidence": "e", "confidence_score": "high"}}))


@pytest.mark.parametrize("reply", [
    json.dumps({KEY: "just a sentence of evidence"}),                       # string value
    json.dumps({KEY: ["only evidence"]}),                                   # missing confidence
    json.dumps({KEY: ["evidence", 0]}),                                     # zero confidence = no support
    json.dumps({"performOperations": ["e", 0.9]}),                          # no address in the key
    json.dumps({f"x_{VULN[:12]}": ["e", 0.9]}),                             # truncated address
])
def test_a_verdict_naming_functions_but_none_usable_is_an_error_not_a_clean_negative(reply):
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict(reply)


def test_usable_entries_survive_next_to_unusable_ones(capsys):
    both = {"pattern": [{"function": SELECTOR, "address": VULN}, {"function": "other", "address": OTHER}]}   # both are candidates here
    a = verdict(json.dumps({KEY: ["e", 0.7], "bad": "x", f"other_{OTHER}": ["e2", 0.6]}), both)
    assert sorted(a.potentially_vulnerable_functions) == sorted([KEY, f"other_{OTHER}"])
    assert "1 verdict entr" in capsys.readouterr().out


@pytest.mark.parametrize("abbreviated", [f"{SELECTOR}_{VULN[:12]}", f"{SELECTOR}_{VULN[:10]}…{VULN[-4:]}", f"{SELECTOR}_{VULN[:10].upper().replace('0X', '0x')}"])
def test_an_abbreviated_address_resolves_only_to_the_matching_candidate(abbreviated):
    a = verdict(json.dumps({abbreviated: ["Observed: caller-supplied calldata", 0.8]}))
    assert list(a.potentially_vulnerable_functions) == [KEY]


def test_an_abbreviated_address_of_a_function_that_is_not_the_candidate_is_not_repaired():
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict(json.dumps({f"transfer_{VULN[:12]}": ["e", 0.8]}))


@pytest.mark.parametrize("reply", ["{}", "[]"])
def test_an_empty_verdict_is_still_a_valid_no_finding(reply):
    assert verdict(reply).potentially_vulnerable_functions == {}


# ------------------------------------------------------------------------------------------ the ranker (checked, not changed)

def test_the_ranker_keeps_both_selector_named_candidates_with_normalized_addresses_and_no_other_loss():
    """guard: nothing in function_ranker drops or merges the two Seneca candidates (same selector on two contracts, mixed-case
    address in the input); the reported live logs show both were analyzed, and this pins why."""
    from faultseeker.function_analysis.function_ranker import FunctionRanker
    mixed = "0x45E15D1E4F92F28A916F4F2971AD9ADC278E148B"
    calls = [{"function": SELECTOR, "address": mixed, "gas": 1, "params": "0x", "depth": [0]},
             {"function": SELECTOR, "address": OTHER, "gas": 1, "params": "0x", "depth": [1]},
             {"function": SELECTOR, "address": VULN, "gas": 9, "params": "0x", "depth": [2]}]       # the same contract again
    forensics = SimpleNamespace(address_calls_with_created_contract=[], functions_to_be_inspected={"k": calls})
    out = FunctionRanker().rank(forensics, {"repeated_patterns": {}, "function_call_loc_memo": {}})
    assert sorted(out.functions_to_be_inspected) == sorted([KEY, f"{SELECTOR}_{OTHER}"])
    assert out.functions_to_be_inspected[KEY]["count"] == 2, "calls to one contract aggregate under one key"
    assert sorted(a.lower() for a in out.address_list) == sorted([VULN, OTHER])


# ------------------------------------------------------------------------------------------ real pipeline, literal fake model

class LiteralModel(AbstractAgent):
    """Provider boundary only. Understanding echoes what it was given (as a summary would); the verdict is a literal reader."""

    def __init__(self, role):
        super().__init__("", "literal")
        self.role = role

    def _send_message(self, user_message, temperature=0):
        text = str(user_message)
        if self.role == "generation":
            if "Understand and translate the required additional information" in text:
                return json.dumps({"source_code": [{"function": SELECTOR, "address": VULN}]})
            return json.dumps({"task_selected": 1, "task_description": "inspect the function", "information": "", "additional_information": ""})
        if self.role == "processing":
            return "Analysis input: " + text[-6000:]
        if self.role == "organization":
            if "function implementation is potentially vulnerable" in text:
                # It may only use the identifiers the prompt tells it to use as keys (the candidate line), exactly as instructed.
                told = text.split("use exactly these strings as keys): ", 1)[-1].split("\n")[0]
                keys = set(re.findall(r"[A-Za-z0-9_]+_0x[0-9a-fA-F]{40}", told))
                supplied = text.split("Current understanding:", 1)[-1]
                if f"{SELECTOR}_{VULN}" in keys and "function performOperations" in supplied:
                    return json.dumps({f"{SELECTOR}_{VULN}": ["Observed: performOperations decodes (address, bytes) from the caller and "
                                                              "calls the target with caller-supplied calldata", 0.9]})
                return "{}"
            if "Current understanding:" in text:
                return "yes"
            return "Understanding: " + text[-6000:]
        if self.role == "agent":
            keys = re.findall(r'"([A-Za-z0-9_]+_0x[0-9a-fA-F]{40})"', text.split("Likely vulnerable functions:")[-1])
            return json.dumps(list(dict.fromkeys(keys)))
        return "ok"


class SenecaForensics:
    has_source = True

    def __init__(self, *a, **k):
        pass

    def run(self, txn_hash, chain):
        graph = nx.node_link_data(nx.DiGraph(), edges="edges")
        calls = [{"function": SELECTOR, "address": VULN, "gas": 1, "params": "0x", "depth": [0]},
                 {"function": SELECTOR, "address": OTHER, "gas": 1, "params": "0x", "depth": [0]}]
        result = SimpleNamespace(
            transaction_hash=txn_hash, chain=chain, trace={"children": []}, duration=0.0, repeated_patterns={},
            function_call_loc_memo={}, function_calls_to_expand_loc=[], address_calls_with_created_contract=[], flatten_trace=[],
            balance_change={}, address_memo={}, potential_attacker=[], potential_victim=[],
            functions_to_be_inspected={"k": calls}, get_function_count=lambda: 2)
        return result, {"address_relation": graph, "address_calls": {}, "created_address": []}, {"transaction_hash": txn_hash}


def install(monkeypatch, parsed, with_source=True):
    import faultseeker.forensics.orchestrator as orchestrator

    class Downloader:
        calls = []

        def __init__(self, chain, addresses, *a, **k):
            Downloader.calls.append(list(addresses))
            self.addresses = addresses

        def run(self):
            return {a.lower(): (parsed if (with_source and a.lower() == VULN) else {}) for a in self.addresses}
    roles = iter(["reasoning", "generation", "processing", "organization", "filtering", "agent"])
    monkeypatch.setattr(fa, "build_agent", lambda task, model: LiteralModel(next(roles, "agent")))
    monkeypatch.setattr(fa, "ContractDownloader", Downloader)
    monkeypatch.setattr(orchestrator, "ForensicsOrchestrator", SenecaForensics)
    return Downloader


def run_pipeline(tmp_path, monkeypatch, parsed, with_source=True):
    install(monkeypatch, parsed, with_source)
    p = FaultSeekerPipeline(FaultSeekerConfig(cache_dir=str(tmp_path / "cache")))
    raw = p.analyze_transaction(txn_hash=HASH, chain="eth")
    return p, raw, results.normalize(raw)


def test_a_seneca_shaped_run_reports_the_vulnerable_function_when_its_source_is_available(tmp_path, monkeypatch, parsed):
    p, raw, out = run_pipeline(tmp_path, monkeypatch, parsed)
    assert [(r["function"], r["address"]) for r in out["ranking"]] == [(SELECTOR, VULN)], out
    assert raw["potentially_vulnerable_functions"][KEY], "the finding reached the final result"
    assert out["warnings"] == [] or all("No source code" not in w for w in out["warnings"] if VULN in w)


def test_without_source_the_run_completes_but_the_report_names_the_coverage_gap(tmp_path, monkeypatch, parsed):
    """absence of evidence is reported as absence of evidence: no finding is not 'safe'"""
    p, raw, out = run_pipeline(tmp_path, monkeypatch, parsed, with_source=False)
    assert out["ranking"] == [] and out["candidates"] == []
    text = " ".join(out["warnings"])
    assert "No source code was available" in text and SELECTOR in text and VULN[:8] in text
    assert "not evidence" in text
    assert raw["evidence_gaps"], "the gap travels with the result"


def test_the_gap_warning_is_bounded_and_does_not_appear_when_every_analyzed_function_had_source():
    assert not any("No source code" in w for w in results.normalize(
        {"potentially_vulnerable_functions": {}, "evidence_gaps": {}})["warnings"])
    many = {f"f{i}@0x{i:040x}": ["no function source code"] for i in range(9)}
    out = results.normalize({"potentially_vulnerable_functions": {}, "evidence_gaps": many})
    text = " ".join(w for w in out["warnings"] if "No source code" in w)
    assert "9 analyzed function" in text and "and 6 more" in text and len(text) < 600


def test_evidence_gaps_do_not_change_findings_or_ranking():
    base = {"ranked_suspicious_functions": [f"{SELECTOR}_{VULN}"], "potentially_vulnerable_functions": {f"{SELECTOR}_{VULN}": ["e"]}}
    plain = results.normalize(dict(base))
    gapped = results.normalize(dict(base, evidence_gaps={f"{SELECTOR}@{VULN}": ["no function source code"]}))
    assert gapped["ranking"] == plain["ranking"] and gapped["candidates"] == plain["candidates"]
    assert any("No source code" in w for w in gapped["warnings"])
