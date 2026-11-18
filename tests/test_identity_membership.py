"""Identity membership at both boundaries (OFFLINE; the model is a recording fake).

Boundary 1, function_analyzer._update_potentially_vulnerable_function: a verdict key is accepted only when it resolves
UNIQUELY to a candidate of the analysis in progress (or to a function the trace backs and the analysis context shows).
Boundary 2, server.results.normalize: a ranked entry is accepted only when it resolves UNIQUELY to an accepted finding.
Function-name case is preserved (Solidity is case-sensitive); only addresses are case-normalized. Full, abbreviated and
decorated spellings all go through the same membership and ambiguity checks.
"""
import json

import pytest

try:
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    from faultseeker.server import results
    from faultseeker.utils.agent import AbstractAgent, ModelResponseError
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

A1 = "0x" + "1" * 40
A2 = "0x" + "2" * 40
A3 = "0x" + "3" * 40
P1 = "0x" + "1" * 36 + "1111"          # shares a long prefix with P2
P2 = "0x" + "1" * 36 + "2222"


class Recorder(AbstractAgent):
    def __init__(self, reply):
        super().__init__("", "rec")
        self.reply = reply

    def _send_message(self, user_message, temperature=0):
        return self.reply


def analyzer(summary, reply, loc_memo=None):
    from faultseeker.prompts.function_analysis import VulnerabilityAnalysisPrompts
    a = object.__new__(FunctionAnalyzer)
    a.vulnerability_prompts = VulnerabilityAnalysisPrompts()
    a.understanding_result, a.processing_result, a.cheatsheet = "U", "P", []
    a.current_task, a.potentially_vulnerable_functions = {"task_description": "t"}, {}
    a.function_call_info_summary = summary
    a.organization_agent = Recorder(reply if isinstance(reply, str) else json.dumps(reply))
    a.tx_analysis = {"function_call_loc_memo": loc_memo or {}}
    return a


def verdict(summary, reply, loc_memo=None):
    a = analyzer(summary, reply, loc_memo)
    a._update_potentially_vulnerable_function()
    return a


ENTRY = ["Observed: withdraw sends funds before the balance update", 0.8]
WITHDRAW = {"function": "withdraw", "address": A1}


# ----------------------------------------------------------------------------------------- boundary 1: verdict keys

def test_a_full_key_for_another_address_is_not_accepted():
    """the reproduction: context has withdraw@1111..., the model supplies withdraw@2222..."""
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict(WITHDRAW, {f"withdraw_{A2}": ENTRY})


def test_empty_context_accepts_nothing():
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict({}, {f"withdraw_{A1}": ENTRY})
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict({"function": "withdraw"}, {f"withdraw_{A1}": ENTRY})        # a function with no address is no candidate


def test_a_valid_key_is_accepted_and_stored_under_the_candidate_identifier():
    a = verdict(WITHDRAW, {f"withdraw_{A1}": ENTRY})
    assert list(a.potentially_vulnerable_functions) == [f"withdraw_{A1}"]


def test_address_case_is_normalized_and_the_candidate_spelling_is_stored():
    letters = "0x" + "ab" * 20
    for typed in ("0x" + letters[2:].upper(), "0x" + letters[2:4].upper() + letters[4:]):
        a = verdict({"function": "withdraw", "address": letters}, {f"withdraw_{typed}": ENTRY})
        assert list(a.potentially_vulnerable_functions) == [f"withdraw_{letters}"]


def test_function_name_case_is_preserved_never_folded():
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict(WITHDRAW, {f"Withdraw_{A1}": ENTRY})
    a = verdict({"function": "Withdraw", "address": A1}, {f"Withdraw_{A1}": ENTRY})
    assert list(a.potentially_vulnerable_functions) == [f"Withdraw_{A1}"]


def test_mixed_valid_and_invalid_entries_keep_only_the_valid_ones_and_record_the_rest(capsys):
    a = verdict(WITHDRAW, {f"withdraw_{A1}": ENTRY, f"withdraw_{A2}": ENTRY, "junk": ENTRY, f"other_{A3}": ENTRY})
    assert list(a.potentially_vulnerable_functions) == [f"withdraw_{A1}"]
    assert sum(a.verdict_rejections.values()) == 3, a.verdict_rejections
    assert "3 verdict entr" in capsys.readouterr().out


def test_ambiguous_abbreviations_are_rejected_not_guessed():
    summary = {"pattern": [{"function": "withdraw", "address": P1}, {"function": "withdraw", "address": P2}]}
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict(summary, {"withdraw_" + P1[:12]: ENTRY})                    # a prefix of both
    a = verdict(summary, {f"withdraw_{P1[:6]}…{P1[-4:]}": ENTRY})           # prefix AND suffix single out one
    assert list(a.potentially_vulnerable_functions) == [f"withdraw_{P1}"]


def test_an_abbreviation_never_crosses_function_names():
    summary = {"pattern": [{"function": "withdraw", "address": A1}, {"function": "deposit", "address": A2}]}
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict(summary, {"deposit_" + A1[:12]: ENTRY})                     # 0x1111… is withdraw's address, not deposit's


def test_the_same_candidate_in_two_spellings_is_one_finding():
    letters = "0x" + "ab" * 20
    upper = "0x" + letters[2:].upper()
    a = verdict({"function": "withdraw", "address": letters}, {f"withdraw_{letters}": ENTRY, f"withdraw_{upper}": ["second spelling", 0.9]})
    entry = a.potentially_vulnerable_functions[f"withdraw_{letters}"]
    assert len(entry["evidence"]) == 1 and entry["confidence_score"] == [0.8], "the duplicate must not add evidence"
    assert a.verdict_rejections, "the duplicate is surfaced as a rejection"


@pytest.mark.parametrize("decorated", [f"`withdraw_{A2}`", f"'withdraw_{A2}'", f"Vault.withdraw_{A2}", f"withdraw@{A2}",
                                       f"withdraw::{A2}", f"withdraw(address)_{A2}", f"withdraw_{A2} "])
def test_decorated_forms_of_a_non_candidate_do_not_bypass_membership(decorated):
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict(WITHDRAW, {decorated: ENTRY})


@pytest.mark.parametrize("decorated", [f"`withdraw_{A1}`", f"withdraw@{A1}", f"Vault.withdraw_{A1}", f"withdraw::{A1}"])
def test_decorated_forms_of_a_candidate_resolve_to_that_candidate_only(decorated):
    a = verdict(WITHDRAW, {decorated: ENTRY})
    assert list(a.potentially_vulnerable_functions) == [f"withdraw_{A1}"]


def trace_context(known=True):
    summary = dict(WITHDRAW, high_appreance_count_children_calls={f"helper::{A3}": 2})
    memo = {f"helper::{A3}": [{"depth": [0, 0], "params": "p"}]} if known else {}
    return summary, memo


def test_another_function_is_accepted_only_when_the_trace_backs_it_and_the_context_shows_it():
    summary, memo = trace_context(known=True)
    a = verdict(summary, {f"helper_{A3}": ENTRY}, memo)
    assert list(a.potentially_vulnerable_functions) == [f"helper_{A3}"]
    summary, memo = trace_context(known=False)
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict(summary, {f"helper_{A3}": ENTRY}, memo)                     # shown, but not in the trace: not backed
    summary, memo = trace_context(known=True)
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict(summary, {f"other_{A3}": ENTRY}, memo)                      # in neither


def test_an_unknown_key_in_the_trace_memo_but_not_shown_to_the_model_is_not_accepted():
    memo = {f"helper::{A3}": [{"depth": [0], "params": "p"}]}
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict(WITHDRAW, {f"helper_{A3}": ENTRY}, memo)


# ----------------------------------------------------------------------------------------- boundary 2: ranked keys

def raw(ranked, potential, **kw):
    base = {"transaction_hash": "0x" + "1" * 64, "chain": "eth", "ranked_suspicious_functions": ranked,
            "potentially_vulnerable_functions": potential, "transaction_understanding": "t"}
    base.update(kw)
    return base


def shown(out):
    return [(r["function"], r["address"]) for r in out["ranking"]]


def test_an_unmatched_full_key_is_not_ranked_and_the_report_says_so():
    out = results.normalize(raw([f"withdraw_{A2}"], {f"withdraw_{A1}": ["real evidence"]}))
    assert (("withdraw", A2) not in shown(out)) and all(r["evidence"] for r in out["ranking"]), out["ranking"]
    assert shown(out) == [("withdraw", A1)] and out["ranking"][0].get("unranked")
    assert any("not an accepted finding" in w or "not valid" in w for w in out["warnings"]), out["warnings"]


def test_a_ranking_over_an_empty_findings_set_invents_no_finding():
    out = results.normalize(raw([f"withdraw_{A1}"], {}))
    assert out["ranking"] == [] and out["candidates"] == []
    assert any("No potentially vulnerable" in w for w in out["warnings"])
    assert any("1 ranking entr" in w for w in out["warnings"])


def test_ranked_address_case_is_normalized_but_function_name_case_is_not():
    letters = "0x" + "ab" * 20
    upper = "0x" + letters[2:].upper()
    out = results.normalize(raw([f"withdraw_{upper}"], {f"withdraw_{letters}": ["e"]}))
    assert shown(out) == [("withdraw", letters)] and not out["ranking"][0].get("unranked")
    out = results.normalize(raw([f"Withdraw_{A1}"], {f"withdraw_{A1}": ["e"]}))
    assert out["ranking"][0].get("unranked"), "a different-case name is a different function: it must not be ranked"
    assert any("ranking entr" in w for w in out["warnings"])


def test_ambiguous_abbreviated_ranked_entries_are_rejected():
    potential = {f"withdraw_{P1}": ["e1"], f"withdraw_{P2}": ["e2"]}
    out = results.normalize(raw(["withdraw_" + P1[:12]], potential))
    assert all(r.get("unranked") for r in out["ranking"]) and len(out["ranking"]) == 2
    assert any("matches 2" in w for w in out["warnings"]), out["warnings"]
    out = results.normalize(raw([f"withdraw_{P2[:6]}…{P2[-4:]}"], potential))
    assert shown(out)[0] == ("withdraw", P2) and not out["ranking"][0].get("unranked")


def test_ranked_decorated_forms_resolve_through_membership_only():
    potential = {f"withdraw_{A1}": ["e"]}
    for ok in (f"`withdraw_{A1}`", f"withdraw@{A1}", f"Vault.withdraw_{A1}"):
        out = results.normalize(raw([ok], potential))
        assert shown(out) == [("withdraw", A1)] and not out["ranking"][0].get("unranked"), ok
    for bad in (f"`withdraw_{A2}`", f"withdraw@{A2}", f"Vault.withdraw_{A2}"):
        out = results.normalize(raw([bad], potential))
        assert out["ranking"][0].get("unranked") and shown(out) == [("withdraw", A1)], bad
        assert any("ranking entr" in w for w in out["warnings"]), bad


def test_duplicates_and_mixed_valid_invalid_ranked_entries():
    potential = {f"withdraw_{A1}": ["e1"], f"deposit_{A3}": ["e3"]}
    out = results.normalize(raw([f"withdraw_{A1}", f"withdraw_{A1.upper().replace('0X', '0x')}", f"withdraw_{A2}", f"deposit_{A3}", "nonsense"], potential))
    assert shown(out) == [("withdraw", A1), ("deposit", A3)]
    assert [r["rank"] for r in out["ranking"]] == [1, 2] and not any(r.get("unranked") for r in out["ranking"])
    assert any("2 ranking entries were not valid" in w or "2 ranking entries were not" in w for w in out["warnings"]), out["warnings"]


def test_valid_findings_survive_when_optional_ranking_is_unusable():
    out = results.normalize(raw("An error occurred.", {f"withdraw_{A1}": ["real evidence"]}, ranking_problem="ProviderFailure: down"))
    assert shown(out) == [("withdraw", A1)] and out["ranking"][0]["evidence"] == ["real evidence"]
