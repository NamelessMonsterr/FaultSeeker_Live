"""Evidence and report contract: raw model output -> verdict acceptance -> normalizer -> API/UI payload (OFFLINE).

Supported evidence structures become readable text; raw objects, confidence fields, provider error sentinels and malformed
values never reach a report; junk is never promoted into a finding; rejection and limited coverage are surfaced.
"""
import json
import math

import pytest

try:
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    from faultseeker.server import results
    from faultseeker.utils.agent import AbstractAgent, ModelResponseError
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

A1 = "0x" + "1" * 40
A2 = "0x" + "2" * 40
KEY = f"withdraw_{A1}"


def raw(potential=None, ranked=None, **kw):
    base = {"transaction_hash": "0x" + "1" * 64, "chain": "eth", "transaction_understanding": "t",
            "ranked_suspicious_functions": ranked if ranked is not None else list(potential or {}),
            "potentially_vulnerable_functions": potential or {}}
    base.update(kw)
    return base


def evidence_of(value):
    out = results.normalize(raw({KEY: value}))
    return out, [e for r in out["ranking"] + out["candidates"] for e in r["evidence"]]


# ------------------------------------------------------------------------------------------ readable evidence

def test_a_supported_evidence_dict_becomes_readable_text_without_confidence():
    out, ev = evidence_of([{"evidence": "withdraw sends funds first", "confidence_score": 0.9}])
    assert ev == ["withdraw sends funds first"]
    out, ev = evidence_of([{"observation": "call to token.transfer precedes the balance write", "hypothesis": "reentrancy",
                            "confidence": 0.7, "confidence_score": 0.7}])
    assert len(ev) == 1 and "Observation: call to token.transfer" in ev[0] and "Hypothesis: reentrancy" in ev[0]
    assert "confidence" not in ev[0].lower() and "{" not in ev[0] and "0.7" not in ev[0]


def test_nested_lists_and_dicts_flatten_to_text():
    _, ev = evidence_of([["first", ["second"]], {"evidence": ["third", {"observation": "fourth"}]}])
    assert ev == ["first", "second", "third; Observation: fourth"], "one dict is one evidence text"


def test_a_stringified_dict_is_parsed_not_displayed_raw():
    _, ev = evidence_of(["{'evidence': 'inside a string', 'confidence_score': 0.5}"])
    assert ev == ["inside a string"]


@pytest.mark.parametrize("junk", [{"foo": 1, "bar": [1, 2]}, {"confidence_score": 0.9}, {}, 5, 2.5, True, False, math.inf, math.nan,
                                  "An error occurred.", " an error occurred. ", "", "   ", [None, "", {}, 3]])
def test_junk_evidence_never_appears_and_is_not_promoted_to_a_finding(junk):
    out, ev = evidence_of(junk)
    assert ev == [] and out["ranking"] == [] and out["candidates"] == [], out
    assert any("no usable evidence" in w for w in out["warnings"]), out["warnings"]
    assert "No potentially vulnerable" in " ".join(out["warnings"])
    text = json.dumps(out)
    assert "An error occurred" not in text and "confidence" not in text.lower()


def test_a_finding_keeps_its_good_evidence_when_some_items_are_junk_and_says_so():
    out, ev = evidence_of(["real evidence", {"foo": 1}, "An error occurred.", math.inf, {"evidence": "more", "confidence_score": 1}])
    assert ev == ["real evidence", "more"] and len(out["ranking"]) == 1
    assert any("evidence item" in w and "could not be shown" in w for w in out["warnings"]), out["warnings"]


def test_control_characters_are_removed_and_length_is_bounded():
    _, ev = evidence_of(["line one\x00\x1b[31mred\x07", "x" * 10000])
    assert "\x00" not in ev[0] and "\x1b" not in ev[0] and "\x07" not in ev[0] and ev[0].startswith("line one")
    assert len(ev[1]) <= 2001 and ev[1].endswith("…")


def test_junk_potential_entries_are_not_promoted():
    out = results.normalize(raw({"no_address_key": ["x"], "plain": ["y"], KEY: ["good"], f"junk_{A2}": [{"a": 1}]}))
    assert [r["function"] for r in out["ranking"]] == ["withdraw"]
    assert any("not valid function" in w or "not a valid" in w or "identifier" in w for w in out["warnings"]), out["warnings"]
    assert any("no usable evidence" in w for w in out["warnings"])


# ------------------------------------------------------------------------------------------ surfaced rejection and coverage

def test_verdict_rejections_and_limited_coverage_are_surfaced_without_becoming_findings():
    out = results.normalize(raw({KEY: ["good"]}, verdict_rejections={"not a candidate of this analysis": 2, "unusable evidence": 1},
                                coverage={"status": "limited", "limited": True, "candidates": 9, "selected": 3, "analyzed": 3,
                                          "omitted": [f"f{i}@{A1}" for i in range(6)], "failed": [], "selection_rejected": 1,
                                          "selection_replies_ignored": 0}))
    text = " ".join(out["warnings"])
    assert "3 model verdict entries were rejected" in text and "not a candidate of this analysis" in text
    assert "6 of 9 candidate functions were not analyzed" in text and "not evidence" in text
    assert out["coverage"]["limited"] is True and out["coverage"]["omitted_count"] == 6 and out["coverage"]["candidates"] == 9
    assert [r["function"] for r in out["ranking"] + out["candidates"]] == ["withdraw"]


def test_no_finding_with_limited_coverage_is_not_a_clean_conclusion():
    cov = {"status": "limited", "limited": True, "candidates": 5, "selected": 1, "analyzed": 1, "omitted": ["a@" + A1] * 4,
           "failed": [], "selection_rejected": 0, "selection_replies_ignored": 0}
    out = results.normalize(raw({}, coverage=cov))
    text = " ".join(out["warnings"])
    assert "No potentially vulnerable functions were identified among the 1 analyzed" in text
    assert "4 of 5 candidate functions were not analyzed" in text and "not a clean result" in text


def test_genuinely_empty_input_reads_differently_from_a_filtered_or_failed_analysis():
    empty = results.normalize(raw({}, coverage={"status": "no_candidates", "limited": False, "candidates": 0, "selected": 0,
                                                "analyzed": 0, "omitted": [], "failed": [], "selection_rejected": 0,
                                                "selection_replies_ignored": 0}))
    assert any("No candidate functions were found" in w for w in empty["warnings"])
    assert not any("were not analyzed" in w for w in empty["warnings"])


def test_complete_coverage_adds_no_coverage_warning():
    cov = {"status": "complete", "limited": False, "candidates": 3, "selected": 3, "analyzed": 3, "omitted": [], "failed": [],
           "selection_rejected": 0, "selection_replies_ignored": 0}
    out = results.normalize(raw({KEY: ["e"]}, coverage=cov))
    assert out["warnings"] == [] and out["coverage"]["limited"] is False


def test_malformed_coverage_and_rejection_fields_do_not_crash_or_mislead():
    for bad in (None, "x", 5, [1], {"omitted": "all", "candidates": "many"}, {"status": 9}):
        out = results.normalize(raw({KEY: ["e"]}, coverage=bad, verdict_rejections=bad))
        json.dumps(out)
        assert [r["function"] for r in out["ranking"]] == ["withdraw"]


def test_input_limited_verdicts_are_reported_as_limited_evidence():
    out = results.normalize(raw({}, evidence_gaps={f"withdraw@{A1}": ["evidence reduced to fit the model input budget"]}))
    text = " ".join(out["warnings"])
    assert "model input budget" in text and "not evidence" in text and "No source code was available" not in text


# ------------------------------------------------------------------------------------------ verdict acceptance

class Recorder(AbstractAgent):
    def __init__(self, reply):
        super().__init__("", "rec")
        self.reply = reply

    def _send_message(self, user_message, temperature=0):
        return self.reply


def verdict(reply):
    from faultseeker.prompts.function_analysis import VulnerabilityAnalysisPrompts
    a = object.__new__(FunctionAnalyzer)
    a.vulnerability_prompts = VulnerabilityAnalysisPrompts()
    a.understanding_result, a.processing_result, a.cheatsheet = "U", "P", []
    a.current_task, a.potentially_vulnerable_functions = {"task_description": "t"}, {}
    a.function_call_info_summary = {"function": "withdraw", "address": A1}
    a.organization_agent = Recorder(reply if isinstance(reply, str) else json.dumps(reply))
    a.tx_analysis = {"function_call_loc_memo": {}}
    a._update_potentially_vulnerable_function()
    return a


@pytest.mark.parametrize("confidence", [0.5, 1, 1.0, "0.5", " 0.9 ", 0.01])
def test_finite_confidence_inside_the_supported_range_is_accepted(confidence):
    a = verdict({KEY: ["evidence", confidence]})
    assert a.potentially_vulnerable_functions[KEY]["confidence_score"] == [float(confidence)]


@pytest.mark.parametrize("confidence", [math.inf, -math.inf, math.nan, "inf", "-inf", "nan", "Infinity", "1e999", 1.01, 2, 90, -0.2, 0, "0",
                                        True, False, None, "high", [0.5], {"a": 1}])
def test_infinite_nonfinite_or_unsupported_confidence_is_rejected(confidence):
    reply = json.dumps({KEY: ["evidence", confidence]})              # json.dumps writes inf/nan as Infinity/NaN, which json.loads reads
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict(reply)


@pytest.mark.parametrize("evidence", [{}, {"foo": "bar"}, 5, True, [], [None, ""], "An error occurred.", "", "  ", ["", {}], {"confidence_score": 0.5}])
def test_unsupported_evidence_types_are_rejected_not_accepted_as_truthy_objects(evidence):
    with pytest.raises(ModelResponseError, match="none had a usable"):
        verdict({KEY: [evidence, 0.8]})


@pytest.mark.parametrize("evidence,stored", [("plain", ["plain"]), (["a", "b"], ["a", "b"]), ({"evidence": "x"}, ["x"]),
                                              ({"observation": "o", "hypothesis": "h"}, ["Observation: o; Hypothesis: h"])])
def test_supported_evidence_structures_are_accepted_and_stored_as_readable_text(evidence, stored):
    a = verdict({KEY: [evidence, 0.8]})
    assert a.potentially_vulnerable_functions[KEY]["evidence"] == stored


def test_partial_rejection_keeps_the_valid_entry_and_counts_the_rest(capsys):
    a = verdict({KEY: ["good", 0.8], f"withdraw_{A2}": ["not a candidate", 0.9], "x": 5})
    assert list(a.potentially_vulnerable_functions) == [KEY]
    assert sum(a.verdict_rejections.values()) == 2
    assert "2 verdict entr" in capsys.readouterr().out


def test_rejections_roll_back_with_a_failed_attempt_but_survive_a_completed_one():
    a = verdict({KEY: ["good", 0.8], f"withdraw_{A2}": ["x", 0.9]})
    for field in ("task_tree", "processing_result", "children_call_memo_single", "children_call_memo", "understanding_result"):
        setattr(a, field, getattr(a, field, ""))
    a.repeated_patterns = []
    state = a._capture_candidate_attempt_state()
    a.verdict_rejections = {"junk": 9}
    a._restore_candidate_attempt_state(state)
    assert sum(a.verdict_rejections.values()) == 1


# ------------------------------------------------------------------------------------------ the API carries the contract

def test_the_normalized_result_is_json_and_has_no_raw_objects():
    out = results.normalize(raw({KEY: [{"evidence": "e", "confidence_score": 0.9}, {"zzz": {"deep": 1}}]},
                                ranked=[KEY, "An error occurred.", {"function": "nope"}]))
    dumped = json.dumps(out)
    assert "confidence_score" not in dumped and "zzz" not in dumped and "deep" not in dumped
    assert all(isinstance(e, str) for r in out["ranking"] + out["candidates"] for e in r["evidence"])
