"""Normalization of raw pipeline output, including the failure shapes the LLM layer really produces."""
import json

from faultseeker.server import results, settings

A = "0xc342774492b54ce5f8ac662113ed702fc1b34972"
B = "0xBB4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"


def raw(**kw):
    base = {"transaction_hash": "0x" + "1" * 64, "chain": "eth", "ranked_suspicious_functions": [],
            "potentially_vulnerable_functions": {}, "transaction_understanding": "text", "duration": 3.0,
            "timestamp": "2026-11-06T10:00:00", "_debug": {"functions_to_inspect_count": 4}}
    base.update(kw)
    return base


def test_ranking_joined_with_evidence_and_split_into_name_and_address():
    out = results.normalize(raw(
        ranked_suspicious_functions=[f"mint_{A}", f"safe_transfer_from_{B}"],
        potentially_vulnerable_functions={f"mint_{A}": ["e1", "e2"], f"safe_transfer_from_{B}": "single"}))
    assert [r["function"] for r in out["ranking"]] == ["mint", "safe_transfer_from"]
    assert out["ranking"][1]["address"] == B.lower() and out["ranking"][0]["evidence"] == ["e1", "e2"]
    assert out["ranking"][1]["evidence"] == ["single"] and out["warnings"] == [] and out["candidates"] == []
    assert out["stats"]["functions_to_inspect"] == 4 and out["kind"] == "live"


def test_case_insensitive_matching_duplicates_and_unranked_candidates():
    out = results.normalize(raw(
        ranked_suspicious_functions=[f"Mint_{A.upper().replace('0X', '0x')}", f"mint_{A}"],
        potentially_vulnerable_functions={f"mint_{A}": ["e"], f"burn_{A}": ["b"]}))
    assert len(out["ranking"]) == 1 and out["ranking"][0]["evidence"] == ["e"]
    assert [c["function"] for c in out["candidates"]] == ["burn"]


def test_dict_and_object_rankings_are_accepted():
    out = results.normalize(raw(ranked_suspicious_functions={f"a_{A}": 1, f"b_{A}": 2},
                                potentially_vulnerable_functions={f"a_{A}": ["x"]}))
    assert [r["function"] for r in out["ranking"]] == ["a", "b"] and out["ranking"][1]["evidence"] == []
    out = results.normalize(raw(ranked_suspicious_functions=[{"function": f"c_{A}"}, {"nothing": 1}]))
    assert [r["function"] for r in out["ranking"]] == ["c"]


def test_failed_model_output_is_never_displayed_as_a_finding():
    for bad in (["An error occurred."], "An error occurred.", None, 7, ["", "  "]):
        out = results.normalize(raw(ranked_suspicious_functions=bad,
                                    potentially_vulnerable_functions={f"mint_{A}": ["x"]}))
        assert [r["function"] for r in out["ranking"]] == ["mint"] and out["ranking"][0]["unranked"]
        assert any("unranked" in w for w in out["warnings"])
    out = results.normalize(raw(ranked_suspicious_functions=["An error occurred."]))
    assert out["ranking"] == [] and any("No potentially vulnerable" in w for w in out["warnings"])


def test_model_error_count_adds_a_warning_and_odd_inputs_do_not_crash():
    out = results.normalize(raw(), model_errors=3)
    assert any("3 model request(s) failed" in w for w in out["warnings"])
    out = results.normalize({"potentially_vulnerable_functions": ["not", "a", "dict"], "transaction_understanding": 5})
    assert out["ranking"] == [] and out["understanding"] == "" and out["transaction_hash"] == ""
    out = results.normalize(raw(potentially_vulnerable_functions={"no_address_key": {"a": 1}, "plain": None}))
    assert {r["function"] for r in out["ranking"]} == {"no_address_key", "plain"}   # unranked, so promoted
    assert all(r["address"] == "" and r["unranked"] for r in out["ranking"])
    json.dumps(out)


def test_reference_capture_comes_from_ground_truth(tmp_path, monkeypatch):
    cap = results.reference_capture()
    assert cap["kind"] == "capture" and cap["chain"] == "bsc"
    assert cap["ranking"][0]["function"] == "mint" and cap["ranking"][0]["address"].startswith("0xc342")
    assert "ground truth" in cap["understanding"].lower() and "not output from a live run" in cap["understanding"]
    monkeypatch.setattr(settings, "DEFAULT_CAPTURE_TX", "0x" + "9" * 64)
    assert results.reference_capture() == {}


def test_captures_file_overrides_the_reference(tmp_path, monkeypatch):
    f = tmp_path / "capture.json"
    f.write_text(json.dumps({"transaction_hash": "0x" + "2" * 64, "chain": "eth", "ranking": [], "candidates": []}))
    monkeypatch.setattr(settings, "CAPTURE_FILE", f)
    cap = results.reference_capture()
    assert cap["kind"] == "capture" and cap["transaction_hash"] == "0x" + "2" * 64 and cap["warnings"] == []
    f.write_text("{not json")
    assert results.reference_capture()["ranking"][0]["function"] == "mint"   # falls back, never crashes
