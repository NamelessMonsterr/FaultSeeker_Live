"""Ranking output contract: analyzed candidates always land in the report with validated function names, and an unusable
ranking is explained by name instead of silently leaving the report short. OFFLINE tests.

Provenance: a live Seneca (ETH) run analyzed the right contract but the report came back with warnings "1 ranking entry was
not valid function names and were left out" and "The model did not return a usable ranking, so candidates are shown
unranked". By construction the unranked fallback PROMOTES candidates into `ranking` (flagged unranked) and leaves
`candidates` empty; that shape is kept (the UI renders it), but the dropped entry was never named and a bare function name
in the model's ranking (the prompt asks for names) could not be matched. These tests reproduce the mechanism with synthetic
data and fake model replies; they are not proof about the live run.
"""
import json

import pytest

try:
    from faultseeker.core.config import FaultSeekerConfig
    from faultseeker.core.pipeline import FaultSeekerPipeline
    from faultseeker.server import results
    from tests import pipeline_fakes as fakes
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

from tests.conftest import USER_KEY, start_run, wait_final

A = "0x45e15d1e" + "ab" * 16                      # a Chamber-like address (40 hex digits)
B = "0x" + "bb" * 20
HASH = "0x" + "c4c4" + "0" * 60


def raw(ranked, potential, **kw):
    base = {"transaction_hash": HASH, "chain": "eth", "ranked_suspicious_functions": ranked,
            "potentially_vulnerable_functions": potential, "transaction_understanding": "u", "duration": 1.0}
    base.update(kw)
    return base


def names(out):
    return [(r["function"], r["address"]) for r in out["ranking"]]


# ------------------------------------------------------------------------------------------ resolution of ranking entries

@pytest.mark.parametrize("entry", [f"swap_{A}", f"SWAP_{A}", "swap", "Swap", f"swap@{A}", f"swap::{A}", "Chamber.swap",
                                   "swap(address,uint256)", "`swap`", "'swap'", "Chamber.swap(address)"])
def test_every_supported_form_resolves_to_the_analyzed_function(entry):
    out = results.normalize(raw([entry], {f"swap_{A}": ["evidence"]}))
    assert names(out) == [("swap", A.lower())] and out["warnings"] == [] and out["candidates"] == []
    assert out["ranking"][0]["evidence"] == ["evidence"] and "unranked" not in out["ranking"][0]


def test_a_bare_name_shared_by_two_analyzed_functions_is_never_guessed_and_is_named():
    out = results.normalize(raw(["transfer"], {f"transfer_{A}": ["a"], f"transfer_{B}": ["b"]}))
    assert sorted(names(out)) == sorted([("transfer", A.lower()), ("transfer", B.lower())])      # kept, unranked
    assert all(r["unranked"] for r in out["ranking"])
    text = " ".join(out["warnings"])
    assert "'transfer' (matches 2 analyzed functions)" in text and "unranked" in text


def test_an_unmatched_entry_is_named_and_the_rest_still_ranks():
    out = results.normalize(raw([f"swap_{A}", "doesNotExist"], {f"swap_{A}": ["e"], f"burn_{B}": ["b"]}))
    assert names(out) == [("swap", A.lower())]
    assert [c["function"] for c in out["candidates"]] == ["burn"], "analyzed candidates are never lost"
    assert any("'doesNotExist' (not an analyzed function)" in w and "not valid function names" in w for w in out["warnings"])


def test_the_live_shape_one_invalid_entry_names_the_gap_and_every_candidate_is_in_the_report():
    out = results.normalize(raw(["see the swap function in the Chamber contract"], {f"swap_{A}": ["e1", "e2"]}))
    assert names(out) == [("swap", A.lower())] and out["ranking"][0]["unranked"] is True
    assert out["ranking"][0]["evidence"] == ["e1", "e2"]
    text = " ".join(out["warnings"])
    assert "'see the swap function in the Chamber" in text and "not an analyzed function" in text
    assert "Reason: none of its 1 entries matched an analyzed function." in text


@pytest.mark.parametrize("bad,reason", [([], "empty or not a list"), ("An error occurred.", "empty or not a list"), (None, "empty or not a list")])
def test_an_empty_or_non_list_ranking_is_explained(bad, reason):
    out = results.normalize(raw(bad, {f"swap_{A}": ["e"]}))
    assert names(out) == [("swap", A.lower())] and out["ranking"][0]["unranked"]
    assert any(reason in w and "unranked" in w for w in out["warnings"])


def test_the_analyzers_ranking_problem_is_reported_with_candidates_or_without():
    with_candidates = results.normalize(raw([], {f"swap_{A}": ["e"]}, ranking_problem="ProviderFailure: the provider returned null content"))
    assert any("Reason: ProviderFailure: the provider returned null content." in w for w in with_candidates["warnings"])
    without = results.normalize(raw([], {}, ranking_problem="ModelResponseError: the model reply is not valid JSON"))
    assert any("ranking request could not be used" in w for w in without["warnings"])
    assert any("No potentially vulnerable" in w for w in without["warnings"])


def test_warning_text_from_the_model_is_bounded_and_printable():
    nasty = "x\u0000\u202e" + "A" * 500
    out = results.normalize(raw([nasty] + [f"e{i}" for i in range(6)], {f"swap_{A}": ["e"]}))
    text = " ".join(out["warnings"])
    assert "\u0000" not in text and "\u202e" not in text and len(text) < 700 and "and 4 more" in text
    json.dumps(out)


def test_existing_ranking_behaviour_is_unchanged():
    """guard: full keys, case-insensitive matching, duplicates, dict rankings, keys absent from the findings"""
    out = results.normalize(raw([f"mint_{A}", f"MINT_{A}", f"burn_{B}"], {f"mint_{A}": ["m"]}))
    assert names(out) == [("mint", A.lower()), ("burn", B.lower())] and out["ranking"][1]["evidence"] == []
    out = results.normalize(raw({f"a_{A}": 1}, {}))
    assert names(out) == [("a", A.lower())]


# ------------------------------------------------------------------------------------------ real analyzer -> pipeline -> report

def pipeline(tmp_path, monkeypatch, scenario):
    state = fakes.install(scenario, monkeypatch.setattr)
    monkeypatch.setenv("OPENAI_API_KEY", USER_KEY)
    return FaultSeekerPipeline(FaultSeekerConfig(cache_dir=str(tmp_path / "cache"))), state


def report(tmp_path, monkeypatch, scenario):
    p, state = pipeline(tmp_path, monkeypatch, scenario)
    result = p.analyze_transaction(txn_hash=HASH, chain="bsc")
    return result, results.normalize(result)


@pytest.mark.parametrize("scenario", ["foundok", "foundbare"])
def test_a_full_key_or_a_bare_name_ranking_yields_a_validated_ranked_report(tmp_path, monkeypatch, scenario):
    result, out = report(tmp_path, monkeypatch, scenario)
    assert names(out) == [("foo", fakes.A)] and out["warnings"] == [] and "unranked" not in out["ranking"][0]
    assert result["ranking_problem"] == ""


@pytest.mark.parametrize("scenario,reason", [("foundbad", "not valid JSON"), ("foundoutage", "provider call failed"),
                                             ("foundnull", "null content")])
def test_an_unusable_ranking_reply_still_yields_the_analyzed_candidate_with_the_gap_named(tmp_path, monkeypatch, scenario, reason):
    result, out = report(tmp_path, monkeypatch, scenario)
    assert names(out) == [("foo", fakes.A)] and out["ranking"][0]["unranked"] is True and out["ranking"][0]["evidence"]
    assert any("unranked" in w and reason in w for w in out["warnings"]), out["warnings"]
    assert result["ranked_suspicious_functions"] == [] and reason in result["ranking_problem"]
    assert USER_KEY not in json.dumps(out) and fakes.LEAKY not in json.dumps(out)


def test_a_ranking_that_names_only_a_different_function_is_explained(tmp_path, monkeypatch):
    result, out = report(tmp_path, monkeypatch, "foundunmatched")
    assert names(out) == [("foo", fakes.A)] and out["ranking"][0]["unranked"]
    assert any("'bar' (not an analyzed function)" in w for w in out["warnings"])


# ------------------------------------------------------------------------------------------ real worker / API

def run_scenario(make_client, scenario):
    c = make_client(FAULTSEEKER_WORKER_MODULE="tests.pipeline_fake_worker")
    run_id = start_run(c, txn_hash="0x" + fakes.HASH_PREFIX[scenario] + "0" * 60)
    return c, run_id, wait_final(c, run_id, 90)["run"]


def test_api_bare_name_ranking_completes_with_a_ranked_validated_report(make_client):
    c, run_id, run = run_scenario(make_client, "foundbare")
    assert run["state"] == "completed", run
    body = c.get(f"/api/runs/{run_id}/result").json()
    assert names(body) == [("foo", fakes.A)] and body["warnings"] == [] and body["candidates"] == []


def test_api_unusable_ranking_completes_with_the_candidate_and_names_the_gap(make_client):
    c, run_id, run = run_scenario(make_client, "foundbad")
    assert run["state"] == "completed", run
    body = c.get(f"/api/runs/{run_id}/result").json()
    assert names(body) == [("foo", fakes.A)] and body["ranking"][0]["unranked"] is True
    assert any("unranked" in w and "not valid JSON" in w for w in body["warnings"]), body["warnings"]


def test_normalize_suppresses_provider_error_ranking_leftover():
    # GPT-authored regression (2026-11-14): the provider sentinel must never be quoted in warnings, while a genuine
    # unmatched entry keeps its named reason and the unusable ranking stays flagged.
    out = results.normalize(raw(["An error occurred.", "Foo.bar"], {f"swap_{A}": ["e"]}))
    text = "\n".join(out["warnings"])
    assert "an error occurred" not in text.casefold()
    assert "'Foo.bar' (not an analyzed function)" in text
    assert "not valid function names" in text


def test_normalize_sentinel_only_leftover_is_flagged_without_a_quote():
    out = results.normalize(raw(["An error occurred."], {f"swap_{A}": ["e"]}))
    text = "\n".join(out["warnings"])
    assert "an error occurred" not in text.casefold()
    assert "1 ranking entry was not valid function names and were left out." in text
