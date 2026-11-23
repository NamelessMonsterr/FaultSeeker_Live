"""Generic worker errors are sanitized before API/UI publication; the detail goes to the redacted technical log (OFFLINE)."""
import pytest

try:
    from tests.conftest import start_run, wait_final
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

INTERNAL = "internal detail /srv/faultseeker/internal.py token=abcd1234efgh model said {'junk': 1}"


def everything_published(client, run_id):
    """What the API/UI show about a run apart from the technical-log panel (where detail is meant to live)."""
    import json
    meta = client.get(f"/api/runs/{run_id}").json()["run"]
    return json.dumps(meta) + "\n" + client.get("/api/runs").text


def test_a_generic_pipeline_error_is_published_without_its_raw_text(make_client):
    c = make_client(FAKE_MODE="pipeline_error")
    rid = start_run(c)
    data = wait_final(c, rid)
    err = data["run"]["error"]
    assert data["run"]["state"] == "failed" and err["code"] == "pipeline_error"
    published = everything_published(c, rid)
    for leaked in ("/srv/faultseeker", "token=", "junk", "abcd1234efgh"):
        assert leaked not in published, f"{leaked!r} reached the API payload"
    assert "KeyError" in err["message"] and "technical logs" in err["hint"]
    assert any("internal detail" in line for line in data["logs"]), "the detail belongs in the technical log"


def test_an_odd_exception_type_name_is_not_published_verbatim(make_client):
    c = make_client(FAKE_MODE="pipeline_error_oddtype")
    rid = start_run(c)
    err = wait_final(c, rid)["run"]["error"]
    assert err["code"] == "pipeline_error" and "<script>" not in err["message"] and "Bad Type" not in err["message"]


def test_the_lost_output_stream_message_carries_no_exception_text(make_client):
    c = make_client(FAKE_MODE="bigline", FAKE_BIG=400_000, FAULTSEEKER_MAX_LINE_BYTES=100_000)
    err = wait_final(c, start_run(c))["run"]["error"]
    assert "output stream" in err["message"] and "chunk" not in err["message"].lower() and "limit" not in err["message"].lower()


@pytest.mark.parametrize("mode,code", [("forensics_model", "forensics_model_failed"), ("input_limit", "input_too_large")])
def test_typed_model_failures_get_their_own_fixed_explanations(make_client, mode, code):
    c = make_client(FAKE_MODE=mode)
    rid = start_run(c)
    err = wait_final(c, rid)["run"]["error"]
    assert err["code"] == code and "SECRET-REPLY-TEXT" not in everything_published(c, rid)


def test_an_input_budget_failure_is_named_as_an_application_limit_not_a_provider_problem(make_client):
    c = make_client(FAKE_MODE="budget_incomplete")
    err = wait_final(c, start_run(c))["run"]["error"]
    assert err["code"] == "analysis_incomplete" and "InputLimitExceeded" in err["message"]
    assert "input budget" in err["hint"] and "not a provider outage" in err["hint"] and "FAULTSEEKER_CONTEXT_TOKENS_<MODEL>" in err["hint"]
    assert "provider key, quota" not in err["hint"]


def test_input_too_large_hint_points_at_the_budget(make_client):
    c = make_client(FAKE_MODE="input_limit")
    err = wait_final(c, start_run(c))["run"]["error"]
    assert err["code"] == "input_too_large" and "input budget" in err["message"] and "FAULTSEEKER_CONTEXT_TOKENS_<MODEL>" in err["hint"]
