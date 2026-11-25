"""Missing contract source is reported with the lookup's actual cause (or stated uncertainty), separate from code defects (OFFLINE)."""
import subprocess

import pytest

try:
    from faultseeker.data_collection import contract_downloader as cd
    from faultseeker.data_collection import source_fetcher
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
    from faultseeker.server import results
except ImportError as exc:
    pytest.skip(f"full requirements not installed: {exc}", allow_module_level=True)

ADDR = "0x" + "ab" * 20
KEY = "KEYVALUE1234567890SECRET"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    cd.ContractDownloader.lookup_outcomes.clear()
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    yield
    cd.ContractDownloader.lookup_outcomes.clear()


def lookup(monkeypatch, tmp_path, sourcify, getcode_stderr=None, getcode_files=False, getcode_output=None):
    def fetch(chain_id, address, out):
        if isinstance(sourcify, Exception):
            raise sourcify
        return sourcify

    def run_getcode(chain, address, out):
        if getcode_stderr is not None:
            raise subprocess.CalledProcessError(1, "getCode", stderr=getcode_stderr)
        return getcode_output                       # a zero exit: whatever the tool printed, if anything
    monkeypatch.setattr(source_fetcher, "fetch", fetch)
    monkeypatch.setattr(cd.ContractDownloader, "_run_getcode", staticmethod(run_getcode))
    monkeypatch.setattr(cd.ContractDownloader, "_has_sources", staticmethod(lambda out: getcode_files))
    cd.ContractDownloader.get_source_code("eth", ADDR, str(tmp_path))
    return cd.ContractDownloader.lookup_outcomes[ADDR]


def test_missing_credentials_are_reported_as_such_without_promising_recovery(monkeypatch, tmp_path, capsys):
    o = lookup(monkeypatch, tmp_path, 0, b"Error: Missing/Invalid API Key")
    assert o["cause"] == "explorer_credentials" and o["explorer_key_configured"] is False
    text = cd.describe_source_lookup(o)
    assert "missing or invalid API key" in text and "not guaranteed" in text and "no ETHERSCAN_API_KEY" in text
    out = capsys.readouterr().out
    assert "Contract source unavailable" in out and "does not guarantee" in out


def test_an_unreachable_lookup_is_not_called_unverified(monkeypatch, tmp_path):
    o = lookup(monkeypatch, tmp_path, source_fetcher.SourceUnavailable("connection refused"), b"")
    assert o["cause"] == "lookup_unreachable"
    assert "not evidence that the contract is unverified" in cd.describe_source_lookup(o)


def test_a_contract_neither_service_has_and_the_tool_calls_unverified_is_reported_as_unverified(monkeypatch, tmp_path):
    # Changed by audit F08: an EMPTY zero-exit used to be called "unverified"; only an explicit not-verified report is (see the F08 tests below).
    o = lookup(monkeypatch, tmp_path, 0, None, getcode_files=False, getcode_output="Contract source code not verified")
    assert o["sourcify"] == "no verified match" and o["cause"] == "unverified"


def test_an_unrecognized_failure_says_the_cause_is_unknown(monkeypatch, tmp_path):
    o = lookup(monkeypatch, tmp_path, 0, b"segmentation fault in getCode")
    assert o["cause"] == "unknown" and "could not be determined" in cd.describe_source_lookup(o)


def test_found_source_leaves_no_failure_outcome(monkeypatch, tmp_path):
    o = lookup(monkeypatch, tmp_path, 3)
    assert o["cause"] == "found" and o["sourcify"] == "found"


def analyzer_with(addresses):
    a = object.__new__(FunctionAnalyzer)
    a._universe_identities = {f"swap@{x}" for x in addresses}
    return a


def test_the_analysis_result_reports_only_failed_lookups_and_never_a_key(monkeypatch, tmp_path):
    monkeypatch.setenv("ETHERSCAN_API_KEY", KEY)
    lookup(monkeypatch, tmp_path, 0, f"bad request apikey={KEY} invalid key".encode())
    other = "0x" + "cd" * 20
    cd.ContractDownloader.lookup_outcomes[other] = {"chain": "eth", "cause": "found", "sourcify": "found"}
    report = analyzer_with([ADDR, other]).source_lookup_report()
    assert list(report) == [ADDR]
    assert KEY not in repr(report) and report[ADDR]["explorer_key_configured"] is True
    assert report[ADDR]["cause"] == "explorer_credentials"


def raw(**kw):
    base = {"transaction_hash": "0x" + "1" * 64, "chain": "eth", "ranked_suspicious_functions": [], "potentially_vulnerable_functions": {},
            "transaction_understanding": "t"}
    base.update(kw)
    return base


def test_the_report_shows_the_lookup_cause_next_to_the_missing_source_warning(monkeypatch, tmp_path):
    lookup(monkeypatch, tmp_path, 0, b"Error: Missing/Invalid API Key")
    report = analyzer_with([ADDR]).source_lookup_report()
    out = results.normalize(raw(source_lookups=report, evidence_gaps={f"swap@{ADDR}": ["no function source code"]}))
    text = " ".join(out["warnings"])
    assert "No source code was available for 1 analyzed function" in text
    assert f"Contract source lookup for {ADDR[:8]}…{ADDR[-4:]} [eth]" in text and "missing or invalid API key" in text
    assert "will recover" not in text and "guarantee" in text


def test_malformed_lookup_data_is_ignored_not_displayed():
    out = results.normalize(raw(source_lookups={"not-an-address": {"summary": "x"}, ADDR: {"summary": 5}, "z": 1}))
    assert out["warnings"] == [] or not any("Contract source lookup" in w for w in out["warnings"])
    out = results.normalize(raw(source_lookups="junk"))
    assert not any("Contract source lookup" in w for w in out["warnings"])


def test_missing_source_is_an_evidence_gap_not_an_execution_failure():
    out = results.normalize(raw(
        coverage={"status": "complete", "limited": False, "evidence_limited": True, "reduced_count": 0, "source_missing_count": 1,
                  "candidates": 1, "selected": 1, "analyzed": 1, "omitted": [], "failed": [], "selection_rejected": 0, "selection_replies_ignored": 0},
        function_results=[{"identity": f"swap@{ADDR}", "function": "swap", "address": ADDR, "execution": "completed", "evidence": "source_missing"}]))
    f = out["functions"][0]
    assert f["execution"] == "completed" and f["evidence"] == "source_missing" and out["coverage"]["limited"] is False
    assert any("not a clean result" in w for w in out["warnings"])


# ------------------------------------------------------------------------------------------------ audit F08: a zero exit is not proof of "unverified"

@pytest.mark.parametrize("output,cause", [
    ("Error! Missing/Invalid API Key", "explorer_credentials"), ("NOTOK: Invalid API Key", "explorer_credentials"),
    ("Max rate limit reached", "explorer_rate_limited"), ("Contract source code not verified", "unverified"),
    ("", "no_files"), ("some unrecognized banner", "no_files")])
def test_a_zero_exit_with_no_files_is_classified_from_what_the_tool_printed(monkeypatch, tmp_path, output, cause):
    o = lookup(monkeypatch, tmp_path, 0, None, getcode_files=False, getcode_output=output)
    assert o["cause"] == cause, o
    assert o["sourcify"] == "no verified match"


def test_credential_output_is_never_called_unverified_even_with_no_sourcify_match(monkeypatch, tmp_path, capsys):
    o = lookup(monkeypatch, tmp_path, 0, None, getcode_output="Error! Missing/Invalid API Key")
    text = cd.describe_source_lookup(o)
    assert "unverified" not in text.lower() and "neither service has verified source" not in text
    assert "missing or invalid API key" in text and "not guaranteed" in text
    out = capsys.readouterr().out
    assert "Contract source unavailable" in out and "neither service has verified source" not in out


def test_silent_no_files_says_the_cause_is_not_established(monkeypatch, tmp_path):
    o = lookup(monkeypatch, tmp_path, 0, None, getcode_output="")
    text = cd.describe_source_lookup(o)
    assert "not established" in text and "neither service has verified source" not in text


def test_an_unreachable_sourcify_with_a_silent_explorer_is_connectivity_not_absence(monkeypatch, tmp_path):
    o = lookup(monkeypatch, tmp_path, source_fetcher.SourceUnavailable("connection refused"), None, getcode_output="")
    assert o["cause"] == "lookup_unreachable"


def test_the_tool_output_is_bounded_and_scrubbed_of_the_key(monkeypatch, tmp_path):
    monkeypatch.setenv("ETHERSCAN_API_KEY", KEY)
    o = lookup(monkeypatch, tmp_path, 0, None, getcode_output=f"Error! Invalid API Key {KEY} " + "x" * 5000)
    assert KEY not in repr(o) and len(o["explorer"]) < 400 and o["cause"] == "explorer_credentials"


def test_a_source_success_after_a_noisy_zero_exit_is_still_found(monkeypatch, tmp_path):
    o = lookup(monkeypatch, tmp_path, 0, None, getcode_files=True, getcode_output="Error! Invalid API Key (but files were written)")
    assert o["cause"] == "found"
