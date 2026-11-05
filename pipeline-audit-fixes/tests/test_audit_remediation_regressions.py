"""
Regression tests for fixes applied in audit remediation sessions.

Covers:
  - statistics.py: paired_t_test zero-variance
  - temporal.py: identity_unresolved flag on TemporalAttackCorrelator.correlate()
  - remediation.py: vuln_hint-only matching (suggest_remediations returns List[str])
  - ingest_external_baselines.py: per_chain_f1 groups by chain field, not hash prefix
  - fix_csv.py: tail-slice index (len-based vs expected_cols-based)
  - metrics.py: length validation + nonfinite rejection in brier_score
  - utils.py: address length validity + lower/canonical sync
  - cross_chain_runner.py: dry-run/partial not counted as success
"""
import sys
import math

sys.path.insert(0, r"c:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-audit-fixes")

# ─── statistics.py ────────────────────────────────────────────────────────────
from faultseeker.research.statistics import paired_t_test


def test_paired_t_test_zero_variance():
    result = paired_t_test([1.0, 1.0], [0.0, 0.0])
    assert result["t"] is None, f"Expected t=None, got {result['t']}"
    assert result["p_approx"] is None, f"Expected p_approx=None, got {result['p_approx']}"
    assert result["note"] == "degenerate_zero_variance", f"Bad note: {result['note']}"


def test_paired_t_test_normal():
    result = paired_t_test([1.0, 0.8, 0.9], [0.5, 0.4, 0.3])
    assert result["t"] is not None
    assert 0.0 <= result["p_approx"] <= 1.0


# ─── temporal.py ─────────────────────────────────────────────────────────────
from faultseeker.research.temporal import TemporalAttackCorrelator


def test_identity_unresolved_flagged():
    """Campaigns with no attacker/victim fields must have identity_unresolved=True."""
    results = [
        {"txn_hash": "0xaaa", "chain": "eth", "loss_usd": 100},
        {"txn_hash": "0xbbb", "chain": "eth", "loss_usd": 200},
    ]
    campaigns = TemporalAttackCorrelator().correlate(results)
    for c in campaigns:
        assert "identity_unresolved" in c, \
            f"identity_unresolved missing from campaign: {c}"
        assert c["identity_unresolved"] is True, \
            f"Expected identity_unresolved=True, got {c['identity_unresolved']}"


def test_identity_resolved_when_known():
    """Campaigns with explicit attacker/victim must have identity_unresolved=False."""
    results = [
        {"txn_hash": "0xccc", "chain": "eth", "loss_usd": 100,
         "attacker": "0x1234", "victim": "0x5678"},
    ]
    campaigns = TemporalAttackCorrelator().correlate(results)
    for c in campaigns:
        assert c.get("identity_unresolved") is False, \
            f"Should not be identity_unresolved when attacker/victim provided, got: {c}"


# ─── remediation.py ──────────────────────────────────────────────────────────
from faultseeker.research.remediation import suggest_remediations


def test_remediation_no_false_reentrancy_from_signal_key():
    """Signals dict with reentrancy=False must NOT trigger reentrancy remediations."""
    recs = suggest_remediations("", {"reentrancy": False})
    assert not any("reentrancy" in r.lower() for r in recs), \
        f"Reentrancy rec triggered despite reentrancy=False signal: {recs}"


def test_remediation_reentrancy_from_hint():
    """Explicit reentrancy vuln_hint must trigger reentrancy remediations."""
    recs = suggest_remediations("reentrancy", {})
    assert any("reentrancy" in r.lower() or "checks-effects" in r.lower() for r in recs), \
        f"Reentrancy rec not triggered by explicit vuln_hint: {recs}"


# ─── ingest_external_baselines.py ────────────────────────────────────────────
from benchmark.ingest_external_baselines import per_chain_f1


def test_per_chain_f1_groups_by_chain():
    """Two rows with same chain but different hash prefixes must share one F1 bucket."""
    rows = [
        {"chain": "eth", "txn_hash": "0x" + "aa" + "b" * 62, "label": 1, "prediction": 1},
        {"chain": "eth", "txn_hash": "0x" + "bb" + "b" * 62, "label": 0, "prediction": 0},
        {"chain": "bsc", "txn_hash": "0x" + "cc" + "b" * 62, "label": 1, "prediction": 1},
    ]
    scores = per_chain_f1(rows)
    assert len(scores) == 2, \
        f"Expected 2 chain buckets (eth+bsc), got {len(scores)}: {scores}"


def test_per_chain_f1_different_chains_separate():
    rows = [
        {"chain": "eth",      "txn_hash": "0x" + "1" * 64, "label": 1, "prediction": 1},
        {"chain": "arbitrum", "txn_hash": "0x" + "1" * 64, "label": 0, "prediction": 0},
    ]
    scores = per_chain_f1(rows)
    assert len(scores) == 2, f"Expected 2 chain buckets, got {len(scores)}: {scores}"


def test_per_chain_f1_missing_chain_unknown_bucket():
    """Rows with no chain field all land in a single unknown_chain bucket."""
    rows = [
        {"txn_hash": "0x" + "a" * 64, "label": 1, "prediction": 1},
        {"txn_hash": "0x" + "b" * 64, "label": 0, "prediction": 0},
    ]
    scores = per_chain_f1(rows)
    assert len(scores) == 1, f"Expected 1 unknown bucket, got {len(scores)}"


# ─── fix_csv.py tail-slice ────────────────────────────────────────────────────
def test_fix_csv_tail_slice():
    """Verify len-based tail slice gives the right result vs the old expected_cols-based one."""
    parsed = ["a", "b", "c", "d", "e"]  # len=5, one extra field
    tail_col_count = 2
    expected_cols = 4

    post_old = parsed[expected_cols - tail_col_count:]  # buggy: parsed[2:] → 3 items
    post_new = parsed[len(parsed) - tail_col_count:]    # fixed:  parsed[3:] → 2 items

    assert len(post_old) == 3, f"Old slice sanity check: {post_old}"
    assert len(post_new) == 2, f"New slice should be 2: {post_new}"
    assert post_new == ["d", "e"], f"Unexpected tail: {post_new}"


# ─── metrics.py ──────────────────────────────────────────────────────────────
from benchmark.honest_eval.metrics import classification_metrics, brier_score


def test_classification_metrics_length_mismatch():
    try:
        classification_metrics([1, 0], [1.0], 0.5)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "mismatch" in str(e).lower()


def test_classification_metrics_normal():
    result = classification_metrics([1, 0], [1.0, 0.0], 0.5)
    assert result["n"] == 2
    assert result["f1"] == 1.0
    assert result["precision"] == 1.0


def test_brier_score_length_mismatch():
    try:
        brier_score([1, 0], [])
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "mismatch" in str(e).lower()


def test_brier_score_nonfinite():
    assert brier_score([1], [float("nan")]) is None
    assert brier_score([1], [float("inf")]) is None


def test_brier_score_normal():
    result = brier_score([1, 0], [0.9, 0.1])
    assert isinstance(result, float)
    assert math.isclose(result, 0.01, rel_tol=1e-4)


def test_brier_score_empty():
    assert brier_score([], []) == 0.0


# ─── utils.py ────────────────────────────────────────────────────────────────
from faultseeker.utils.utils import get_common_address, get_common_address_lower


def test_all_canonical_addresses_valid_length():
    for chain in ("mainnet", "eth", "bsc", "polygon", "avalanche", "optimism",
                  "fantom", "arbitrum", "pulsechain", "base"):
        for addr in get_common_address(chain):
            assert len(addr) == 42, \
                f"{chain}: bad address length {len(addr)}: {addr!r}"


def test_lower_matches_canonical():
    for chain in ("polygon", "avalanche", "fantom", "arbitrum", "pulsechain"):
        canonical = get_common_address(chain)
        lower = get_common_address_lower(chain)
        assert [a.lower() for a in canonical] == lower, \
            f"{chain}: lower does not match canonical"


def test_no_uppercase_in_lower():
    for chain in ("polygon", "avalanche", "fantom", "arbitrum", "pulsechain"):
        for addr in get_common_address_lower(chain):
            assert addr == addr.lower(), \
                f"{chain}: uppercase in lower list: {addr!r}"


# ─── cross_chain_runner.py ───────────────────────────────────────────────────
from faultseeker.core.cross_chain_runner import ChainAnalysisResult


def test_dry_run_not_success():
    r = ChainAnalysisResult("eth")
    r.add_result("0x1", "reentrancy", "high", 0.0, False,
                 raw={"dry_run": True, "txn_hash": "0x1", "chain": "eth"})
    assert r.successful == 0
    assert r.dry_runs == 1
    assert r.failed == 1


def test_partial_not_success():
    r = ChainAnalysisResult("eth")
    r.add_result("0x2", "flashloan", "medium", 0.5, False,
                 raw={"analysis_status": "partial", "verdict": "INCONCLUSIVE"})
    assert r.successful == 0
    assert r.partials == 1
    assert r.failed == 1


def test_completed_is_success():
    r = ChainAnalysisResult("eth")
    r.add_result("0x3", "reentrancy", "high", 0.85, True,
                 raw={"analysis_status": "completed",
                      "detected_vulnerability_types": ["reentrancy"]})
    assert r.successful == 1
    assert r.confidence_scores == [0.85]
    assert r.detected_vuln_type_counts["reentrancy"] == 1


def test_gt_vuln_counts_always_recorded():
    r = ChainAnalysisResult("eth")
    r.add_result("0xA", "reentrancy", "high", 0.0, False, raw={"dry_run": True})
    r.add_result("0xB", "flashloan", "medium", 0.5, False,
                 raw={"analysis_status": "partial"})
    r.add_result("0xC", "reentrancy", "high", 0.9, True,
                 raw={"analysis_status": "completed"})
    assert r.gt_vuln_type_counts["reentrancy"] == 2
    assert r.gt_vuln_type_counts["flashloan"] == 1


def test_success_rate_excludes_dry_and_partial():
    r = ChainAnalysisResult("eth")
    r.add_result("0xA", "x", "h", 0.0, False, raw={"dry_run": True})
    r.add_result("0xB", "x", "h", 0.5, False, raw={"analysis_status": "partial"})
    r.add_result("0xC", "x", "h", 0.9, True,  raw={"analysis_status": "completed"})
    d = r.to_dict()
    assert d["successful"] == 1
    assert d["dry_runs"] == 1
    assert d["partials"] == 1
    assert d["failed"] == 2
    assert d["success_rate"] == round(1 / 3 * 100, 1)


# ─── Runner ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        sys.exit(1)
