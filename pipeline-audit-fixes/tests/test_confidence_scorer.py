"""
tests/test_confidence_scorer.py
Unit tests for the ConfidenceScorer engine (Gap 4).
Covers: score range, component methods, thresholds, sort order.
"""

import pytest
from faultseeker.core.confidence_scorer import (
    ConfidenceScorer,
    ConfidenceScore,
    CONFIDENCE_LEVELS,
    generate_evidence_card,
)


# â”€â”€ Fixtures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@pytest.fixture
def scorer():
    return ConfidenceScorer()


@pytest.fixture
def sample_func():
    return {
        'function': 'flashLoan',
        'address': '0xdeadbeef00000000000000000000000000000001',
        'depth': 3,
        'evidence': ['flash loan detected', 'reentrancy callback found', 'balance changed'],
        'confidence_score': [0.8, 'high'],
    }


@pytest.fixture
def sample_forensics():
    return {
        'repeated_patterns': [{'function': 'flashLoan'}],
        'balance_change': {'0xdeadbeef00000000000000000000000000000001': {'eth': -100}},
        'potential_attacker': ['0xdeadbeef00000000000000000000000000000001'],
        'potential_victim': ['0xvictim00000000000000000000000000000001'],
    }


# â”€â”€ score_function() â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestScoreFunction:

    def test_returns_confidence_score_object(self, scorer, sample_func, sample_forensics):
        result = scorer.score_function(sample_func, sample_forensics)
        assert isinstance(result, ConfidenceScore)

    def test_overall_in_unit_range(self, scorer, sample_func, sample_forensics):
        result = scorer.score_function(sample_func, sample_forensics)
        assert 0.0 <= result.overall <= 1.0

    def test_all_components_in_unit_range(self, scorer, sample_func, sample_forensics):
        result = scorer.score_function(sample_func, sample_forensics)
        for component in (result.pattern_match, result.code_evidence,
                          result.txn_consistency, result.llm_confidence):
            assert 0.0 <= component <= 1.0, f"Component out of range: {component}"

    def test_level_is_valid_string(self, scorer, sample_func, sample_forensics):
        result = scorer.score_function(sample_func, sample_forensics)
        valid_levels = {level for _, level, _ in CONFIDENCE_LEVELS}
        assert result.level in valid_levels

    def test_explanation_is_non_empty_list(self, scorer, sample_func, sample_forensics):
        result = scorer.score_function(sample_func, sample_forensics)
        assert isinstance(result.explanation, list)
        assert len(result.explanation) > 0

    def test_empty_func_no_crash(self, scorer):
        result = scorer.score_function({}, {})
        assert 0.0 <= result.overall <= 1.0


# â”€â”€ Component Methods â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestComponents:

    def test_pattern_match_flash_loan_keyword(self, scorer):
        func = {'evidence': ['flash loan borrow detected'], 'function': 'flashLoan'}
        forensics = {'repeated_patterns': [], 'balance_change': {},
                     'potential_attacker': [], 'potential_victim': []}
        score = scorer._compute_pattern_match(func, forensics)
        assert score > 0.0

    def test_pattern_match_caps_at_one(self, scorer):
        # Fill evidence with every known pattern keyword
        all_keywords = ['reentrancy', 'flash loan', 'price', 'access', 'overflow',
                        'logic', 'governance', 'bridge', 'donation', 'sandwich',
                        'rugpull', 'signature', 'inflation', 'precision', 'proxy']
        func = {'evidence': all_keywords, 'function': 'attack',
                'repeated_patterns': [{'function': 'attack'}]}
        forensics = {'repeated_patterns': [{'function': 'attack'}],
                     'balance_change': {}, 'potential_attacker': [], 'potential_victim': []}
        score = scorer._compute_pattern_match(func, forensics)
        assert score <= 1.0

    def test_llm_confidence_numeric(self, scorer):
        func = {'confidence_score': [0.9, 0.7]}
        score = scorer._compute_llm_confidence(func)
        assert abs(score - 0.8) < 0.01

    def test_llm_confidence_text_labels(self, scorer):
        func = {'confidence_score': ['high', 'very high']}
        score = scorer._compute_llm_confidence(func)
        assert score > 0.5

    def test_llm_confidence_percentage_string(self, scorer):
        func = {'confidence_score': ['80%']}
        score = scorer._compute_llm_confidence(func)
        assert abs(score - 0.8) < 0.01

    def test_llm_confidence_no_scores_returns_neutral(self, scorer):
        func = {'confidence_score': []}
        score = scorer._compute_llm_confidence(func)
        assert score == 0.5

    def test_txn_consistency_attacker_boost(self, scorer):
        address = '0xattacker0000000000000000000000000000001'
        func = {'address': address, 'depth': 2}
        forensics = {
            'balance_change': {'eth': -500},
            'potential_attacker': [address],
            'potential_victim': [],
        }
        score = scorer._compute_txn_consistency(func, forensics)
        assert score > 0.4  # Should be above neutral

    def test_code_evidence_no_contract_info(self, scorer):
        func = {'address': '0x1234', 'evidence': []}
        score = scorer._compute_code_evidence(func, None)
        assert 0.0 <= score <= 1.0


# â”€â”€ Confidence Level Thresholds â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestConfidenceLevels:

    @pytest.mark.parametrize("score,expected_level", [
        (0.95, "very_high"),
        (0.80, "high"),
        (0.60, "moderate"),
        (0.40, "low"),
        (0.10, "very_low"),
    ])
    def test_threshold_classification(self, scorer, score, expected_level):
        level = scorer._classify(score)
        assert level == expected_level


# â”€â”€ score_all() sort order â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestScoreAll:

    def test_results_sorted_descending_by_overall(self, scorer, sample_forensics):
        funcs = [
            {'function': 'f1', 'address': '0x1', 'depth': 1,
             'evidence': ['logic error'], 'confidence_score': [0.3]},
            {'function': 'f2', 'address': '0x2', 'depth': 5,
             'evidence': ['flash loan', 'reentrancy', 'price manipulation'],
             'confidence_score': [0.9]},
            {'function': 'f3', 'address': '0x3', 'depth': 2,
             'evidence': ['access control'], 'confidence_score': [0.6]},
        ]
        results = scorer.score_all(funcs, sample_forensics)
        scores = [r['confidence']['overall'] for r in results]
        assert scores == sorted(scores, reverse=True), \
            f"Results not sorted descending: {scores}"

    def test_returns_list_of_dicts(self, scorer, sample_forensics):
        results = scorer.score_all([], sample_forensics)
        assert isinstance(results, list)

    def test_each_result_has_confidence_key(self, scorer, sample_func, sample_forensics):
        results = scorer.score_all([sample_func], sample_forensics)
        assert len(results) == 1
        assert 'confidence' in results[0]
        assert 'overall' in results[0]['confidence']


# â”€â”€ generate_evidence_card() â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGenerateEvidenceCard:

    def test_card_has_required_keys(self, sample_func):
        confidence = {'overall': 0.8, 'level': 'high', 'components': {}, 'explanation': []}
        card = generate_evidence_card(sample_func, confidence)
        assert 'function_signature' in card
        assert 'confidence' in card
        assert 'evidence' in card
        assert 'analyst_notes' in card

    def test_function_signature_fields(self, sample_func):
        card = generate_evidence_card(sample_func, {})
        sig = card['function_signature']
        assert sig['function'] == sample_func['function']
        assert sig['address'] == sample_func['address']
        assert sig['call_depth'] == sample_func['depth']


@pytest.mark.parametrize("value,expected", [("0.5%", 0.005), ("1%", 0.01), ("2%", 0.02), ("80%", 0.8), ("NaN", 0.5), (float("nan"), 0.5), (float("inf"), 0.5), (True, 0.5), (False, 0.5)])
def test_confidence_percent_and_invalid_numbers(value, expected):
    assert ConfidenceScorer()._compute_llm_confidence({"confidence_score": [value]}) == pytest.approx(expected)


@pytest.mark.parametrize("patterns,expected", [
    ({"keys": [], "keys_function_only": []}, 0.0),
    ({"keys": [], "keys_function_only": [{"pattern": ["foo"], "repeats": 3}]}, 0.5),
])
def test_pattern_scoring_uses_actual_trace_analyzer_schema(scorer, patterns, expected):
    assert scorer._compute_pattern_match({"function": "foo", "evidence": []}, {"repeated_patterns": patterns}) == expected


@pytest.mark.parametrize("source", [{}, {"foo": []}, {"bar": [{"content": "unrelated source"}]}])
def test_empty_or_other_function_source_does_not_boost_code_evidence(scorer, source):
    finding = {"address": "0x1234", "function": "foo", "evidence": []}
    assert scorer._compute_code_evidence(finding, {"0x1234": source}) <= scorer._compute_code_evidence(finding, None)


def test_actual_downloader_function_content_is_recognized(scorer):
    finding = {"address": "0x1234", "function": "foo", "evidence": []}
    info = {"0x1234": {"foo": [{"content": "contract C { function foo() external {} }"}]}}
    assert scorer._compute_code_evidence(finding, info) == pytest.approx(.8)
