"""
tests/test_pipeline_parse.py
Unit tests for FaultSeekerPipeline._parse_txn_link() (Gap 5: Multi-Chain).
Verifies all 8 supported chains and invalid input handling.
"""

import pytest
from faultseeker.core.pipeline import FaultSeekerPipeline

VALID_HASH = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"


# ── Valid Chain URLs ──────────────────────────────────────────────────────────

class TestParseValidChains:

    @pytest.mark.parametrize("url,expected_chain", [
        # Ethereum
        (f"https://etherscan.io/tx/{VALID_HASH}", "eth"),
        # BSC
        (f"https://bscscan.com/tx/{VALID_HASH}", "bsc"),
        # Polygon
        (f"https://polygonscan.com/tx/{VALID_HASH}", "polygon"),
        # Arbitrum
        (f"https://arbiscan.io/tx/{VALID_HASH}", "arbitrum"),
        # Optimism
        (f"https://optimistic.etherscan.io/tx/{VALID_HASH}", "optimism"),
        # Avalanche
        (f"https://snowtrace.io/tx/{VALID_HASH}", "avalanche"),
        # Base
        (f"https://basescan.org/tx/{VALID_HASH}", "base"),
        # Fantom
        (f"https://ftmscan.com/tx/{VALID_HASH}", "fantom"),
    ])
    def test_correct_chain_detected(self, url, expected_chain):
        txn_hash, chain = FaultSeekerPipeline._parse_txn_link(url)
        assert chain == expected_chain, f"URL: {url}\nExpected: {expected_chain}, Got: {chain}"

    @pytest.mark.parametrize("url", [
        f"https://etherscan.io/tx/{VALID_HASH}",
        f"https://bscscan.com/tx/{VALID_HASH}",
        f"https://polygonscan.com/tx/{VALID_HASH}",
    ])
    def test_correct_hash_extracted(self, url):
        txn_hash, chain = FaultSeekerPipeline._parse_txn_link(url)
        assert txn_hash == VALID_HASH

    def test_bare_hash_with_chain_keyword_eth(self):
        """Hash embedded directly with eth keyword in URL."""
        url = f"https://eth.example.com/tx/{VALID_HASH}"
        txn_hash, chain = FaultSeekerPipeline._parse_txn_link(url)
        assert chain == "eth"
        assert txn_hash == VALID_HASH

    def test_case_insensitive_url(self):
        """Chain detection should be case-insensitive."""
        url = f"https://ETHERSCAN.IO/tx/{VALID_HASH}"
        txn_hash, chain = FaultSeekerPipeline._parse_txn_link(url)
        assert chain == "eth"


# ── Invalid Input Handling ────────────────────────────────────────────────────

class TestParseInvalidInput:

    def test_missing_hash_raises_value_error(self):
        with pytest.raises(ValueError, match="Could not extract transaction hash"):
            FaultSeekerPipeline._parse_txn_link("https://etherscan.io/tx/0x1234")

    def test_unsupported_chain_raises_value_error(self):
        with pytest.raises(ValueError, match="not supported"):
            FaultSeekerPipeline._parse_txn_link(
                f"https://solscan.io/tx/{VALID_HASH}"
            )

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError):
            FaultSeekerPipeline._parse_txn_link("")

    def test_hash_too_short_raises_value_error(self):
        """A 63-char hex string should not match the 64-char pattern."""
        short_hash = "0x" + "a" * 63
        with pytest.raises(ValueError, match="Could not extract transaction hash"):
            FaultSeekerPipeline._parse_txn_link(
                f"https://etherscan.io/tx/{short_hash}"
            )

    def test_hash_exactly_64_chars_is_valid(self):
        """A 64-char hex hash should parse successfully."""
        url = f"https://etherscan.io/tx/{VALID_HASH}"
        txn_hash, chain = FaultSeekerPipeline._parse_txn_link(url)
        assert len(txn_hash) == 66  # '0x' + 64 hex chars


# ── BSC vs Polygon Disambiguation ─────────────────────────────────────────────

class TestChainDisambiguation:

    def test_bscscan_not_detected_as_eth(self):
        """bscscan contains 'bsc' first in chain_map and must not match 'eth'."""
        url = f"https://bscscan.com/tx/{VALID_HASH}"
        _, chain = FaultSeekerPipeline._parse_txn_link(url)
        assert chain == "bsc"
        assert chain != "eth"

    def test_optimism_on_etherscan_subdomain(self):
        """optimistic.etherscan.io should match 'optimism', not 'eth'."""
        url = f"https://optimistic.etherscan.io/tx/{VALID_HASH}"
        _, chain = FaultSeekerPipeline._parse_txn_link(url)
        assert chain == "optimism"
