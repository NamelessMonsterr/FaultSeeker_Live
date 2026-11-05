import csv
import random

from benchmark.build_candidate_exploit_expansion import build_candidate_rows
from benchmark.research_readiness_report import _candidate_expansion_summary
from benchmark.validate_benign_dataset import validate_benign_dataset
from benchmark.validate_imported_incidents import split_hashes


def test_split_hashes_fuzz_rejects_near_misses():
    rng = random.Random(1337)
    valid_hashes = {"0x" + f"{idx:064x}" for idx in range(20)}
    invalid_values = {
        "0x" + "g" * 64,
        "0x" + "a" * 63,
        "0x" + "b" * 65,
        "0x" + "c" * 32 + " " + "c" * 32,
        "not-a-hash",
        "",
    }
    tokens = list(valid_hashes | invalid_values)
    rng.shuffle(tokens)

    parsed = split_hashes("|".join(tokens))

    assert parsed == sorted(valid_hashes)


def test_large_benign_dataset_validation_meets_minimum_and_detects_duplicates(tmp_path):
    path = tmp_path / "large_benign.csv"
    duplicate_hash = "0x" + "f" * 64
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["txn_hash", "chain", "benign_category", "source", "validation_status"],
        )
        writer.writeheader()
        for idx in range(5001):
            writer.writerow(
                {
                    "txn_hash": duplicate_hash if idx in {100, 200} else "0x" + f"{idx:064x}",
                    "chain": "eth" if idx % 2 == 0 else "arbitrum",
                    "benign_category": ["swap", "liquidation", "staking"][idx % 3],
                    "source": "synthetic-test",
                    "validation_status": "verified",
                }
            )

    summary = validate_benign_dataset(str(path))

    assert summary["rows"] == 5001
    assert summary["meets_minimum_size"] is False
    assert summary["meets_preferred_size"] is False
    assert summary["duplicate_hashes"] == 1
    assert summary["chain_counts"] == {"eth": 2501, "arbitrum": 2500}


def test_candidate_expansion_dedupes_same_tx_same_chain_but_keeps_cross_chain(tmp_path):
    tx_hash = "0x" + "a" * 64
    manifest = tmp_path / "manifest.csv"
    manifest.write_text(
        "\n".join(
            [
                "source,incident_id,title,chains,vulnerability_type,transaction_hashes,tx_count,overlap_verified_benchmark,validation_status,required_next_steps",
                f"test,incident-1,One,Ethereum,Reentrancy,{tx_hash},1,,candidate_manual_review,review",
                f"test,incident-2,Two,Ethereum,Reentrancy,{tx_hash},1,,candidate_manual_review,review",
                f"test,incident-3,Three,Arbitrum One,Reentrancy,{tx_hash},1,,candidate_manual_review,review",
            ]
        ),
        encoding="utf-8",
    )

    rows, summary = build_candidate_rows(str(manifest))

    assert len(rows) == 2
    assert summary["candidate_rows"] == 2
    assert {(row["candidate_tx_hash"], row["candidate_chain"]) for row in rows} == {
        (tx_hash, "eth"),
        (tx_hash, "arbitrum"),
    }


def test_empty_benign_csv_reports_all_required_fields_missing(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("", encoding="utf-8")

    summary = validate_benign_dataset(str(path))

    assert summary["rows"] == 0
    assert summary["missing_required_fields"] == [
        "txn_hash",
        "chain",
        "benign_category",
        "source",
        "validation_status",
    ]
    assert summary["duplicate_hashes"] == 0


def test_benign_dataset_reports_schema_and_duplicates(tmp_path):
    path = tmp_path / "benign.csv"
    path.write_text(
        "\n".join(
            [
                "txn_hash,chain,benign_category,source,validation_status",
                "0x" + "1" * 64 + ",eth,swap,test,verified",
                "0x" + "1" * 64 + ",eth,swap,test,verified",
            ]
        ),
        encoding="utf-8",
    )

    summary = validate_benign_dataset(str(path))

    assert summary["rows"] == 2
    assert summary["missing_required_fields"] == []
    assert summary["duplicate_hashes"] == 1
    assert summary["meets_minimum_size"] is False


def test_benign_dataset_reports_missing_required_fields(tmp_path):
    path = tmp_path / "benign_missing.csv"
    path.write_text(
        "\n".join(
            [
                "txn_hash,chain,source",
                "0x" + "2" * 64 + ",eth,test",
            ]
        ),
        encoding="utf-8",
    )

    summary = validate_benign_dataset(str(path))

    assert summary["missing_required_fields"] == ["benign_category", "validation_status"]
    assert summary["category_counts"] == {"UNKNOWN": 1}


def test_candidate_expansion_ignores_malformed_manifest_rows_without_crashing(tmp_path):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text(
        "\n".join(
            [
                "source,incident_id,title,chains,vulnerability_type,transaction_hashes,tx_count,overlap_verified_benchmark,validation_status,required_next_steps",
                "test,missing-hash,Missing,Ethereum,Reentrancy,,0,,candidate_manual_review,review",
                "test,wrong-status,Wrong,Ethereum,Reentrancy,0x" + "1" * 64 + ",1,,blocked_missing_transaction_hash,skip",
            ]
        ),
        encoding="utf-8",
    )

    rows, summary = build_candidate_rows(str(manifest))

    assert rows == []
    assert summary["candidate_rows"] == 0
    assert summary["supported_candidate_rows"] == 0


def test_readiness_summary_handles_corrupt_json_without_crashing(tmp_path):
    corrupt = tmp_path / "summary.json"
    corrupt.write_text("{not-json", encoding="utf-8")

    summary = _candidate_expansion_summary(str(corrupt))

    assert summary["exists"] is True
    assert "parse_error" in summary
