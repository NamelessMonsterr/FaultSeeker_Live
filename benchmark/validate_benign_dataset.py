import argparse
import csv
import json
import os
from collections import Counter


REQUIRED_FIELDS = ["txn_hash", "chain", "benign_category", "source", "validation_status"]
TARGET_MIN_ROWS = 10000
TARGET_PREFERRED_ROWS = 10000


def validate_benign_dataset(path: str) -> dict:
    rows = load_csv(path)
    fieldnames = set(rows[0].keys()) if rows else set(read_header(path))
    missing_fields = [field for field in REQUIRED_FIELDS if field not in fieldnames]
    tx_hashes = [row.get("txn_hash", "").strip().lower() for row in rows if row.get("txn_hash", "").strip()]
    hash_counts = Counter(tx_hashes)
    duplicate_hashes = sorted(tx for tx, count in hash_counts.items() if count > 1)
    category_counts: dict[str, int] = {}
    chain_counts: dict[str, int] = {}
    for row in rows:
        category = row.get("benign_category", "").strip() or "UNKNOWN"
        chain = row.get("chain", "").strip().lower() or "unknown"
        category_counts[category] = category_counts.get(category, 0) + 1
        chain_counts[chain] = chain_counts.get(chain, 0) + 1
    return {
        "path": path,
        "rows": len(rows),
        "missing_required_fields": missing_fields,
        "duplicate_hashes": len(duplicate_hashes),
        "duplicate_hash_examples": duplicate_hashes[:10],
        "target_min_rows": TARGET_MIN_ROWS,
        "target_preferred_rows": TARGET_PREFERRED_ROWS,
        "meets_minimum_size": len(rows) >= TARGET_MIN_ROWS,
        "meets_preferred_size": len(rows) >= TARGET_PREFERRED_ROWS,
        "chain_counts": sort_counts(chain_counts),
        "category_counts": sort_counts(category_counts),
    }


def load_csv(path: str) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def read_header(path: str) -> list[str]:
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        return next(reader, [])


def sort_counts(counts: dict[str, int]) -> dict[str, int]:
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a benign transaction dataset for false-positive evaluation.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--summary-output", default=None)
    args = parser.parse_args()

    summary = validate_benign_dataset(args.input)
    if args.summary_output:
        os.makedirs(os.path.dirname(args.summary_output) or ".", exist_ok=True)
        with open(args.summary_output, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
