import argparse
import csv
import io
import json
import os
import urllib.request
from collections import Counter


SOURCE_URL = "https://raw.githubusercontent.com/dianxiang-sun/rug_pull_dataset/main/rugpull_dataset.csv"
DEFAULT_OUTPUT = "benchmark/imported/rugpull_contract_incidents.csv"
DEFAULT_SUMMARY_OUTPUT = "benchmark/imported/rugpull_contract_incidents_summary.json"

FIELDNAMES = [
    "source",
    "incident_id",
    "chain",
    "contract_address",
    "losses",
    "rugpull_type",
    "root_causes",
    "reporting_sources",
    "url",
    "validation_status",
    "required_next_steps",
]

CHAIN_MAP = {
    "ETH": "eth",
    "BSC": "bsc",
}


def import_rugpull_contracts(source_url: str = SOURCE_URL) -> tuple[list[dict], dict]:
    payload = urllib.request.urlopen(source_url, timeout=120).read().decode("utf-8-sig", errors="replace")
    rows = [normalize_row(row) for row in csv.DictReader(io.StringIO(payload))]
    rows = [row for row in rows if row]
    return rows, build_summary(rows)


def normalize_row(row: dict) -> dict | None:
    contract = row.get("address", "").strip().lower()
    chain = row.get("Chain", "").strip().upper()
    incident_id = row.get("No.", "").strip()
    if not contract or not incident_id:
        return None
    return {
        "source": "github:dianxiang-sun/rug_pull_dataset",
        "incident_id": f"rugpull-{incident_id}",
        "chain": CHAIN_MAP.get(chain, chain.lower()),
        "contract_address": contract,
        "losses": row.get("Losses", "").strip(),
        "rugpull_type": row.get("Type", "").strip(),
        "root_causes": row.get("Root Causes", "").strip(),
        "reporting_sources": row.get("Sources", "").strip(),
        "url": row.get("URL", "").strip(),
        "validation_status": "contract_incident_verified_tx_unresolved",
        "required_next_steps": "Resolve exploit transaction hashes from source reports before merging into tx benchmark.",
    }


def build_summary(rows: list[dict]) -> dict:
    return {
        "source": "github:dianxiang-sun/rug_pull_dataset",
        "rows": len(rows),
        "chain_counts": dict(Counter(row["chain"] for row in rows)),
        "type_counts": dict(Counter(row["rugpull_type"] for row in rows).most_common(20)),
        "rows_with_contract_addresses": sum(1 for row in rows if row["contract_address"]),
        "rows_with_transaction_hashes": 0,
        "validation_status_counts": dict(Counter(row["validation_status"] for row in rows)),
        "merge_guidance": (
            "Use as incident/contract evidence and manual resolution queue. "
            "Rows are not transaction-level exploit ground truth until tx hashes are resolved."
        ),
    }


def write_csv(path: str, rows: list[dict]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Import contract-level rug-pull incidents.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--summary-output", default=DEFAULT_SUMMARY_OUTPUT)
    args = parser.parse_args()

    rows, summary = import_rugpull_contracts()
    write_csv(args.output, rows)
    write_json(args.summary_output, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
