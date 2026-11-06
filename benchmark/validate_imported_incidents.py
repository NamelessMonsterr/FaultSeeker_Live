import argparse
import csv
import json
import os
import re
from typing import Iterable


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_IMPORTED = os.path.join(ROOT, "benchmark", "imported", "defihacklabs_incidents.full.csv")
DEFAULT_VERIFIED = os.path.join(ROOT, "benchmark", "benchmark_classification_fixed.csv")
DEFAULT_OUTPUT = os.path.join(ROOT, "benchmark", "imported", "defihacklabs_validation_manifest.csv")


MANIFEST_FIELDS = [
    "source",
    "incident_id",
    "title",
    "chains",
    "vulnerability_type",
    "transaction_hashes",
    "tx_count",
    "overlap_verified_benchmark",
    "validation_status",
    "required_next_steps",
]

TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")


def build_manifest(imported_csv: str, verified_csv: str) -> tuple[list[dict], dict]:
    verified_hashes = load_verified_hashes(verified_csv)
    rows = load_csv(imported_csv)
    manifest = [classify_imported_row(row, verified_hashes) for row in rows]
    summary = summarize_manifest(manifest)
    return manifest, summary


def classify_imported_row(row: dict, verified_hashes: set[str]) -> dict:
    tx_hashes = split_hashes(row.get("transaction_hashes", ""))
    overlaps = sorted(tx for tx in tx_hashes if tx in verified_hashes)
    if not tx_hashes:
        status = "blocked_missing_transaction_hash"
        next_steps = "Find a canonical exploit transaction hash before benchmark consideration."
    elif overlaps:
        status = "already_in_verified_benchmark"
        next_steps = "Use only as cross-source evidence for the existing verified row."
    else:
        status = "candidate_manual_review"
        next_steps = "Verify chain, transaction hash, label, source URL, trace availability, and duplicate incident status."
    return {
        "source": row.get("source", ""),
        "incident_id": row.get("incident_id", ""),
        "title": row.get("title", ""),
        "chains": row.get("chains", ""),
        "vulnerability_type": row.get("vulnerability_type", ""),
        "transaction_hashes": "|".join(tx_hashes),
        "tx_count": len(tx_hashes),
        "overlap_verified_benchmark": "|".join(overlaps),
        "validation_status": status,
        "required_next_steps": next_steps,
    }


def summarize_manifest(manifest: Iterable[dict]) -> dict:
    rows = list(manifest)
    status_counts: dict[str, int] = {}
    chain_counts: dict[str, int] = {}
    vuln_counts: dict[str, int] = {}
    unique_candidate_hashes = set()
    for row in rows:
        status = row.get("validation_status", "")
        status_counts[status] = status_counts.get(status, 0) + 1
        for chain in split_pipe(row.get("chains", "")):
            chain_counts[chain] = chain_counts.get(chain, 0) + 1
        vuln = row.get("vulnerability_type", "").strip()
        if vuln:
            vuln_counts[vuln] = vuln_counts.get(vuln, 0) + 1
        if status == "candidate_manual_review":
            unique_candidate_hashes.update(split_hashes(row.get("transaction_hashes", "")))
    return {
        "rows": len(rows),
        "status_counts": dict(sorted(status_counts.items())),
        "candidate_unique_transaction_hashes": len(unique_candidate_hashes),
        "top_chains": top_counts(chain_counts),
        "top_vulnerability_types": top_counts(vuln_counts),
    }


def load_verified_hashes(path: str) -> set[str]:
    return {
        row.get("txn_hash", "").strip().lower()
        for row in load_csv(path)
        if row.get("txn_hash", "").strip()
    }


def load_csv(path: str) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(rows: list[dict], output_csv: str) -> None:
    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    with open(output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def split_hashes(value: str) -> list[str]:
    return sorted({item.strip().lower() for item in split_pipe(value) if TX_HASH_RE.fullmatch(item.strip())})


def split_pipe(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split("|") if item.strip()]


def top_counts(counts: dict[str, int], limit: int = 10) -> dict[str, int]:
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit])


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate staged public incident imports before benchmark merge.")
    parser.add_argument("--imported", default=DEFAULT_IMPORTED)
    parser.add_argument("--verified", default=DEFAULT_VERIFIED)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--summary-output", default=None)
    args = parser.parse_args()

    manifest, summary = build_manifest(args.imported, args.verified)
    write_csv(manifest, args.output)
    if args.summary_output:
        os.makedirs(os.path.dirname(args.summary_output) or ".", exist_ok=True)
        with open(args.summary_output, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
    print(json.dumps({"output": args.output, **summary}, indent=2))


if __name__ == "__main__":
    main()
