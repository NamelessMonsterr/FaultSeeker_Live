import argparse
import csv
import json
import os
from collections import Counter
from datetime import datetime


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_EXPLOIT_CSV = os.path.join(ROOT, "benchmark", "benchmark_classification_fixed.csv")
DEFAULT_SOURCES = os.path.join(ROOT, "benchmark", "dataset_sources.json")


def load_existing_exploits(path: str) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def summarize_rows(rows: list[dict]) -> dict:
    hashes = [row.get("txn_hash", "").strip().lower() for row in rows if row.get("txn_hash", "").strip()]
    chains = [row.get("chain", "").strip().lower() for row in rows if row.get("chain", "").strip()]
    vuln_types = [row.get("vuln_type", "").strip() for row in rows if row.get("vuln_type", "").strip()]
    return {
        "rows": len(rows),
        "unique_hashes": len(set(hashes)),
        "duplicates": sorted([item for item, count in Counter(hashes).items() if count > 1]),
        "chains": dict(Counter(chains).most_common()),
        "vulnerability_types": dict(Counter(vuln_types).most_common()),
    }


def build_manifest(exploit_csv: str, sources_path: str) -> dict:
    rows = load_existing_exploits(exploit_csv)
    with open(sources_path, encoding="utf-8") as f:
        sources = json.load(f)
    summary = summarize_rows(rows)
    targets = {
        "exploit_rows_target": 1000,
        "benign_rows_target_min": 10000,
        "benign_rows_target_preferred": 10000,
        "required_categories": [
            "reentrancy",
            "inflation",
            "flashloan",
            "oracle manipulation",
            "governance attack",
            "bridge exploit",
            "sandwich/mev",
            "access control",
            "precision loss",
            "delegatecall abuse",
        ],
    }
    gaps = {
        "exploit_rows_remaining": max(0, targets["exploit_rows_target"] - summary["rows"]),
        "benign_dataset_present": False,
        "baseline_results_present": False,
        "statistical_report_present": False,
    }
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "existing_exploit_csv": os.path.relpath(exploit_csv, ROOT),
        "summary": summary,
        "targets": targets,
        "gaps": gaps,
        "candidate_sources": sources,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the FaultSeeker++ research dataset expansion manifest.")
    parser.add_argument("--exploit-csv", default=DEFAULT_EXPLOIT_CSV)
    parser.add_argument("--sources", default=DEFAULT_SOURCES)
    parser.add_argument("--output", default=os.path.join(ROOT, "benchmark", "research_dataset_manifest.json"))
    args = parser.parse_args()

    manifest = build_manifest(args.exploit_csv, args.sources)
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(json.dumps(manifest["summary"], indent=2))
    print(f"Manifest written to {args.output}")


if __name__ == "__main__":
    main()
