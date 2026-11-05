import argparse
import csv
import json
import os
from collections import Counter


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPLOIT_CSV = os.path.join(ROOT, "benchmark", "benchmark_classification_fixed.csv")
SOURCES_JSON = os.path.join(ROOT, "benchmark", "dataset_sources.json")
STAGED_IMPORT_CSV = os.path.join(ROOT, "benchmark", "imported", "defihacklabs_incidents.sample.csv")
FULL_IMPORT_CSV = os.path.join(ROOT, "benchmark", "imported", "defihacklabs_incidents.full.csv")
DEFILLAMA_IMPORT_CSV = os.path.join(ROOT, "benchmark", "imported", "defillama_hacks.full.csv")
RUGPULL_IMPORT_CSV = os.path.join(ROOT, "benchmark", "imported", "rugpull_contract_incidents.csv")
RUGPULL_SUMMARY_JSON = os.path.join(ROOT, "benchmark", "imported", "rugpull_contract_incidents_summary.json")
HF_BENIGN_IMPORT_CSV = os.path.join(ROOT, "benchmark", "imported", "hf_ethereum_benign_transactions.csv")
HF_BENIGN_SUMMARY_JSON = os.path.join(ROOT, "benchmark", "imported", "hf_ethereum_benign_transactions_summary.json")
FULL_IMPORT_SUMMARY_JSON = os.path.join(ROOT, "benchmark", "imported", "defihacklabs_validation_summary.full.json")
CANDIDATE_EXPANSION_SUMMARY_JSON = os.path.join(ROOT, "benchmark", "imported", "defihacklabs_candidate_expansion_summary.json")
GITHUB_CANDIDATE_SUMMARY_JSON = os.path.join(ROOT, "benchmark", "imported", "defihacklabs_github_candidates_summary.json")
RESEARCH_EXPLOIT_POOL_SUMMARY_JSON = os.path.join(ROOT, "benchmark", "research_exploit_pool_summary.json")
RESEARCH_DOCS = [
    os.path.join(ROOT, "docs", "research", "BASELINE_MATRIX.md"),
    os.path.join(ROOT, "docs", "research", "ABLATION_PROTOCOL.md"),
    os.path.join(ROOT, "docs", "research", "ERROR_TAXONOMY.md"),
    os.path.join(ROOT, "docs", "research", "REPRODUCIBILITY_CHECKLIST.md"),
    os.path.join(ROOT, "docs", "research", "BENIGN_DATA_ACQUISITION.md"),
]


def build_report(exploit_csv: str = EXPLOIT_CSV, sources_json: str = SOURCES_JSON) -> dict:
    rows = _load_csv(exploit_csv)
    with open(sources_json, encoding="utf-8") as f:
        sources = json.load(f)
    chains = Counter(row.get("chain", "").strip().lower() for row in rows)
    vuln_types = Counter(row.get("vuln_type", "").strip() for row in rows)
    candidate_summary = _candidate_expansion_summary()
    research_pool_summary = _research_exploit_pool_summary()
    benign_summary = _benign_dataset_summary()
    validated_plus_candidates = len(rows) + int(candidate_summary.get("candidate_rows", 0) or 0)
    return {
        "current_verified_exploit_rows": len(rows),
        "unique_transactions": len({row.get("txn_hash", "").strip().lower() for row in rows if row.get("txn_hash", "").strip()}),
        "chain_count": len([chain for chain in chains if chain]),
        "top_chains": dict(chains.most_common(10)),
        "top_vulnerability_types": dict(vuln_types.most_common(15)),
        "tdsc_targets": {
            "exploit_rows": 1000,
            "benign_rows_min": 10000,
            "benign_rows_preferred": 10000,
            "baseline_families": ["static", "dynamic_trace", "llm_only"],
            "required_statistics": ["bootstrap_ci", "paired_t_test", "wilcoxon_signed_rank", "mcnemar"],
        },
        "remaining_empirical_work": {
            "additional_verified_exploit_rows_needed": max(0, 1000 - len(rows)),
            "best_case_verified_rows_after_current_candidates": validated_plus_candidates,
            "additional_verified_rows_needed_after_current_candidates": max(0, 1000 - validated_plus_candidates),
            "research_pool_rows": int(research_pool_summary.get("rows", 0) or 0),
            "research_pool_target_met": bool(research_pool_summary.get("target_met", False)),
            "additional_research_pool_rows_needed": max(0, 1000 - int(research_pool_summary.get("rows", 0) or 0)),
            "benign_rows_needed_min": max(0, 10000 - int(benign_summary.get("rows", 0) or 0)),
            "run_baselines": True,
            "produce_final_ablation_tables": True,
            "conduct_human_explainability_study": True,
        },
        "staged_public_imports": _staged_import_summary(),
        "additional_incident_sources": {
            "defillama_hacks": _incident_source_summary(DEFILLAMA_IMPORT_CSV),
            "rugpull_contract_incidents": _rugpull_contract_summary(),
        },
        "benign_dataset": benign_summary,
        "public_import_validation": _public_import_validation_summary(),
        "candidate_expansion": candidate_summary,
        "github_candidate_expansion": _github_candidate_summary(),
        "research_exploit_pool": research_pool_summary,
        "research_artifacts": _research_artifact_summary(),
        "registered_public_sources": sources,
    }


def _load_csv(path: str) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return [
            {str(k or "").strip().lstrip("\ufeff").strip(chr(34)): v for k, v in row.items()}
            for row in csv.DictReader(f)
        ]


def _staged_import_summary(path: str | None = None) -> dict:
    path = path or (FULL_IMPORT_CSV if os.path.exists(FULL_IMPORT_CSV) else STAGED_IMPORT_CSV)
    if not os.path.exists(path):
        return {"path": path, "exists": False, "rows": 0, "rows_with_transaction_hashes": 0}
    rows = _load_csv(path)
    return {
        "path": path,
        "exists": True,
        "rows": len(rows),
        "rows_with_transaction_hashes": sum(1 for row in rows if _is_truthy(row.get("has_transaction_hash"))),
    }


def _incident_source_summary(path: str) -> dict:
    if not os.path.exists(path):
        return {"path": path, "exists": False, "rows": 0, "rows_with_transaction_hashes": 0}
    rows = _load_csv(path)
    return {
        "path": path,
        "exists": True,
        "rows": len(rows),
        "rows_with_transaction_hashes": sum(1 for row in rows if _is_truthy(row.get("has_transaction_hash"))),
        "blocked_missing_transaction_hash": sum(
            1 for row in rows if row.get("validation_status") == "blocked_missing_transaction_hash"
        ),
    }


def _rugpull_contract_summary(path: str = RUGPULL_SUMMARY_JSON) -> dict:
    summary = _load_optional_json_summary(path)
    if summary.get("exists"):
        return summary
    return _incident_source_summary(RUGPULL_IMPORT_CSV)


def _benign_dataset_summary(summary_path: str = HF_BENIGN_SUMMARY_JSON, csv_path: str = HF_BENIGN_IMPORT_CSV) -> dict:
    summary = _load_optional_json_summary(summary_path)
    if summary.get("exists"):
        return summary
    if not os.path.exists(csv_path):
        return {
            "path": csv_path,
            "exists": False,
            "rows": 0,
            "target_rows": 10000,
            "target_met": False,
        }
    rows = _load_csv(csv_path)
    return {
        "path": csv_path,
        "exists": True,
        "rows": len(rows),
        "target_rows": 10000,
        "target_met": len(rows) >= 10000,
    }


def _public_import_validation_summary(path: str = FULL_IMPORT_SUMMARY_JSON) -> dict:
    return _load_optional_json_summary(path)


def _candidate_expansion_summary(path: str = CANDIDATE_EXPANSION_SUMMARY_JSON) -> dict:
    return _load_optional_json_summary(path)


def _github_candidate_summary(path: str = GITHUB_CANDIDATE_SUMMARY_JSON) -> dict:
    return _load_optional_json_summary(path)


def _research_exploit_pool_summary(path: str = RESEARCH_EXPLOIT_POOL_SUMMARY_JSON) -> dict:
    return _load_optional_json_summary(path)


def _load_optional_json_summary(path: str) -> dict:
    if not os.path.exists(path):
        return {"path": path, "exists": False}
    try:
        with open(path, encoding="utf-8") as f:
            summary = json.load(f)
    except json.JSONDecodeError as exc:
        return {"path": path, "exists": True, "parse_error": str(exc)}
    return {"path": path, "exists": True, **summary}


def _research_artifact_summary(paths: list[str] = RESEARCH_DOCS) -> dict:
    return {
        os.path.relpath(path, ROOT).replace("\\", "/"): os.path.exists(path)
        for path in paths
    }


def _is_truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a FaultSeeker++ TDSC readiness report.")
    parser.add_argument("--output", default="benchmark/research_readiness_report.json")
    args = parser.parse_args()
    report = build_report()
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report["remaining_empirical_work"], indent=2))
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
