import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from statistics import mean
from typing import Iterable

try:
    from benchmark.research_readiness_report import ROOT
except ModuleNotFoundError:
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from faultseeker.research.statistics import bootstrap_ci


EXPLOIT_POOL = os.path.join(ROOT, "benchmark", "research_exploit_pool.csv")
BENIGN_CSV = os.path.join(ROOT, "benchmark", "imported", "hf_ethereum_benign_transactions.csv")
OUTPUT_DIR = os.path.join(ROOT, "reports", "external_baselines")
TEMPLATE = os.path.join(OUTPUT_DIR, "external_baseline_template.csv")

REQUIRED_COLUMNS = {
    "system",
    "txn_hash",
    "label",
    "prediction",
    "score",
    "runtime_ms",
    "token_cost_usd",
    "gpu_memory_mb",
}


def load_labels(exploit_pool: str = EXPLOIT_POOL, benign_csv: str = BENIGN_CSV, benign_limit: int = 10000) -> list[dict]:
    rows = []
    for row in read_csv(exploit_pool):
        rows.append(
            {
                "txn_hash": normalize_hash(row.get("txn_hash")),
                "chain": row.get("chain", ""),
                "label": 1,
                "category": row.get("vuln_type", "unknown"),
                "validation_status": row.get("validation_status", ""),
            }
        )
    for row in read_csv(benign_csv)[:benign_limit]:
        rows.append(
            {
                "txn_hash": normalize_hash(row.get("txn_hash")),
                "chain": row.get("chain", ""),
                "label": 0,
                "category": "benign",
                "validation_status": row.get("validation_status", ""),
            }
        )
    return rows


def write_template(path: str, rows: list[dict], systems: list[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fields = [
        "system",
        "txn_hash",
        "chain",
        "label",
        "category",
        "prediction",
        "score",
        "runtime_ms",
        "token_cost_usd",
        "gpu_memory_mb",
        "notes",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for system in systems:
            for row in rows:
                writer.writerow(
                    {
                        "system": system,
                        "txn_hash": row["txn_hash"],
                        "chain": row["chain"],
                        "label": row["label"],
                        "category": row["category"],
                        "prediction": "",
                        "score": "",
                        "runtime_ms": "",
                        "token_cost_usd": "",
                        "gpu_memory_mb": "",
                        "notes": "fill with external tool output",
                    }
                )


def ingest_results(path: str) -> tuple[list[dict], list[str]]:
    rows = read_csv(path)
    if not rows:
        return [], ["input file is empty"]
    missing = sorted(REQUIRED_COLUMNS - set(rows[0]))
    errors = [f"missing columns: {', '.join(missing)}"] if missing else []
    clean = []
    for index, row in enumerate(rows, start=2):
        system = row.get("system", "").strip()
        tx_hash = normalize_hash(row.get("txn_hash"))
        if not system:
            errors.append(f"line {index}: missing system")
            continue
        if not tx_hash.startswith("0x") or len(tx_hash) != 66:
            errors.append(f"line {index}: invalid txn_hash")
            continue
        label = parse_binary(row.get("label"))
        prediction = parse_binary(row.get("prediction"))
        if label is None:
            errors.append(f"line {index}: invalid label")
            continue
        if prediction is None:
            score = parse_float(row.get("score"))
            if score is None:
                errors.append(f"line {index}: prediction or score required")
                continue
            prediction = 1 if score >= 0.5 else 0
        # Preserve chain for per_chain_f1 grouping; empty string when absent.
        chain_field = str(row.get("chain") or "").strip().lower()
        clean.append(
            {
                "system": system,
                "txn_hash": tx_hash,
                "chain": chain_field,
                "label": label,
                "prediction": prediction,
                "score": parse_float(row.get("score")),
                "runtime_ms": parse_float(row.get("runtime_ms")),
                "token_cost_usd": parse_float(row.get("token_cost_usd")),
                "gpu_memory_mb": parse_float(row.get("gpu_memory_mb")),
            }
        )
    return clean, errors


def evaluate(rows: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[row["system"]].append(row)
    summaries = []
    for system, items in sorted(grouped.items()):
        labels = [row["label"] for row in items]
        preds = [row["prediction"] for row in items]
        tp = sum(1 for pred, label in zip(preds, labels) if pred == 1 and label == 1)
        fp = sum(1 for pred, label in zip(preds, labels) if pred == 1 and label == 0)
        tn = sum(1 for pred, label in zip(preds, labels) if pred == 0 and label == 0)
        fn = sum(1 for pred, label in zip(preds, labels) if pred == 0 and label == 1)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        ci_low, ci_high = bootstrap_ci(per_chain_f1(items), samples=400, seed=29)
        summaries.append(
            {
                "system": system,
                "transactions": len(items),
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "f1_ci_low": round(ci_low, 4),
                "f1_ci_high": round(ci_high, 4),
                "false_positive_rate": round(fpr, 4),
                "runtime_ms_mean": round_optional_mean(row["runtime_ms"] for row in items),
                "token_cost_usd_mean": round_optional_mean(row["token_cost_usd"] for row in items),
                "gpu_memory_mb_mean": round_optional_mean(row["gpu_memory_mb"] for row in items),
            }
        )
    return summaries


def per_chain_f1(rows: list[dict]) -> list[float]:
    """Compute per-chain F1 scores for bootstrap CI.

    Groups rows by the explicit 'chain' field. When chain is absent or empty,
    all such rows form a single unknown-chain bucket. Do not group by hash prefix:
    hex characters have no chain-identity semantics.
    """
    buckets: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        # Use validated chain field; fall back to explicit unknown marker so the
        # caller is aware that some rows lacked chain identity.
        chain_key = row.get("chain") or "unknown_chain"
        buckets[chain_key].append(row)
    values = []
    for items in buckets.values():
        tp = sum(1 for row in items if row["prediction"] == 1 and row["label"] == 1)
        fp = sum(1 for row in items if row["prediction"] == 1 and row["label"] == 0)
        fn = sum(1 for row in items if row["prediction"] == 0 and row["label"] == 1)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        values.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    return values or [0.0]


def write_csv(path: str, rows: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fields = list(rows[0].keys()) if rows else []
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: str) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_binary(value: object) -> int | None:
    text = str(value if value is not None else "").strip().lower()
    if text in {"1", "true", "yes", "exploit", "vulnerable", "positive"}:
        return 1
    if text in {"0", "false", "no", "benign", "safe", "negative"}:
        return 0
    return None


def parse_float(value: object) -> float | None:
    text = str(value if value is not None else "").strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def round_optional_mean(values: Iterable[float | None]) -> float | str:
    present = [value for value in values if value is not None]
    return round(mean(present), 4) if present else ""


def normalize_hash(value: object) -> str:
    text = str(value or "").strip().lower()
    return text if text.startswith("0x") else f"0x{text}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or score external baseline result files.")
    parser.add_argument("--input", help="CSV containing external baseline predictions.")
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    parser.add_argument("--make-template", action="store_true")
    parser.add_argument("--benign-limit", type=int, default=10000)
    parser.add_argument(
        "--systems",
        default="Slither,Mythril,TxSpector,GPTScan",
        help="Comma-separated systems for template creation.",
    )
    args = parser.parse_args()

    if args.make_template:
        rows = load_labels(benign_limit=args.benign_limit)
        systems = [item.strip() for item in args.systems.split(",") if item.strip()]
        write_template(os.path.join(args.output_dir, "external_baseline_template.csv"), rows, systems)
        print(json.dumps({"template_rows": len(rows) * len(systems), "systems": systems}, indent=2))
        return

    if not args.input:
        parser.error("--input is required unless --make-template is used")

    rows, errors = ingest_results(args.input)
    summaries = evaluate(rows) if rows else []
    os.makedirs(args.output_dir, exist_ok=True)
    if summaries:
        write_csv(os.path.join(args.output_dir, "external_baseline_summary.csv"), summaries)
    result = {
        "input": args.input,
        "rows": len(rows),
        "systems": sorted({row["system"] for row in rows}),
        "errors": errors,
        "summary_path": os.path.join(args.output_dir, "external_baseline_summary.csv") if summaries else "",
    }
    with open(os.path.join(args.output_dir, "external_baseline_ingest_report.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))
    if errors:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
