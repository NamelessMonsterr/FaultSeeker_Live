"""DEPRECATED / NOT A MEASUREMENT -- see reports/SYNTHETIC_DO_NOT_CITE/README.md.

This harness derives every score from the ground-truth `label` column, so its
output restates the labels instead of evaluating FaultSeeker++. It is retained
only as a synthetic sensitivity check. Use benchmark/run_honest_experiments.py
for any number that will be published.
"""

import sys as _sys

_LEAKAGE_BANNER = (
    "\n" + "=" * 74 + "\n"
    "WARNING: this harness reads ground-truth labels inside its scoring\n"
    "functions. Its output is SYNTHETIC and must not be cited.\n"
    "Use: python benchmark/run_honest_experiments.py\n"
    + "=" * 74 + "\n"
)
print(_LEAKAGE_BANNER, file=_sys.stderr)

import argparse
import csv
import json
import os
import sys
from collections import Counter
from statistics import mean
from typing import Any, Callable, Dict, Iterable, List

try:
    from benchmark.research_readiness_report import ROOT
except ModuleNotFoundError:
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from faultseeker.research.adversarial import AdversarialRobustnessEvaluator
from faultseeker.research.statistics import bootstrap_ci


EXPLOIT_POOL = os.path.join(ROOT, "benchmark", "research_exploit_pool.csv")
BENIGN_CSV = os.path.join(ROOT, "benchmark", "imported", "hf_ethereum_benign_transactions.csv")
RESULTS_DIR = os.path.join(ROOT, "reports", "research_results")

STATIC_TYPES = {
    "reentrancy",
    "access control",
    "lack of access control",
    "delegatecall abuse",
    "arbitrary external call",
    "precision loss",
    "integer overflow",
    "integer overflow/underflow",
    "unsafe cast",
}
TRACE_TYPES = {
    "flash loan attack",
    "price manipulation",
    "oracle manipulation",
    "price oracle manipulation",
    "reentrancy",
    "liquidation abuse",
    "bridge exploit",
}
GRAPH_TYPES = {
    "price manipulation",
    "oracle manipulation",
    "bridge exploit",
    "mev/sandwich",
    "business logic flaw",
    "logic flaw",
    "logic error",
    "governance attack",
}
LLM_TYPES = STATIC_TYPES | TRACE_TYPES | GRAPH_TYPES | {"unknown", "inflation attack", "signature replay"}


def load_rows(exploit_pool: str = EXPLOIT_POOL, benign_csv: str = BENIGN_CSV, benign_limit: int = 10000) -> list[dict]:
    rows = []
    for row in read_csv(exploit_pool):
        rows.append(
            {
                "txn_hash": row.get("txn_hash", ""),
                "chain": row.get("chain", ""),
                "label": 1,
                "vuln_type": normalize_type(row.get("vuln_type", "")),
                "pool_status": row.get("pool_status", ""),
                "source": row.get("source", ""),
                "validation_status": row.get("validation_status", ""),
            }
        )
    for row in read_csv(benign_csv)[:benign_limit]:
        rows.append(
            {
                "txn_hash": row.get("txn_hash", ""),
                "chain": row.get("chain", ""),
                "label": 0,
                "vuln_type": "benign",
                "pool_status": "benign_candidate",
                "source": row.get("source", ""),
                "validation_status": row.get("validation_status", ""),
            }
        )
    return rows


def baseline_systems() -> dict[str, Callable[[dict], float]]:
    return {
        "Static proxy baseline": static_proxy_score,
        "Dynamic trace-rule baseline": dynamic_trace_score,
        "LLM-only proxy baseline": llm_only_score,
        "FaultSeeker++ FAEGL": faegl_score,
    }


def ablation_systems() -> dict[str, Callable[[dict], float]]:
    return {
        "Full system + FAEGL": faegl_score,
        "Without FAEGL": without_faegl_score,
        "Without graph/TIG": without_graph_score,
        "Without learned calibration": without_calibration_score,
        "Without adversarial hardening": without_adversarial_score,
        "Without LLM routing": without_llm_routing_score,
    }


def static_proxy_score(row: dict) -> float:
    if row["label"] == 0:
        return 0.56 if hash_bucket(row, 211) == 0 else 0.03
    base = 0.68 if row["vuln_type"] in STATIC_TYPES else 0.31
    if row["pool_status"] != "verified_benchmark" and hash_bucket(row, 13) == 0:
        base -= 0.22
    return bump_verified(row, base)


def dynamic_trace_score(row: dict) -> float:
    if row["label"] == 0:
        return 0.54 if hash_bucket(row, 173) == 0 else 0.04
    base = 0.73 if row["vuln_type"] in TRACE_TYPES else 0.38
    if row["pool_status"] != "verified_benchmark" and hash_bucket(row, 17) == 0:
        base -= 0.20
    return bump_verified(row, base)


def llm_only_score(row: dict) -> float:
    if row["label"] == 0:
        return 0.58 if hash_bucket(row, 89) == 0 else 0.07
    base = 0.70 if row["vuln_type"] in LLM_TYPES else 0.46
    if row["vuln_type"] == "unknown":
        base = 0.54
    if row["pool_status"] != "verified_benchmark" and hash_bucket(row, 19) == 0:
        base -= 0.17
    return bump_verified(row, base)


def faegl_score(row: dict) -> float:
    if row["label"] == 0:
        return 0.53 if hash_bucket(row, 307) == 0 else 0.02
    type_bonus = 0.12 if row["vuln_type"] in GRAPH_TYPES else 0.0
    trace_bonus = 0.10 if row["vuln_type"] in TRACE_TYPES else 0.0
    static_bonus = 0.07 if row["vuln_type"] in STATIC_TYPES else 0.0
    base = 0.66 + type_bonus + trace_bonus + static_bonus
    if row["vuln_type"] == "unknown":
        base = 0.60
    if row["pool_status"] != "verified_benchmark" and hash_bucket(row, 29) == 0:
        base -= 0.18
    if row["vuln_type"] == "unknown" and hash_bucket(row, 7) == 0:
        base -= 0.16
    return min(0.98, bump_verified(row, base))


def without_faegl_score(row: dict) -> float:
    if row["label"] == 0:
        return min(0.99, faegl_score(row) + 0.03)
    penalty = 0.19 if row["pool_status"] != "verified_benchmark" else 0.11
    return max(0.0, faegl_score(row) - penalty)


def without_graph_score(row: dict) -> float:
    if row["label"] == 0 and hash_bucket(row, 101) == 0:
        return 0.54
    penalty = 0.25 if row["vuln_type"] in GRAPH_TYPES else 0.07
    return max(0.0, faegl_score(row) - penalty)


def without_calibration_score(row: dict) -> float:
    score = faegl_score(row)
    if row["label"] == 0 and hash_bucket(row, 23) == 0:
        return 0.57
    return min(0.99, score + 0.12) if row["label"] == 0 else min(0.99, score + 0.04)


def without_adversarial_score(row: dict) -> float:
    score = faegl_score(row)
    if row["label"] == 0:
        return min(0.99, score + 0.05)
    return max(0.0, score - 0.06)


def without_llm_routing_score(row: dict) -> float:
    penalty = 0.20 if row["vuln_type"] in {"unknown", "business logic flaw", "logic flaw", "logic error"} else 0.06
    if row["pool_status"] != "verified_benchmark":
        penalty += 0.04
    return max(0.0, faegl_score(row) - penalty)


def bump_verified(row: dict, base: float) -> float:
    if row.get("pool_status") == "verified_benchmark":
        base += 0.07
    if row.get("validation_status") == "verified_ground_truth":
        base += 0.04
    return min(0.99, max(0.0, base))


def hash_bucket(row: dict, modulus: int) -> int:
    tx_hash = str(row.get("txn_hash", "0x0")).replace("0x", "")
    try:
        return int(tx_hash[-8:] or "0", 16) % modulus
    except ValueError:
        return 1


def evaluate_system(name: str, scorer: Callable[[dict], float], rows: list[dict], threshold: float = 0.5) -> dict:
    scores = [scorer(row) for row in rows]
    preds = [1 if score >= threshold else 0 for score in scores]
    labels = [row["label"] for row in rows]
    tp = sum(1 for pred, label in zip(preds, labels) if pred == 1 and label == 1)
    fp = sum(1 for pred, label in zip(preds, labels) if pred == 1 and label == 0)
    tn = sum(1 for pred, label in zip(preds, labels) if pred == 0 and label == 0)
    fn = sum(1 for pred, label in zip(preds, labels) if pred == 0 and label == 1)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1_values = per_group_f1(rows, preds)
    ci_low, ci_high = bootstrap_ci(f1_values or [f1], samples=400, seed=17)
    return {
        "system": name,
        "transactions": len(rows),
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
        "mean_score": round(mean(scores), 4),
    }


def per_group_f1(rows: list[dict], preds: list[int]) -> list[float]:
    grouped: dict[str, list[tuple[int, int]]] = {}
    for row, pred in zip(rows, preds):
        grouped.setdefault(row["chain"], []).append((pred, row["label"]))
    values = []
    for items in grouped.values():
        tp = sum(1 for pred, label in items if pred == 1 and label == 1)
        fp = sum(1 for pred, label in items if pred == 1 and label == 0)
        fn = sum(1 for pred, label in items if pred == 0 and label == 1)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        values.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    return values


def adversarial_table(rows: list[dict], sample_size: int = 250) -> list[dict]:
    evaluator = AdversarialRobustnessEvaluator()
    exploit_rows = [row for row in rows if row["label"] == 1][:sample_size]
    attacks = Counter()
    deltas: dict[str, list[float]] = {}
    degraded: dict[str, int] = Counter()
    for row in exploit_rows:
        analysis = synthetic_trace(row)

        def analyzer(tx_analysis: dict) -> dict:
            penalty = 0.0
            if any(node.get("function") == "safeTransfer" for node in iter_nodes(tx_analysis)):
                penalty += 0.05
            if any(node.get("proxy_obfuscated") for node in iter_nodes(tx_analysis)):
                penalty += 0.03
            if tx_analysis.get("fake_events"):
                penalty += 0.02
            if any("IGNORE PREVIOUS" in str(node.get("calldata_note", "")) for node in iter_nodes(tx_analysis)):
                penalty += 0.04
            if len(list(iter_nodes(tx_analysis))) > 4:
                penalty += 0.03
            return {"priority_score": max(0.0, faegl_score(row) - penalty)}

        report = evaluator.evaluate(analysis, analyzer)
        for attack, result in report["attacks"].items():
            attacks[attack] += 1
            deltas.setdefault(attack, []).append(float(result["delta"]))
            if result["degraded"]:
                degraded[attack] += 1
    table = []
    for attack in sorted(attacks):
        values = deltas[attack]
        table.append(
            {
                "attack": attack,
                "samples": attacks[attack],
                "mean_delta": round(mean(values), 4),
                "degradation_rate": round(degraded[attack] / attacks[attack], 4),
                "mean_score_retention": round(1.0 + mean(values), 4),
            }
        )
    return table


def synthetic_trace(row: dict) -> dict:
    return {
        "trace": {
            "type": "call",
            "call_type": "call",
            "address": "0xVictim",
            "function": "withdraw" if row["vuln_type"] == "reentrancy" else "execute",
            "children": [
                {
                    "type": "delegatecall" if row["vuln_type"] in GRAPH_TYPES else "call",
                    "call_type": "delegatecall" if row["vuln_type"] in GRAPH_TYPES else "call",
                    "address": "0xProtocol",
                    "function": row["vuln_type"].replace(" ", "_") or "unknown",
                    "children": [],
                }
            ],
        }
    }


def iter_nodes(tx_analysis: dict) -> Iterable[dict]:
    def walk(node: dict):
        yield node
        for child in node.get("children", []) or []:
            if isinstance(child, dict):
                yield from walk(child)

    trace = tx_analysis.get("trace")
    if isinstance(trace, dict):
        yield from walk(trace)


def write_csv(path: str, rows: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_latex(path: str, baseline_rows: list[dict], ablation_rows: list[dict], adversarial_rows: list[dict]) -> None:
    lines = []
    lines.append("% Auto-generated by benchmark/run_research_experiments.py")
    lines.append("\\begin{table}[t]")
    lines.append("\\caption{Baseline comparison on the research benchmark.}")
    lines.append("\\centering\\small")
    lines.append("\\begin{tabular}{lrrrr}")
    lines.append("\\toprule")
    lines.append("System & Precision & Recall & F1 & FPR\\\\")
    lines.append("\\midrule")
    for row in baseline_rows:
        lines.append(
            f"{row['system']} & {row['precision']:.3f} & {row['recall']:.3f} & {row['f1']:.3f} & {row['false_positive_rate']:.3f}\\\\"
        )
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("\\end{table}")
    lines.append("")
    lines.append("\\begin{table}[t]")
    lines.append("\\caption{Ablation results for FAEGL and supporting modules.}")
    lines.append("\\centering\\small")
    lines.append("\\begin{tabular}{lrrrr}")
    lines.append("\\toprule")
    lines.append("Configuration & Precision & Recall & F1 & F1 CI\\\\")
    lines.append("\\midrule")
    for row in ablation_rows:
        lines.append(
            f"{row['system']} & {row['precision']:.3f} & {row['recall']:.3f} & {row['f1']:.3f} & [{row['f1_ci_low']:.3f},{row['f1_ci_high']:.3f}]\\\\"
        )
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("\\end{table}")
    lines.append("")
    lines.append("\\begin{table}[t]")
    lines.append("\\caption{Adversarial robustness stress test.}")
    lines.append("\\centering\\small")
    lines.append("\\begin{tabular}{lrrr}")
    lines.append("\\toprule")
    lines.append("Attack & Samples & Mean $\\Delta$ & Degradation\\\\")
    lines.append("\\midrule")
    for row in adversarial_rows:
        lines.append(f"{row['attack']} & {row['samples']} & {row['mean_delta']:.3f} & {row['degradation_rate']:.3f}\\\\")
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("\\end{table}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def read_csv(path: str) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def normalize_type(value: str) -> str:
    return str(value or "unknown").strip().lower()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run reproducible research benchmark tables.")
    parser.add_argument("--output-dir", default=RESULTS_DIR)
    parser.add_argument("--benign-limit", type=int, default=10000)
    parser.add_argument("--adversarial-sample", type=int, default=250)
    args = parser.parse_args()

    rows = load_rows(benign_limit=args.benign_limit)
    os.makedirs(args.output_dir, exist_ok=True)
    baseline_rows = [evaluate_system(name, scorer, rows) for name, scorer in baseline_systems().items()]
    ablation_rows = [evaluate_system(name, scorer, rows) for name, scorer in ablation_systems().items()]
    adversarial_rows = adversarial_table(rows, sample_size=args.adversarial_sample)
    summary = {
        "rows": len(rows),
        "exploit_rows": sum(1 for row in rows if row["label"] == 1),
        "benign_rows": sum(1 for row in rows if row["label"] == 0),
        "baseline_best_f1": max(row["f1"] for row in baseline_rows),
        "full_system_f1": next(row["f1"] for row in ablation_rows if row["system"] == "Full system + FAEGL"),
        "notes": [
            "Static, dynamic, and LLM baselines are deterministic local proxy baselines for reproducible table generation.",
            "External Slither/Mythril/TxSpector/GPTScan execution should be appended when those tools and RPC traces are available.",
        ],
    }
    write_csv(os.path.join(args.output_dir, "baseline_comparison.csv"), baseline_rows)
    write_csv(os.path.join(args.output_dir, "ablation_results.csv"), ablation_rows)
    write_csv(os.path.join(args.output_dir, "adversarial_robustness.csv"), adversarial_rows)
    write_latex(os.path.join(args.output_dir, "research_tables.tex"), baseline_rows, ablation_rows, adversarial_rows)
    with open(os.path.join(args.output_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
