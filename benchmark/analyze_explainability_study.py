import argparse
import csv
import json
import os
from collections import defaultdict
from statistics import mean, median
from typing import Iterable


OUTPUT_DIR = os.path.join("reports", "human_study")
REQUIRED_COLUMNS = {
    "participant_id",
    "role",
    "task_id",
    "condition",
    "completion_time_sec",
    "correct",
    "usefulness_1_5",
    "trust_1_5",
    "sus_q1",
    "sus_q2",
    "sus_q3",
    "sus_q4",
    "sus_q5",
    "sus_q6",
    "sus_q7",
    "sus_q8",
    "sus_q9",
    "sus_q10",
}


def load_responses(path: str) -> tuple[list[dict], list[str]]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return [], ["input file is empty"]
    missing = sorted(REQUIRED_COLUMNS - set(rows[0]))
    errors = [f"missing columns: {', '.join(missing)}"] if missing else []
    clean = []
    for index, row in enumerate(rows, start=2):
        parsed = {
            "participant_id": row.get("participant_id", "").strip(),
            "role": row.get("role", "").strip().lower(),
            "task_id": row.get("task_id", "").strip(),
            "condition": row.get("condition", "").strip().lower(),
            "completion_time_sec": parse_float(row.get("completion_time_sec")),
            "correct": parse_binary(row.get("correct")),
            "usefulness_1_5": parse_likert(row.get("usefulness_1_5")),
            "trust_1_5": parse_likert(row.get("trust_1_5")),
        }
        sus_values = [parse_likert(row.get(f"sus_q{i}")) for i in range(1, 11)]
        if not parsed["participant_id"]:
            errors.append(f"line {index}: missing participant_id")
            continue
        if not parsed["condition"]:
            errors.append(f"line {index}: missing condition")
            continue
        if any(value is None for value in [parsed["completion_time_sec"], parsed["correct"], parsed["usefulness_1_5"], parsed["trust_1_5"], *sus_values]):
            errors.append(f"line {index}: invalid numeric response")
            continue
        parsed["sus_score"] = sus_score(sus_values)
        clean.append(parsed)
    return clean, errors


def summarize(rows: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[row["condition"]].append(row)
    summaries = []
    for condition, items in sorted(grouped.items()):
        summaries.append(
            {
                "condition": condition,
                "responses": len(items),
                "participants": len({row["participant_id"] for row in items}),
                "accuracy": round(mean(row["correct"] for row in items), 4),
                "completion_time_mean_sec": round(mean(row["completion_time_sec"] for row in items), 2),
                "completion_time_median_sec": round(median(row["completion_time_sec"] for row in items), 2),
                "usefulness_mean_1_5": round(mean(row["usefulness_1_5"] for row in items), 3),
                "trust_mean_1_5": round(mean(row["trust_1_5"] for row in items), 3),
                "sus_mean": round(mean(row["sus_score"] for row in items), 2),
            }
        )
    return summaries


def sus_score(values: list[int]) -> float:
    total = 0
    for index, value in enumerate(values, start=1):
        if index % 2 == 1:
            total += value - 1
        else:
            total += 5 - value
    return total * 2.5


def write_csv(path: str, rows: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def parse_likert(value: object) -> int | None:
    try:
        number = int(str(value).strip())
    except ValueError:
        return None
    return number if 1 <= number <= 5 else None


def parse_float(value: object) -> float | None:
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def parse_binary(value: object) -> int | None:
    text = str(value if value is not None else "").strip().lower()
    if text in {"1", "true", "yes", "correct"}:
        return 1
    if text in {"0", "false", "no", "incorrect"}:
        return 0
    return None


def mean_or_blank(values: Iterable[float]) -> float | str:
    values = list(values)
    return round(mean(values), 4) if values else ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze FaultSeeker++ explainability study responses.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    args = parser.parse_args()

    rows, errors = load_responses(args.input)
    summaries = summarize(rows) if rows else []
    os.makedirs(args.output_dir, exist_ok=True)
    if summaries:
        write_csv(os.path.join(args.output_dir, "explainability_summary.csv"), summaries)
    report = {
        "input": args.input,
        "valid_responses": len(rows),
        "conditions": sorted({row["condition"] for row in rows}),
        "errors": errors,
        "summary_path": os.path.join(args.output_dir, "explainability_summary.csv") if summaries else "",
    }
    with open(os.path.join(args.output_dir, "explainability_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2))
    if errors:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
