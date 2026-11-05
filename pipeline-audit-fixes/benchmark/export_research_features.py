import argparse
import csv
import json
import os


FEATURE_FIELDS = [
    "pattern_match",
    "code_evidence",
    "txn_consistency",
    "llm_confidence",
    "trace_entropy",
    "call_depth",
    "state_delta",
    "token_flow_anomaly",
    "label",
]


def features_from_result(result: dict, label: int) -> dict:
    confidence = _first_confidence(result)
    signals = result.get("signals", {}) or {}
    graph = signals.get("graph_reasoning", {}) if isinstance(signals, dict) else {}
    debug = signals.get("debug", {}) if isinstance(signals, dict) else {}
    return {
        "pattern_match": confidence.get("pattern_match", 0.0),
        "code_evidence": confidence.get("code_evidence", 0.0),
        "txn_consistency": confidence.get("txn_consistency", 0.0),
        "llm_confidence": confidence.get("llm_confidence", 0.0),
        "trace_entropy": signals.get("trace_entropy", 0.0),
        "call_depth": debug.get("call_depth_max", signals.get("call_depth_max", 0.0)),
        "state_delta": debug.get("storage_events_total", 0.0),
        "token_flow_anomaly": graph.get("anomaly_score", signals.get("token_flow_anomaly", 0.0)),
        "label": int(label),
    }


def export_feature_rows(input_dir: str, output_csv: str, label: int) -> int:
    rows = []
    for name in sorted(os.listdir(input_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(input_dir, name), encoding="utf-8") as f:
            rows.append(features_from_result(json.load(f), label=label))

    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    with open(output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def _first_confidence(result: dict) -> dict:
    scored = result.get("scored_functions") or []
    if not scored:
        return {}
    confidence = scored[0].get("confidence", {})
    return confidence.get("components", {}) if isinstance(confidence, dict) else {}


def main() -> None:
    parser = argparse.ArgumentParser(description="Export calibration-ready feature rows from analysis JSON outputs.")
    parser.add_argument("--input-dir", default="data/output")
    parser.add_argument("--output", default="benchmark/calibration_features.csv")
    parser.add_argument("--label", type=int, default=1, help="1 for exploit rows, 0 for benign rows")
    args = parser.parse_args()
    count = export_feature_rows(args.input_dir, args.output, args.label)
    print(f"Exported {count} rows to {args.output}")


if __name__ == "__main__":
    main()
