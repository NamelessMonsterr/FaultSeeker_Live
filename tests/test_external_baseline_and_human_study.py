import csv

from benchmark.analyze_explainability_study import load_responses, summarize
from benchmark.ingest_external_baselines import evaluate, ingest_results


def test_external_baseline_ingest_scores_predictions(tmp_path):
    path = tmp_path / "baselines.csv"
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "system",
                "txn_hash",
                "label",
                "prediction",
                "score",
                "runtime_ms",
                "token_cost_usd",
                "gpu_memory_mb",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "system": "Slither",
                "txn_hash": "0x" + "1" * 64,
                "label": "1",
                "prediction": "1",
                "score": "0.90",
                "runtime_ms": "1200",
                "token_cost_usd": "0",
                "gpu_memory_mb": "0",
            }
        )
        writer.writerow(
            {
                "system": "Slither",
                "txn_hash": "0x" + "2" * 64,
                "label": "0",
                "prediction": "0",
                "score": "0.10",
                "runtime_ms": "800",
                "token_cost_usd": "0",
                "gpu_memory_mb": "0",
            }
        )

    rows, errors = ingest_results(str(path))
    assert errors == []
    summary = evaluate(rows)
    assert summary[0]["system"] == "Slither"
    assert summary[0]["f1"] == 1.0
    assert summary[0]["runtime_ms_mean"] == 1000.0


def test_human_study_summarizes_sus_and_task_metrics(tmp_path):
    path = tmp_path / "responses.csv"
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
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
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "participant_id": "P001",
                "role": "auditor",
                "task_id": "T001",
                "condition": "faultseeker_evidence",
                "completion_time_sec": "240",
                "correct": "1",
                "usefulness_1_5": "5",
                "trust_1_5": "4",
                "sus_q1": "5",
                "sus_q2": "1",
                "sus_q3": "5",
                "sus_q4": "1",
                "sus_q5": "5",
                "sus_q6": "1",
                "sus_q7": "5",
                "sus_q8": "1",
                "sus_q9": "5",
                "sus_q10": "1",
            }
        )

    rows, errors = load_responses(str(path))
    assert errors == []
    summary = summarize(rows)
    assert summary[0]["condition"] == "faultseeker_evidence"
    assert summary[0]["accuracy"] == 1.0
    assert summary[0]["sus_mean"] == 100.0
