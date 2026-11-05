# Human Explainability Study Protocol

This protocol evaluates whether FaultSeeker++ evidence cards help analysts inspect exploit transactions faster and with more confidence than transaction metadata alone.

## Study design

- Participants: auditors, security students, and blockchain analysts.
- Tasks: transaction-level exploit triage and vulnerable-function localization.
- Conditions:
  - `metadata_only`: hash, chain, protocol, and short incident label.
  - `faultseeker_evidence`: metadata plus evidence cards, ranked functions, signal breakdown, and confidence.
- Assignment: within-subjects, counterbalanced by task order.
- Minimum target: 20 participants and 8 tasks per participant.

## Measures

| Measure | Source | Interpretation |
|---|---|---|
| Task correctness | analyst answer vs ground truth | higher is better |
| Completion time | seconds per task | lower is better |
| Usefulness | 1-5 Likert | higher is better |
| Trust | 1-5 Likert | higher is better |
| SUS score | 10-item SUS instrument | higher is better |

## Response schema

Use a CSV with these columns:

```text
participant_id,role,task_id,condition,completion_time_sec,correct,usefulness_1_5,trust_1_5,sus_q1,sus_q2,sus_q3,sus_q4,sus_q5,sus_q6,sus_q7,sus_q8,sus_q9,sus_q10
```

Run:

```bash
python benchmark/analyze_explainability_study.py --input docs/research/human_study_response_template.csv
```

The analyzer writes `reports/human_study/explainability_summary.csv` and `reports/human_study/explainability_report.json`.

## Reporting

Report mean accuracy, median completion time, mean usefulness, mean trust, and SUS by condition. For a final paper, add a paired test between `metadata_only` and `faultseeker_evidence` for correctness and completion time.
