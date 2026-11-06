# Baseline Matrix

FaultSeeker++ should report against four baseline families. Do not mix exploit-only scores with false-positive scores; benign rows must be included for precision and F1 claims.

| Family | Baseline | Input | Required Output | Metrics |
|---|---|---|---|---|
| Static analysis | Slither | verified vulnerable contracts | detector hit, vulnerability class, runtime | precision, recall, F1, runtime |
| Static analysis | Mythril | verified vulnerable contracts | detector hit, vulnerability class, runtime | precision, recall, F1, runtime |
| Static analysis | Securify-style rules | verified vulnerable contracts | rule hit, vulnerability class, runtime | precision, recall, F1, runtime |
| Dynamic trace | FaultSeeker rules only | transaction trace | verdict, class, confidence, latency | precision, recall, F1, latency |
| Dynamic trace | trace heuristic baseline | calls, transfers, delegatecalls, logs | verdict, class, latency | precision, recall, F1, latency |
| LLM | LLM-only transaction summary | transaction metadata and trace summary | verdict, class, cost, latency | precision, recall, F1, token cost |
| Full system | FaultSeeker++ full | trace, source, graph, calibration, routing | verdict, class, confidence, evidence | all metrics |

Minimum reporting columns:

| System | Precision | Recall | F1 | F1 95% CI | Runtime/tx | Token cost/tx | Detection latency | GPU memory |
|---|---:|---:|---:|---:|---:|---:|---:|---:|

Required significance tests:

- McNemar test for paired classification correctness.
- Bootstrap confidence intervals for F1 and latency.
- Wilcoxon signed-rank for paired runtime/cost comparisons.
- Paired t-test only as a secondary check when metric differences are approximately normal.

## External result normalization

Create the result sheet:

```bash
python benchmark/ingest_external_baselines.py --make-template
```

Fill one row per `(system, transaction)` with the tool prediction, score, runtime, token cost, and GPU memory. Then score it:

```bash
python benchmark/ingest_external_baselines.py --input reports/external_baselines/external_baseline_template.csv
```

The ingester writes `reports/external_baselines/external_baseline_summary.csv`. Empty template predictions are rejected so paper tables cannot silently mix missing results with completed runs.
