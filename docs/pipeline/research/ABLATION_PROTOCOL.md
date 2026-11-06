# Ablation Protocol

Run every ablation on the same exploit and benign split with fixed seeds. Report mean and 95% bootstrap confidence interval.

| Configuration | Adaptive fallback | Graph metrics | Learned calibration | HITL checkpoints | Expected question answered |
|---|---|---|---|---|---|
| Full system | on | on | on | on | Best achievable system behavior |
| No adaptive fallback | off | on | on | on | Does failure-aware routing reduce missed localization? |
| No graph module | on | off | on | on | Do interaction graph metrics improve exploit reasoning? |
| No learned calibration | on | on | heuristic confidence | on | Does calibration improve probability quality? |
| No HITL | on | on | on | off | Does analyst intervention improve ambiguous cases? |
| Rules only | off | off | heuristic confidence | off | Lower-bound deterministic system |
| LLM only | off | off | model self-confidence | off | Whether structured forensics beats direct prompting |

Required metrics:

- Precision, recall, F1 on exploit plus benign data.
- Exploit localization recall on verified vulnerable functions when available.
- Expected Calibration Error and Brier score for calibrated confidence.
- Runtime, token cost, and failure rate.
- False-positive taxonomy on benign DeFi interactions.

Reporting template:

| Configuration | Precision | Recall | F1 | ECE | Brier | Runtime/tx | Token cost/tx |
|---|---:|---:|---:|---:|---:|---:|---:|
