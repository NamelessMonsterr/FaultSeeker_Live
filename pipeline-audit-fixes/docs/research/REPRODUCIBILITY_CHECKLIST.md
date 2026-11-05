# Reproducibility Checklist

Before paper submission, every result table must be reproducible from a clean checkout.

## Data

- [ ] Verified exploit benchmark includes at least 1000 rows.
- [ ] Benign negative benchmark includes at least 5000 rows.
- [ ] Every row has transaction hash, chain, source URL, label, and validation status.
- [ ] Public imports remain staged until validated.
- [ ] Dataset split seeds are recorded.

## Environment

- [ ] Python version recorded.
- [ ] RPC providers and archive trace support documented.
- [ ] Docker benchmark image builds.
- [ ] All random seeds fixed.
- [ ] Hardware used for runtime/GPU measurements recorded.

## Evaluation

- [ ] Baselines executed on the same split.
- [ ] Ablations executed on the same split.
- [ ] Bootstrap confidence intervals generated.
- [ ] McNemar/Wilcoxon tests generated where applicable.
- [ ] Error taxonomy completed for false positives and false negatives.

## Artifacts

- [ ] Raw prediction CSVs saved.
- [ ] Aggregated metric JSON saved.
- [ ] Calibration diagrams saved.
- [ ] Reliability/ECE/Brier outputs saved.
- [ ] Human-study protocol and anonymized scoring sheet saved.
