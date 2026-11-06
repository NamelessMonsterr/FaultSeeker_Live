# FaultSeeker++ Benchmark

This directory contains the verified exploit benchmark, public-source importers, staged external data, and validation scripts used for research evaluation.

> **Dataset Integrity:** For a full disclosure of verification tiers and dataset composition, see [`DATASET_INTEGRITY.md`](./DATASET_INTEGRITY.md).

## Dataset Summary (JISA Paper)

| Metric | Value |
|---|---:|
| **Exploit (manually verified)** | **231** — RPC-fetched traces + manual post-mortem review |
| **Exploit (source-validated)** | **828** — DeFiHackLabs provenance, tx hash + vuln type confirmed |
| **Exploit total** | **1,059** |
| **Benign transactions** | **10,000** |
| **Total** | **11,059** |
| Covered EVM chains | **10** (ETH, BSC, Polygon, Arbitrum, Optimism, Avalanche, Base, Fantom, zkSync, Gnosis) |
| Vulnerability types (full pool) | 80+ |
| Vulnerability types (verified split) | 40+ |

The verified benchmark lives in:

```text
benchmark/benchmark_classification_fixed.csv   ← Tier 1: manually verified (231 rows)
benchmark/research_exploit_pool.csv            ← Full pool: verified + source-backed (1,059 rows)
benchmark/ground_truth/                        ← Ground-truth JSON artifacts
```

> **Rule:** Do not merge staged imports into the verified benchmark unless each row has a verified transaction hash, chain, label, source URL, and validation status.

## Validate The Verified Benchmark

```bash
python benchmark/validate_dataset.py
```

Expected current result:

```text
231 entries
0 duplicate hashes
0 invalid hashes
8 chains
```

## Public Exploit Expansion

### DeFiHackLabs

```bash
python benchmark/import_public_incidents.py --output benchmark/imported/defihacklabs_incidents.full.csv

python benchmark/validate_imported_incidents.py --imported benchmark/imported/defihacklabs_incidents.full.csv --output benchmark/imported/defihacklabs_validation_manifest.full.csv --summary-output benchmark/imported/defihacklabs_validation_summary.full.json

python benchmark/build_candidate_exploit_expansion.py --manifest benchmark/imported/defihacklabs_validation_manifest.full.csv --output benchmark/imported/defihacklabs_candidate_expansion.csv --summary-output benchmark/imported/defihacklabs_candidate_expansion_summary.json
```

Current staged status:

- 241 imported DeFiHackLabs incident rows.
- 215 rows include transaction hashes.
- 62 overlap existing verified benchmark rows.
- 153 incident rows need manual/RPC review.
- 293 one-row-per-transaction candidates are staged.
- Best-case verified rows after all current candidates are reviewed and accepted: 539.
- Remaining rows needed after that best case: 461.

### DeFiHackLabs GitHub PoCs

```bash
python benchmark/import_defihacklabs_github.py --output benchmark/imported/defihacklabs_github_candidates.csv --summary-output benchmark/imported/defihacklabs_github_candidates_summary.json

python benchmark/build_research_exploit_pool.py --output benchmark/research_exploit_pool.csv --summary-output benchmark/research_exploit_pool_summary.json
```

Current staged status:

- 1,128 transaction candidates extracted from public DeFiHackLabs GitHub PoCs.
- 928 candidates map to currently supported EVM chains.
- The deduplicated exploit research pool contains 1,059 unique chain/transaction rows.
- The pool meets the 1000+ exploit-transaction research target, but only `pool_status=verified_benchmark` rows are strict ground truth until candidates pass RPC/manual validation.

### DeFiLlama Hacks

```bash
python benchmark/import_defillama_hacks.py --output benchmark/imported/defillama_hacks.full.csv
```

This source is incident-level metadata. Most rows do not expose canonical transaction hashes, so they are useful for triage and longitudinal metadata, not direct benchmark merge.

### Rug-Pull Contract Incidents

```bash
python benchmark/import_rugpull_contracts.py --output benchmark/imported/rugpull_contract_incidents.csv --summary-output benchmark/imported/rugpull_contract_incidents_summary.json
```

This source provides contract-level rug-pull incidents. Rows must be resolved to exploit transaction hashes before they can become transaction-level benchmark rows.

Current staged status:

- 2,360 contract incident rows.
- 2,290 Ethereum rows and 70 BSC rows.
- 0 transaction hashes; all rows remain transaction-hash unresolved.

## Benign False-Positive Dataset

The Hugging Face Ethereum activity importer stages non-scam-address transaction candidates:

```bash
python benchmark/import_hf_ethereum_activity.py --target-rows 10000 --output benchmark/imported/hf_ethereum_benign_transactions.csv --summary-output benchmark/imported/hf_ethereum_benign_transactions_summary.json

python benchmark/validate_benign_dataset.py --input benchmark/imported/hf_ethereum_benign_transactions.csv --summary-output benchmark/imported/hf_ethereum_benign_transactions_validation.json
```

Notes:

- Current staged rows: 10,000.
- Duplicate transaction hashes: 0.
- Required fields: complete.
- The labels are address-level scam/non-scam labels, not exploit transaction labels.
- The output is appropriate for false-positive stress testing after spot checks.
- The importer needs `zstandard>=0.22.0` to decompress the upstream label file.
- Hugging Face Dataset Viewer may rate-limit large pulls; rerun if HTTP 429 occurs.

## Readiness Report

```bash
python benchmark/research_readiness_report.py --output benchmark/research_readiness_report.json
```

The report summarizes:

- Verified exploit coverage.
- Remaining exploit and benign row gaps.
- Public import validation state.
- Candidate expansion queue size.
- Incident-level sources that still need transaction hash resolution.
- Research artifact availability.

## Evaluation

```bash
python benchmark/run_eval.py --chain eth --limit 5
python benchmark/run_eval.py --chain eth --limit 20 --save
python benchmark/run_eval.py --signals-only --limit 50
```

Saved evaluation outputs are generated under `benchmark/eval_results/` only when `--save` is used.

## Files

| File or folder | Purpose |
|---|---|
| `benchmark_classification_fixed.csv` | Verified transaction-level exploit benchmark |
| `benchmark_classification.csv` | Original/raw CSV retained for provenance |
| `ground_truth/` | Per-transaction ground-truth JSON files |
| `imported/` | Staged external public-source data and summaries |
| `dataset_sources.json` | Registered public exploit and benign data sources |
| `run_eval.py` | Evaluation runner |
| `validate_dataset.py` | Verified benchmark integrity check |
| `validate_imported_incidents.py` | Public exploit import validation manifest |
| `build_candidate_exploit_expansion.py` | One-row-per-transaction candidate expansion queue |
| `import_defihacklabs_github.py` | Public DeFiHackLabs GitHub PoC transaction extractor |
| `build_research_exploit_pool.py` | Deduplicated verified-plus-candidate exploit research pool builder |
| `validate_benign_dataset.py` | Benign dataset schema/duplicate/size validator |
| `research_readiness_report.py` | TDSC readiness summary |
| `fix_csv.py` | One-time historical CSV repair script, kept for provenance |

## Cleanup-Safe Generated Files

These can be deleted and regenerated:

- `benchmark/research_readiness_report.local.json`
- `benchmark/eval_results/`
- Python `__pycache__/` folders
