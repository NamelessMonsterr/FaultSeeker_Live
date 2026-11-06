# Benign Data Acquisition

False-positive measurement requires a separate benign DeFi transaction set. Do not use exploit-only metrics for precision or F1 claims.

## Primary Candidate

| Dataset | Reported scale | Scope | Status |
|---|---:|---|---|
| BCCC-DeFiFraudTrans-2025 | 1,026,867 annotated transaction samples | Ethereum DeFi fraudulent and legitimate transactions, 2017-2024, 79 transaction/wallet features | Source identified; direct download path still needs acquisition from the publisher page |
| Ethereum Fraud Dataset by Activity | 1.6B Ethereum transaction rows plus address labels | Ethereum activity with address-level scam/non-scam labels | 5000 non-scam-address transaction candidates staged and schema-validated |

Source page: https://www.yorku.ca/research/bccc/2025/09/24/new-dataset-alert-bccc-defifraudtrans-2025/

Hugging Face source: https://huggingface.co/datasets/fesevu/ethereum_fraud_dataset_by_activity

## Required Benign Categories

The final benchmark should stratify benign rows across:

- swaps
- arbitrage
- liquidations
- staking and unstaking
- deposits and withdrawals
- governance voting and execution
- bridge transfers
- approvals and allowance updates

## Acceptance Criteria

Each benign row must include:

- transaction hash
- chain
- source dataset or sampling query
- benign category
- timestamp or block number
- validation status
- exclusion reason if it overlaps a known exploit window

Minimum target: 5000 benign rows. Preferred target: 10000 benign rows.

Current status: 10000 staged rows, 0 duplicate transaction hashes, all required fields present. The preferred 10000-row target is met.

## Current Import Command

```bash
python benchmark/import_hf_ethereum_activity.py --target-rows 10000 --output benchmark/imported/hf_ethereum_benign_transactions.csv --summary-output benchmark/imported/hf_ethereum_benign_transactions_summary.json
python benchmark/validate_benign_dataset.py --input benchmark/imported/hf_ethereum_benign_transactions.csv --summary-output benchmark/imported/hf_ethereum_benign_transactions_validation.json
```

The Hugging Face importer uses address-level non-scam labels. Treat imported rows as benign candidates for false-positive stress testing and spot-check them with RPC before making final paper claims.
