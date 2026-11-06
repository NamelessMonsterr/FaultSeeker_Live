# FaultSeeker Dataset Registry

> **Authoritative reference** -- use these numbers in both papers.

## Tier 1 -- Ground-Truth Corpus (Localization Benchmark)

| Property | Value |
|----------|-------|
| Files | benchmark/ground_truth/*.json |
| Count | **115 transactions** |
| Chains | Ethereum: 102, BSC: 13 |
| Function targets | 161 unique (address, function-name) pairs |
| Line targets | 134 unique (address, line-number) pairs |
| Used for | Top-k accuracy, MRR |

## Tier 2 -- Source-Validated Incident Set

| Property | Value |
|----------|-------|
| Files | benchmark/imported/defihacklabs_incidents.full.csv |
| Count | **241 incidents** |
| Source | DeFiHackLabs GitHub + manual cross-check |
| Used for | Exploit detection (precision / recall / FPR) |

NOTE: The 231 figure in earlier drafts was a pre-validation count. Correct number is 241.
NOTE: The 1,059 figure was a mis-count of raw candidates (1,128 after dedup).
      Do NOT cite 1,059 as benchmark size. Cite 241 (source-validated) or 115 (ground-truth).

## Tier 3 -- Benign Transaction Set (FPR Baseline)

| Property | Value |
|----------|-------|
| Source | HuggingFace sarthak-vajpayee/ethereum-transactions |
| Available | 10,000 transactions |
| Collected | **1,000 transactions** (real traces via QuickNode RPC) |
| File | benchmark/imported/benign_traces.csv |
| Used for | False-positive rate (FPR), precision calculation |

CAUTION: Before 2026-07-31 benign_traces.csv had constant placeholder vectors.
         FPR computed against that data was meaningless. Now corrected.

## Which Numbers to Cite

| Paper Claim | Dataset | N |
|-------------|---------|---|
| Ground-truth exploits | Tier 1 | 115 |
| DeFiHackLabs incidents | Tier 2 | 241 |
| Benign transactions | Tier 3 | 1,000 |
| Top-k / MRR evaluation | Tier 1 | 115 tx, 161 fn targets |
| FPR / Precision | Tier 2 + 3 | 241 exploit + 1,000 benign |
