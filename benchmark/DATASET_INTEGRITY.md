# Dataset Integrity Statement — FaultSeeker++ Benchmark

## Overview

This document discloses the composition and verification status of the FaultSeeker++ benchmark dataset used in the JISA paper submission. Full transparency is provided to reviewers and future researchers.

## Dataset Composition

| Split | Transactions | Chains | Vulnerability Types | Verification Level |
|---|---|---|---|---|
| Exploit (manually verified) | 231 | 8 | 40+ | ✅ Full ground-truth: RPC-fetched traces + manual incident review |
| Exploit (source-validated) | 828 | 10 | 80+ | ✅ Source-backed: DeFiHackLabs GitHub reports with tx hash + vuln type |
| **Exploit total** | **1,059** | **10** | **80+** | See tiered disclosure below |
| Benign | 10,000 | 1 (ETH) | N/A | ✅ Standard Ethereum transfers, no exploit indicators |
| **Total** | **11,059** | **10** | **80+** | |

## Verification Tiers

### Tier 1 — Manually Verified (231 transactions)
- Each transaction was individually fetched via RPC and/or Etherscan trace API
- Vulnerability type was confirmed against public post-mortem reports (Rekt News, BlockSec, PeckShield)
- Stored in `benchmark/benchmark_classification_fixed.csv` with `pool_status = verified_benchmark`
- Feature variance confirmed across all rows (`distinct_feature_vectors = 230`)

### Tier 2 — Source-Validated Candidates (828 transactions)
- Imported from **DeFiHackLabs** GitHub (community-curated exploit PoC repository)
- Each row has a matching GitHub issue/PoC with transaction hash and stated vulnerability type
- Not individually RPC-verified by the authors; correctness depends on community curation quality
- DeFiHackLabs is widely used in academic DeFi security research (>4,000 GitHub stars)
- Stored in `benchmark/research_exploit_pool.csv` with `pool_status = source_backed_candidate`

## Paper Claim Clarification

The paper states **"1,059 annotated exploit transactions"**. This means:
- All 1,059 have a transaction hash, chain identifier, and vulnerability type label
- 231 of these are independently verified by the authors (Tier 1)
- 828 are validated by source (DeFiHackLabs provenance, Tier 2)
- The paper also reports results separately on the 231-row manually verified split where noted

This distinction follows standard practice in DeFi security research (e.g., DeFiHackLabs, SolidiFI, SmartBugs) where community-curated datasets are accepted as ground truth.

## Sources

| Source | Role | URL |
|---|---|---|
| DeFiHackLabs | Primary exploit dataset | https://github.com/SunWeb3Sec/DeFiHackLabs |
| Rekt News | Incident verification | https://rekt.news |
| BlockSec | Incident verification | https://blocksec.com |
| PeckShield | Incident verification | https://peckshield.com |
| SWC Registry | Vulnerability taxonomy | https://swcregistry.io |
| DASP Top-10 | Vulnerability taxonomy | https://dasp.co |

## SWC / DASP Taxonomy Alignment

All vulnerability labels use the SWC Registry and DASP Top-10 taxonomy. The 80+ distinct types in the full pool represent fine-grained sub-categories (e.g., "Flash Loan Attack", "Price Oracle Manipulation", "Reentrancy", etc.). In the manually-verified split, 40+ distinct types are represented.

## Reproducibility

To re-validate the dataset:
```bash
python benchmark/validate_dataset.py
python benchmark/validate_imported_incidents.py
python benchmark/research_readiness_report.py
```

To rebuild the exploit pool from scratch:
```bash
python benchmark/import_defihacklabs_github.py
python benchmark/build_research_exploit_pool.py
python benchmark/fix_csv.py
```
