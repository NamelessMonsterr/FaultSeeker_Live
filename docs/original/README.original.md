# FaultSeeker: LLM-Empowered Fault Localization for Blockchain Transactions

[![ASE 2025](https://img.shields.io/badge/ASE-2025-blue?style=flat-square)](https://conf.researchr.org/home/ase-2025)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

> **FaultSeeker** is an AI-powered framework that automatically analyzes malicious blockchain transactions and produces a **ranked list of vulnerable smart contract functions** with supporting evidence.

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Configuration](#-configuration)
- [Benchmark & Results](#-benchmark--results)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Citation](#-citation)

---

## 🔍 Overview

Blockchain attacks cause billions in losses annually, yet identifying the root cause vulnerabilities remains challenging. **FaultSeeker** addresses this by combining forensic analysis with large language models to automatically:

1. **Analyze transaction execution traces** to understand attack mechanics
2. **Identify attackers and victims** through fund flow analysis
3. **Rank vulnerable functions** using a two-stage approach
4. **Generate evidence-backed reports** for security auditors

**Paper**: *FaultSeeker: LLM-Empowered Framework for Blockchain Transaction Fault Localization*  
**Published at**: 40th IEEE/ACM International Conference on Automated Software Engineering (ASE 2025)  
**PDF**: [Full Paper](./full_paper/FaultSeeker%20LLM-Empowered%20Framework%20for%20Blockchain%20Transaction.pdf)

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **[Foundry](https://book.getfoundry.sh/getting-started/installation)** - For transaction replay
- **OpenAI API Key** - For LLM-based analysis

### Installation

```bash
# Clone the repository
git clone https://github.com/kairanskrr/FaultSeeker.git
cd FaultSeeker

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install FaultSeeker
pip install -e .

# Configure API key
echo "OPENAI_API_KEY=your-openai-api-key-here" > .env
```

### Basic Usage

**Option 1: Analyze using transaction link**
```bash
faultseeker -txn_link "https://etherscan.io/tx/0xABCD..."
# Output: ✓ Analysis complete. Results saved to: ./data/output/analysis_20251114_120530.json
```

**Option 2: Analyze using transaction hash and chain**
```bash
faultseeker -txn_hash "0xABCD..." -chain eth
```

### Available Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-txn_link` | - | Full transaction URL (e.g., `https://etherscan.io/tx/0x...`) |
| `-txn_hash` | - | Transaction hash (alternative to `-txn_link`) |
| `-chain` | `eth` | Blockchain: `eth`, `bsc`, `poly`, `opt`, `arbi`, `avax`, `fantom`, `base` |
| `-forensics_model` | `gpt-4o-mini` | LLM for Stage 1 (forensics analysis) |
| `-function_analysis_model` | `gpt-4o-mini` | LLM for Stage 2 (function analysis) |
| `-cache` | `./data/cache` | Directory for cached intermediate results |
| `-output` | `./data/output` | Output directory for final reports |


**Example:**
```bash
faultseeker -txn_hash 0x9f4ef3cc55b016ea6b867807a09f80d1b2e36f6cd6fccfaf0182f46060332c57 -chain bsc
```

---

## 🔧 Configuration

### AI Models

**OpenAI GPT (Default):**
```bash
# Add to .env file
echo "OPENAI_API_KEY=sk-..." >> .env
```

The system defaults to GPT models for reliability. Model names are case-insensitive and whitespace is automatically stripped.


### Supported Chains

**Currently Supported:**
- ✅ Ethereum (`eth`)
- ✅ BSC (`bsc`)

**Easy to Add** (requires RPC endpoint configuration in `foundry.toml`):
- Polygon (`poly`)
- Optimism (`opt`)
- Arbitrum (`arbi`)
- Avalanche (`avax`)
- Fantom (`fantom`)
- Base (`base`)

To add a new chain, update the RPC URL in `foundry.toml`:

```toml
[rpc_endpoints]
polygon = "https://polygon-rpc.com"
optimism = "https://mainnet.optimism.io"
# ... add more
```

---

## 📈 Benchmark & Results

FaultSeeker has been evaluated on **115 real-world blockchain attacks** covering **65 unique vulnerability types**.

### Vulnerability Coverage

| Framework | Total Categories | Covered |
|-----------|-----------------|---------|
| **SWC Registry** | 36 | 11 |
| **DASP Top 10** | 10 | 6 |

📁 **Benchmark Details**: See [`benchmark/`](./benchmark/) directory for full dataset and classification.

---

## 🏗️ Architecture

FaultSeeker employs a **two-stage pipeline**:
![FaultSeeker](full_paper/figs/overview.png)

### Stage 1: Transaction-Level Forensics
![Tx-Level Forensics](full_paper/figs/tx-analysis.png)

Analyzes the attack transaction to extract:
- **Execution trace insights**: Call sequences, state changes
- **Fund flow patterns**: Token transfers, balance changes
- **Actor identification**: Attackers vs. victims
- **Affected contracts**: Scope of analysis

### Stage 2: Function-Level Analysis

![Function-Level Analysis](full_paper/figs/fucntion-analysis.png)

Narrows down to specific vulnerabilities:
- **2a. Fast Ranking**: Filters functions based on forensic evidence (no LLM)
- **2b. Deep Analysis**: Uses LLM to analyze top-ranked functions and produce detailed vulnerability reports

---

## 📁 Project Structure

```
FaultSeeker/
├── faultseeker/
│   ├── core/                      # Core pipeline components
│   │   ├── config.py              # Configuration dataclass
│   │   ├── pipeline.py            # Main orchestration pipeline
│   │   └── base_agent.py          # Base agent abstraction
│   │
│   ├── forensics/                 # Stage 1: Transaction Forensics
│   │   ├── orchestrator.py        # Forensics coordinator
│   │   ├── trace_analyzer.py      # Execution trace analysis
│   │   ├── fund_flow_analyzer.py  # Fund flow & actor identification
│   │   ├── address_classifier.py  # Address role classification
│   │   └── result.py              # ForensicsResult dataclass
│   │
│   ├── function_analysis/         # Stage 2: Function Analysis
│   │   ├── function_ranker.py     # Stage 2a: Fast ranking (no LLM)
│   │   └── function_analyzer.py   # Stage 2b: Deep LLM analysis
│   │
│   ├── data_collection/           # Data collection utilities
│   │   ├── txn_sequencer.py       # Transaction data aggregation
│   │   ├── txn_info_collector.py  # Transaction metadata fetching
│   │   ├── txn_replayer.py        # Transaction replay via Foundry
│   │   ├── contract_downloader.py # Smart contract source retrieval
│   │   └── trace_parser.py        # Trace parsing utilities
│   │
│   ├── prompts/                   # LLM prompt templates
│   │   ├── forensics/             # Stage 1 prompts
│   │   └── function_analysis/     # Stage 2 prompts
│   │
│   ├── utils/                     # Utility modules
│   │   ├── agent.py               # GPTAgent & OllamaAgent
│   │   ├── utils.py               # Helper functions
│   │   ├── chunk_splitter.py      # Smart contract chunking
│   │   └── solidityParser/        # Solidity AST parsing (ANTLR)
│   │
│   └── main.py                    # CLI entry point
│
├── benchmark/                     # Evaluation dataset
│   ├── benchmark_classification.csv
│   ├── ground_truth/              # 115 annotated attack cases
│   └── README.md
│
├── data/                          # Runtime data (auto-generated)
│   ├── cache/                     # Cached forensics & contracts
│   └── output/                    # Analysis results (JSON)
│
├── requirements.txt               # Python dependencies
├── setup.py                       # Package installation
├── foundry.toml                   # Foundry RPC configuration
└── README.md
```

---

## 📚 Citation

If you use FaultSeeker in your research, please cite our paper:

```bibtex
@inproceedings{faultseeker2025,
  title={{FaultSeeker: LLM-Empowered Framework for Blockchain Transaction Fault Localization}},
  author={Sun, Kairan and Xu, Zhengzi and Li, Kaixuan and Zhang, Lyuye and Sun, Yuqiang and Tan, Liwei and Liu, Yang},
  booktitle={Proceedings of the 40th IEEE/ACM International Conference on Automated Software Engineering},
  year={2025},
  series={ASE '25},
  publisher={IEEE},
}
```

---

**⭐ If you find FaultSeeker helpful, please consider starring the repository!**
