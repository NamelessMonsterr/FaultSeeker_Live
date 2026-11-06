"""
Dataset Validation Script - FaultSeeker++ Benchmark
Checks: row count, duplicate TXs, chain distribution, vuln type breakdown
"""
import csv
import os
import re
from collections import Counter


CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_classification_fixed.csv")
TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")

hashes = []
invalid_hashes = []
chains = []
vuln_types = []
difficulty = []

with open(CSV_PATH, encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)
    for line_no, row in enumerate(reader, start=2):
        txn = row["txn_hash"].strip()
        if txn:
            if not TX_HASH_RE.fullmatch(txn):
                invalid_hashes.append((line_no, txn))
            hashes.append(txn)
            chains.append(row["chain"].strip().lower())
            vuln_types.append(row["vuln_type"].strip())
            difficulty.append(row["class"].strip())

total = len(hashes)
dupes = [h for h, c in Counter(hashes).items() if c > 1]

print(f"\n{'=' * 50}")
print("  FaultSeeker++ Dataset Validation Report")
print(f"{'=' * 50}")
print(f"\n  Total entries   : {total}")
print(f"  Duplicate hashes: {len(dupes)}")
print(f"  Invalid hashes  : {len(invalid_hashes)}")
if dupes:
    print(f"   -> Dupes: {dupes}")
if invalid_hashes:
    print("   -> Invalid examples:")
    for line_no, txn in invalid_hashes[:10]:
        print(f"      line {line_no}: {txn}")

print("\n  Chain breakdown:")
for chain, count in sorted(Counter(chains).items(), key=lambda x: -x[1]):
    pct = count / total * 100
    bar = "#" * int(pct / 2)
    print(f"    {chain:<12} {count:>4}  ({pct:4.1f}%)  {bar}")

print("\n  Difficulty breakdown:")
for diff, count in sorted(Counter(difficulty).items(), key=lambda x: -x[1]):
    print(f"    {diff:<30} {count:>4}")

print("\n  Top 10 vulnerability types:")
for vuln, count in Counter(vuln_types).most_common(10):
    print(f"    {vuln:<45}  {count}")

print(f"\n{'=' * 50}")
passed = total >= 160 and not dupes and not invalid_hashes
print(f"  Target: 160+ strict entries  |  Status: {'PASSED' if passed else 'FAILED'}")
print(f"{'=' * 50}\n")

if not passed:
    raise SystemExit(1)
