"""
benchmark/fix_csv.py
Fixes benchmark_classification.csv data quality issues identified in the FaultSeeker++ report:

1. analysis column column-bleed — The column stores Python list literals like
   ['https://...', 'https://...'] with unquoted commas, causing CSV parsers to
   bleed them into the next columns (swc_registry_classification, dasp_classification).
   Fix: re-read the raw file carefully, convert list literals to JSON arrays, re-export
   with csv.QUOTE_ALL so all fields are always quoted.

2. vuln_type normalization — Near-duplicate strings (case/space variation) are merged.

3. Empty vuln_type — 3 blank rows are marked with a TODO marker.
"""

import csv
import ast
import json
import re
from pathlib import Path

INPUT_CSV = Path(__file__).parent / "benchmark_classification.csv"
OUTPUT_CSV = Path(__file__).parent / "benchmark_classification_fixed.csv"

# Canonical vuln_type merge map: normalise to Title Case, then merge near-dups
VULN_TYPE_MERGE = {
    "Business Logic Flaw": "Business Logic Flaw",
    "business logic flaw": "Business Logic Flaw",
    "Arbitrary External Call": "Arbitrary External Call",
    "Arbitrary External Call Vulnerability": "Arbitrary External Call",
    "Price Manipulation": "Price Manipulation",
    "Price Manipulation Attack": "Price Manipulation",
    "Reentrancy": "Reentrancy",
    "Re-Entrancy": "Reentrancy",
    "Flash Loan Attack": "Flash Loan Attack",
    "Flashloan Attack": "Flash Loan Attack",
    "Access Control": "Access Control",
    "Access Control Vulnerability": "Access Control",
    "Integer Overflow": "Integer Overflow",
    "Integer Overflow/Underflow": "Integer Overflow",
}


def _normalise_vuln_type(raw: str) -> str:
    """Strip, title-case, then merge near-duplicates."""
    cleaned = raw.strip().title()
    return VULN_TYPE_MERGE.get(cleaned, cleaned) or VULN_TYPE_MERGE.get(raw.strip(), cleaned)


def _parse_analysis_field(raw: str) -> str:
    """
    The analysis field may contain:
      - A Python list literal: ['https://a', 'https://b']
      - A single URL string
      - An empty string

    Convert all to a proper JSON-encoded string so it won't bleed on re-export.
    """
    raw = raw.strip()
    if not raw:
        return ""
    # Try to parse as Python literal (handles single-quoted lists)
    if raw.startswith("["):
        try:
            urls = ast.literal_eval(raw)
            if isinstance(urls, list):
                return json.dumps(urls)  # Double-quoted JSON array
        except (ValueError, SyntaxError):
            pass
    # Fall back: return as-is (single URL or already-clean string)
    return raw


def fix_csv():
    # Read with a generous quoting mode — Python's csv module handles most bleed cases
    # when we treat every field carefully
    with open(INPUT_CSV, "r", encoding="utf-8", newline="") as f:
        content = f.read()

    # The bleed problem: rows where the analysis column has bare commas inside list
    # literals. We use a custom approach: read line-by-line and detect the expected
    # number of columns from the header, then re-join overflow fields.
    lines = content.splitlines()
    header_row = next(csv.reader([lines[0]]))
    expected_cols = len(header_row)

    fixed_rows = [header_row]
    skipped = 0
    fixed_bleed = 0

    for line_num, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        parsed = list(csv.reader([line]))[0]

        if len(parsed) == expected_cols:
            # Clean row — no bleed
            fixed_rows.append(parsed)
        elif len(parsed) > expected_cols:
            # Bleed detected — the extra fields are fragments of the analysis column.
            # Strategy: keep columns before 'analysis', re-join the overflow back into
            # the analysis field, then take the last (expected - analysis_idx - 1) cols.
            try:
                analysis_idx = header_row.index("analysis")
                tail_col_count = expected_cols - analysis_idx - 1  # cols after analysis
                pre = parsed[:analysis_idx]
                # Slice tail from len(parsed) (actual width), not expected_cols, so
                # overflow columns are not duplicated when the row is wider than expected.
                post = parsed[len(parsed) - tail_col_count:] if tail_col_count else []
                analysis_fragments = parsed[analysis_idx: len(parsed) - tail_col_count if tail_col_count else len(parsed)]
                analysis_joined = ",".join(analysis_fragments)
                row = pre + [analysis_joined] + post
                fixed_rows.append(row)
                fixed_bleed += 1
            except (ValueError, IndexError):
                fixed_rows.append(parsed[:expected_cols])  # Best-effort truncation
                skipped += 1
        else:
            # Fewer columns than expected — pad with empty strings
            fixed_rows.append(parsed + [""] * (expected_cols - len(parsed)))
            skipped += 1

    # Now apply field-level fixes
    try:
        analysis_idx = header_row.index("analysis")
    except ValueError:
        analysis_idx = None

    try:
        vuln_type_idx = header_row.index("vuln_type")
    except ValueError:
        vuln_type_idx = None

    blank_vuln_count = 0
    for i, row in enumerate(fixed_rows[1:], start=1):
        # Fix analysis field
        if analysis_idx is not None and analysis_idx < len(row):
            row[analysis_idx] = _parse_analysis_field(row[analysis_idx])

        # Fix vuln_type
        if vuln_type_idx is not None and vuln_type_idx < len(row):
            raw_vuln = row[vuln_type_idx].strip()
            if not raw_vuln:
                row[vuln_type_idx] = "TODO: Needs Annotation"
                blank_vuln_count += 1
            else:
                row[vuln_type_idx] = _normalise_vuln_type(raw_vuln)

    # Write fixed CSV with QUOTE_ALL
    with open(OUTPUT_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerows(fixed_rows)

    print(f"[OK] Fixed CSV written to: {OUTPUT_CSV}")
    print(f"   Rows processed:       {len(fixed_rows) - 1}")
    print(f"   Column bleed fixed:   {fixed_bleed}")
    print(f"   Blank vuln_type marked: {blank_vuln_count}")
    print(f"   Rows needing review:  {skipped}")

    # Show vuln_type distribution after fix
    if vuln_type_idx is not None:
        from collections import Counter
        counts = Counter(r[vuln_type_idx] for r in fixed_rows[1:])
        print("\n[vuln_type distribution after fix]")
        for vuln, count in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"   {count:3d}  {vuln}")


if __name__ == "__main__":
    fix_csv()
