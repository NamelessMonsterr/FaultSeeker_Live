import argparse
import csv
import json
import os
import re
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List


HF_DATASET = "akshaynexus/DeFiHackLabs-Dataset"
HF_CONFIG = "incidents"
HF_SPLIT = "train"
HF_ROWS_URL = "https://datasets-server.huggingface.co/rows"
TX_HASH_RE = re.compile(r"0x[a-fA-F0-9]{64}")


def fetch_hf_rows(
    dataset: str = HF_DATASET,
    config: str = HF_CONFIG,
    split: str = HF_SPLIT,
    limit: int | None = None,
    page_size: int = 100,
    sleep_seconds: float = 0.0,
) -> List[Dict[str, Any]]:
    rows = []
    offset = 0
    while True:
        length = page_size
        if limit is not None:
            remaining = limit - len(rows)
            if remaining <= 0:
                break
            length = min(length, remaining)
        payload = query_hf_rows(dataset, config, split, offset=offset, length=length)
        page_rows = [item.get("row", {}) for item in payload.get("rows", [])]
        rows.extend(page_rows)
        total = int(payload.get("num_rows_total", len(rows)))
        if len(rows) >= total or not page_rows:
            break
        offset += len(page_rows)
        if sleep_seconds:
            time.sleep(sleep_seconds)
    return rows


def query_hf_rows(dataset: str, config: str, split: str, offset: int, length: int) -> Dict[str, Any]:
    params = urllib.parse.urlencode(
        {
            "dataset": dataset,
            "config": config,
            "split": split,
            "offset": offset,
            "length": length,
        }
    )
    request = urllib.request.Request(
        f"{HF_ROWS_URL}?{params}",
        headers={"User-Agent": "FaultSeekerResearch/1.0"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def normalize_incident(row: Dict[str, Any]) -> Dict[str, Any]:
    text_blob = json.dumps(row, sort_keys=True)
    tx_hashes = sorted(set(TX_HASH_RE.findall(text_blob)))
    contracts = _coerce_contracts(row.get("contracts"))
    chains = sorted(
        {
            str(contract.get("chain", {}).get("name", "")).strip()
            for contract in contracts
            if isinstance(contract, dict) and contract.get("chain")
        }
    )
    contract_addresses = sorted(
        {
            str(contract.get("address", "")).lower()
            for contract in contracts
            if isinstance(contract, dict) and contract.get("address")
        }
    )
    return {
        "source": "huggingface:akshaynexus/DeFiHackLabs-Dataset",
        "incident_id": row.get("id", ""),
        "title": row.get("title", ""),
        "attack_title": row.get("attack_title", ""),
        "vulnerability_type": row.get("ai_vulnerability_type", ""),
        "root_cause": row.get("ai_root_cause", ""),
        "confidence_score": row.get("ai_confidence_score", ""),
        "resolution_status": row.get("resolution_status", ""),
        "chains": "|".join(chains),
        "contract_addresses": "|".join(contract_addresses),
        "transaction_hashes": "|".join(tx_hashes),
        "has_transaction_hash": bool(tx_hashes),
        "source_row_json": json.dumps(row, sort_keys=True),
    }


def _coerce_contracts(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def write_incidents(rows: Iterable[Dict[str, Any]], output_csv: str) -> int:
    normalized = [normalize_incident(row) for row in rows]
    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    fieldnames = list(normalized[0].keys()) if normalized else list(normalize_incident({}).keys())
    with open(output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(normalized)
    return len(normalized)


def main() -> None:
    parser = argparse.ArgumentParser(description="Import public incident-level datasets for FaultSeeker++ research.")
    parser.add_argument("--source", choices=["hf-defihacklabs"], default="hf-defihacklabs")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", default="benchmark/imported/defihacklabs_incidents.csv")
    parser.add_argument("--page-size", type=int, default=100)
    args = parser.parse_args()

    rows = fetch_hf_rows(limit=args.limit, page_size=args.page_size)
    count = write_incidents(rows, args.output)
    with_hashes = sum(1 for row in rows if normalize_incident(row)["has_transaction_hash"])
    print(json.dumps({"rows_written": count, "rows_with_transaction_hashes": with_hashes, "output": args.output}, indent=2))


if __name__ == "__main__":
    main()
