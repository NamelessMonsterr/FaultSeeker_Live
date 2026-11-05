import argparse
import csv
import datetime as dt
import json
import os
import urllib.request
from typing import Any


DEFILLAMA_HACKS_URL = "https://api.llama.fi/hacks"
DEFAULT_OUTPUT = "benchmark/imported/defillama_hacks.full.csv"
FIELDS = [
    "source",
    "incident_id",
    "title",
    "date",
    "amount_usd",
    "chains",
    "classification",
    "technique",
    "target_type",
    "language",
    "bridge_hack",
    "returned_funds_usd",
    "source_url",
    "defillama_id",
    "has_transaction_hash",
    "validation_status",
    "required_next_steps",
    "source_row_json",
]


def fetch_defillama_hacks(url: str = DEFILLAMA_HACKS_URL) -> list[dict[str, Any]]:
    request = urllib.request.Request(url, headers={"User-Agent": "FaultSeekerResearch/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = json.loads(response.read().decode("utf-8"))
    if not isinstance(data, list):
        raise ValueError("DefiLlama hacks endpoint returned a non-list payload")
    return [row for row in data if isinstance(row, dict)]


def normalize_hack(row: dict[str, Any]) -> dict[str, Any]:
    chains = row.get("chain") or []
    if isinstance(chains, str):
        chains = [chains]
    if not isinstance(chains, list):
        chains = []
    name = str(row.get("name") or "").strip()
    date_value = _format_date(row.get("date"))
    incident_id = _incident_id(name, date_value, row.get("defillamaId"))
    return {
        "source": "defillama:hacks",
        "incident_id": incident_id,
        "title": name,
        "date": date_value,
        "amount_usd": _coerce_number(row.get("amount")),
        "chains": "|".join(str(chain).strip() for chain in chains if str(chain).strip()),
        "classification": row.get("classification") or "",
        "technique": row.get("technique") or "",
        "target_type": row.get("targetType") or "",
        "language": row.get("language") or "",
        "bridge_hack": bool(row.get("bridgeHack")),
        "returned_funds_usd": _coerce_number(row.get("returnedFunds")),
        "source_url": row.get("source") or "",
        "defillama_id": row.get("defillamaId") or "",
        "has_transaction_hash": False,
        "validation_status": "blocked_missing_transaction_hash",
        "required_next_steps": "Find canonical exploit transaction hash and chain before benchmark consideration.",
        "source_row_json": json.dumps(row, sort_keys=True),
    }


def write_hacks(rows: list[dict[str, Any]], output_csv: str) -> int:
    normalized = [normalize_hack(row) for row in rows]
    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    with open(output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(normalized)
    return len(normalized)


def _format_date(value: Any) -> str:
    try:
        timestamp = int(value)
    except (TypeError, ValueError):
        return ""
    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).date().isoformat()


def _incident_id(name: str, date_value: str, defillama_id: Any) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "_" for ch in name).strip("_")
    slug = "_".join(part for part in slug.split("_") if part)
    if defillama_id:
        return f"defillama_{defillama_id}"
    return "_".join(part for part in [date_value, slug] if part)


def _coerce_number(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def main() -> None:
    parser = argparse.ArgumentParser(description="Import DefiLlama hack records as staged incident metadata.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    rows = fetch_defillama_hacks()
    count = write_hacks(rows, args.output)
    print(json.dumps({"rows_written": count, "output": args.output}, indent=2))


if __name__ == "__main__":
    main()
