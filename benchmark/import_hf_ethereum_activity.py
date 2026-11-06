import argparse
import csv
import io
import json
import os
import tempfile
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError
from collections import Counter

DATASET = "fesevu/ethereum_fraud_dataset_by_activity"
DATASET_BASE = "https://datasets-server.huggingface.co"
LABELS_URL = (
    "https://huggingface.co/datasets/fesevu/ethereum_fraud_dataset_by_activity/"
    "resolve/main/addr_labels_balanced.csv.zst"
)
DEFAULT_OUTPUT = "benchmark/imported/hf_ethereum_benign_transactions.csv"
DEFAULT_SUMMARY_OUTPUT = "benchmark/imported/hf_ethereum_benign_transactions_summary.json"
ADDRESS_ID_MAP_URL = (
    "https://huggingface.co/datasets/fesevu/ethereum_fraud_dataset_by_activity/"
    "resolve/main/gnn_dataset/mapping/address_id_map_labels.parquet"
)
ROW_PAGE_SIZE = 100
MAX_PAGES = 200
MAX_PARQUET_FILES = 20

FIELDNAMES = [
    "txn_hash",
    "chain",
    "benign_category",
    "source",
    "validation_status",
    "from_address",
    "to_address",
    "block_number",
    "timestamp",
    "value_wei",
    "tx_fee_wei",
    "matched_non_scam_address",
    "label_source",
]


def import_benign_activity(
    target_rows: int = 10000,
    max_pages: int = MAX_PAGES,
    page_size: int = ROW_PAGE_SIZE,
    source: str = "auto",
    max_parquet_files: int = MAX_PARQUET_FILES,
) -> tuple[list[dict], dict]:
    labels = load_address_labels()
    if source == "parquet":
        return import_benign_activity_from_parquet(labels, target_rows, max_parquet_files)

    rows: list[dict] = []
    seen_hashes: set[str] = set()
    pages_scanned = 0

    try:
        for offset in range(0, max_pages * page_size, page_size):
            pages_scanned += 1
            for source_row in fetch_transaction_rows(offset=offset, length=page_size):
                normalized = normalize_benign_row(source_row, labels)
                if not normalized:
                    continue
                tx_hash = normalized["txn_hash"]
                if tx_hash in seen_hashes:
                    continue
                seen_hashes.add(tx_hash)
                rows.append(normalized)
                if len(rows) >= target_rows:
                    return rows, build_summary(rows, labels, pages_scanned, target_rows, source_mode="rows_api")
    except HTTPError as exc:
        if source != "auto" or exc.code != 429:
            raise
        parquet_rows, summary = import_benign_activity_from_parquet(labels, target_rows, max_parquet_files)
        return parquet_rows, {**summary, "rows_api_pages_before_fallback": pages_scanned, "fallback_reason": "HTTP 429"}

    return rows, build_summary(rows, labels, pages_scanned, target_rows, source_mode="rows_api")


def import_benign_activity_from_parquet(
    labels: dict[str, set[str]],
    target_rows: int,
    max_parquet_files: int,
) -> tuple[list[dict], dict]:
    address_by_id = load_address_id_map()
    rows: list[dict] = []
    seen_hashes: set[str] = set()
    files_scanned = 0

    for parquet_file in small_parquet_files()[:max_parquet_files]:
        files_scanned += 1
        for source_row in fetch_parquet_rows(parquet_file["url"]):
            row = map_parquet_row(source_row, address_by_id)
            normalized = normalize_benign_row(row, labels)
            if not normalized:
                continue
            tx_hash = normalized["txn_hash"]
            if tx_hash in seen_hashes:
                continue
            seen_hashes.add(tx_hash)
            rows.append(normalized)
            if len(rows) >= target_rows:
                return rows, build_summary(
                    rows,
                    labels,
                    pages_scanned=0,
                    target_rows=target_rows,
                    source_mode="parquet",
                    parquet_files_scanned=files_scanned,
                )

    return rows, build_summary(
        rows,
        labels,
        pages_scanned=0,
        target_rows=target_rows,
        source_mode="parquet",
        parquet_files_scanned=files_scanned,
    )


def load_address_labels(labels_url: str = LABELS_URL) -> dict[str, set[str]]:
    try:
        import zstandard
    except ImportError as exc:
        raise RuntimeError(
            "zstandard is required to decompress Hugging Face address labels. "
            "Install zstandard>=0.22.0 before running this importer."
        ) from exc

    compressed = urllib.request.urlopen(labels_url, timeout=120).read()
    decompressed = zstandard.ZstdDecompressor().decompress(compressed).decode("utf-8")
    labels = {"non_scam": set(), "scam": set()}
    for row in csv.DictReader(io.StringIO(decompressed)):
        address = row.get("address", "").strip().lower()
        if not address:
            continue
        if row.get("is_scam", "").strip() == "1":
            labels["scam"].add(address)
        else:
            labels["non_scam"].add(address)
    return labels


def fetch_transaction_rows(offset: int, length: int, retries: int = 5, backoff_seconds: float = 3.0) -> list[dict]:
    query = urllib.parse.urlencode(
        {"dataset": DATASET, "config": "default", "split": "train", "offset": offset, "length": length}
    )
    url = f"{DATASET_BASE}/rows?{query}"
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=120) as response:
                payload = json.loads(response.read().decode("utf-8"))
            return [item["row"] for item in payload.get("rows", [])]
        except HTTPError as exc:
            if exc.code != 429 or attempt == retries - 1:
                raise
            time.sleep(backoff_seconds * (attempt + 1))
        except URLError:
            if attempt == retries - 1:
                raise
            time.sleep(backoff_seconds * (attempt + 1))
    return []


def load_address_id_map(url: str = ADDRESS_ID_MAP_URL) -> dict[int, str]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError(
            "pyarrow is required for parquet fallback. Install pyarrow or use --source rows."
        ) from exc

    path = download_temp_file(url, "address_id_map_labels.parquet")
    table = pq.read_table(path, columns=["address", "node_id"])
    return {int(row["node_id"]): str(row["address"]).lower() for row in table.to_pylist()}


def small_parquet_files(max_size_bytes: int = 20_000_000) -> list[dict]:
    query = urllib.parse.urlencode({"dataset": DATASET})
    with urllib.request.urlopen(f"{DATASET_BASE}/parquet?{query}", timeout=120) as response:
        payload = json.loads(response.read().decode("utf-8"))
    files = [
        item
        for item in payload.get("parquet_files", [])
        if item.get("split") == "train" and int(item.get("size", 0)) <= max_size_bytes
    ]
    return files


def fetch_parquet_rows(url: str) -> list[dict]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError(
            "pyarrow is required for parquet fallback. Install pyarrow or use --source rows."
        ) from exc

    path = download_temp_file(url, os.path.basename(urllib.parse.urlparse(url).path))
    try:
        table = pq.read_table(
            path,
            columns=[
                "src_id",
                "dst_id",
                "ts",
                "value_wei",
                "tx_fee_wei",
                "block_number",
                "contract_creation",
                "tx_hash",
            ],
        )
    except Exception as exc:
        if "No match for FieldRef.Name(src_id)" in str(exc):
            return []
        raise
    return table.to_pylist()


def download_temp_file(url: str, filename: str) -> str:
    path = os.path.join(tempfile.gettempdir(), f"faultseeker_{filename}")
    urllib.request.urlretrieve(url, path)
    return path


def map_parquet_row(row: dict, address_by_id: dict[int, str]) -> dict:
    return {
        "tx_hash": row.get("tx_hash", ""),
        "from_address": address_by_id.get(int(row.get("src_id", -1)), ""),
        "to_address": address_by_id.get(int(row.get("dst_id", -1)), ""),
        "block_number": row.get("block_number", ""),
        "timestamp": row.get("ts", ""),
        "value_wei": row.get("value_wei", ""),
        "tx_fee_wei": row.get("tx_fee_wei", ""),
        "contract_creation": row.get("contract_creation", ""),
    }


def normalize_benign_row(row: dict, labels: dict[str, set[str]]) -> dict | None:
    tx_hash = str(row.get("tx_hash", "")).strip().lower()
    from_address = str(row.get("from_address", "")).strip().lower()
    to_address = str(row.get("to_address", "")).strip().lower()
    if not tx_hash or not from_address:
        return None
    if from_address in labels["scam"] or to_address in labels["scam"]:
        return None
    matched = from_address if from_address in labels["non_scam"] else ""
    if not matched and to_address in labels["non_scam"]:
        matched = to_address
    if not matched:
        return None
    return {
        "txn_hash": tx_hash,
        "chain": "eth",
        "benign_category": "non_scam_address_activity",
        "source": f"huggingface:{DATASET}",
        "validation_status": "address_label_benign_candidate",
        "from_address": from_address,
        "to_address": to_address,
        "block_number": row.get("block_number", ""),
        "timestamp": row.get("timestamp", ""),
        "value_wei": row.get("value_wei", ""),
        "tx_fee_wei": row.get("tx_fee_wei", ""),
        "matched_non_scam_address": matched,
        "label_source": "addr_labels_balanced.csv.zst:is_scam=0",
    }


def build_summary(
    rows: list[dict],
    labels: dict[str, set[str]],
    pages_scanned: int,
    target_rows: int,
    source_mode: str = "rows_api",
    parquet_files_scanned: int = 0,
) -> dict:
    return {
        "source": f"huggingface:{DATASET}",
        "source_mode": source_mode,
        "rows": len(rows),
        "target_rows": target_rows,
        "target_met": len(rows) >= target_rows,
        "pages_scanned": pages_scanned,
        "parquet_files_scanned": parquet_files_scanned,
        "unique_transactions": len({row["txn_hash"] for row in rows}),
        "validation_status_counts": dict(Counter(row["validation_status"] for row in rows)),
        "chain_counts": dict(Counter(row["chain"] for row in rows)),
        "label_counts": {
            "non_scam_addresses": len(labels["non_scam"]),
            "scam_addresses_excluded": len(labels["scam"]),
        },
        "merge_guidance": (
            "Use for false-positive evaluation after downstream RPC spot checks. "
            "Do not treat as exploit ground truth."
        ),
    }


def write_csv(path: str, rows: list[dict]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Import labeled non-scam Ethereum activity from Hugging Face.")
    parser.add_argument("--target-rows", type=int, default=10000)
    parser.add_argument("--max-pages", type=int, default=MAX_PAGES)
    parser.add_argument("--max-parquet-files", type=int, default=MAX_PARQUET_FILES)
    parser.add_argument("--source", choices=["auto", "rows", "parquet"], default="auto")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--summary-output", default=DEFAULT_SUMMARY_OUTPUT)
    args = parser.parse_args()

    rows, summary = import_benign_activity(
        target_rows=args.target_rows,
        max_pages=args.max_pages,
        source="rows_api" if args.source == "rows" else args.source,
        max_parquet_files=args.max_parquet_files,
    )
    write_csv(args.output, rows)
    write_json(args.summary_output, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
