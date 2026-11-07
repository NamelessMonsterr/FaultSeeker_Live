"""Exploit presets from the benchmark ground truth shipped in this repository."""
import json
import re
from functools import lru_cache
from typing import Dict, List, Optional

from . import settings


def _date_parts(text: str):
    m = re.match(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", text or "")
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def _date_label(text: str) -> str:
    y, mo, d = _date_parts(text)
    return f"{y:04d}-{mo:02d}-{d:02d}" if y else ""


@lru_cache(maxsize=1)
def _load() -> List[dict]:
    rows, seen = [], set()
    if not settings.BENCHMARK_DIR.exists():
        return rows
    for path in sorted(settings.BENCHMARK_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        chain = settings.PLATFORM_TO_CHAIN.get(data.get("platform"))
        hashes = data.get("transaction_hash") or []
        if not chain or not hashes:
            continue
        tx = str(hashes[0]).lower()
        if tx in seen:      # the benchmark lists at least one transaction twice
            continue
        seen.add(tx)
        rows.append({"tx": tx, "chain": chain, "name": data.get("name", "Unnamed"),
                     "cause": data.get("cause", ""), "lost": data.get("lost") or "",
                     "time": data.get("time", ""), "location": data.get("location") or {}})
    rows.sort(key=lambda r: _date_parts(r["time"]), reverse=True)
    return rows


def presets_by_chain() -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = {c["id"]: [] for c in settings.CHAINS}
    for r in _load():
        out[r["chain"]].append({"hash": r["tx"], "name": r["name"], "cause": r["cause"],
                                "lost": r["lost"], "date": _date_label(r["time"])})
    return out


def ground_truth_by_hash(tx: str) -> Optional[dict]:
    tx = tx.lower()
    return next((r for r in _load() if r["tx"] == tx), None)
