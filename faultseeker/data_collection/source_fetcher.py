"""Verified contract source from Sourcify: free, no API key, no explorer page.

Writes every source file under `output_dir` (the layout ContractDownloader.parse_contract walks) and, for proxies,
the implementation's files too. Only the standard library is used. Returns the number of .sol files written.
"""
import json
import os
import urllib.error
import urllib.request
from typing import Optional

TIMEOUT = 30


class SourceUnavailable(Exception):
    pass


def _get(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "faultseeker/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise SourceUnavailable(f"Sourcify answered HTTP {exc.code}")
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        raise SourceUnavailable(f"Sourcify could not be reached ({type(getattr(exc, 'reason', exc)).__name__})")


def _safe_join(root: str, rel: str) -> Optional[str]:
    rel = rel.replace("\\", "/").lstrip("/")
    path = os.path.normpath(os.path.join(root, rel))
    return path if path == root or path.startswith(root + os.sep) else None


def _write(sources: dict, root: str) -> int:
    count = 0
    for rel, item in (sources or {}).items():
        content = item.get("content") if isinstance(item, dict) else item
        target = _safe_join(root, rel)
        if target is None or not isinstance(content, str):
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        count += rel.endswith(".sol")
    return count


def fetch(chain_id: int, address: str, output_dir: str, _depth: int = 0) -> int:
    base = os.environ.get("FAULTSEEKER_SOURCIFY_URL", "https://sourcify.dev/server").rstrip("/")
    data = _get(f"{base}/v2/contract/{chain_id}/{address}?fields=sources,proxyResolution")
    if not data or not data.get("match") or not data.get("sources"):
        return 0
    root = os.path.abspath(output_dir)
    count = _write(data["sources"], os.path.join(root, address.lower()) if _depth else root)
    proxy = data.get("proxyResolution") or {}
    if _depth == 0 and proxy.get("isProxy"):
        for impl in (proxy.get("implementations") or [])[:3]:
            impl_address = impl.get("address") if isinstance(impl, dict) else None
            if impl_address:
                try:
                    count += fetch(chain_id, impl_address, os.path.join(root, "Implementation"), 1)
                except SourceUnavailable:
                    pass
    return count
