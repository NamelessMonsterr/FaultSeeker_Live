"""Input validation and secret redaction."""
import ipaddress
import re
import socket
from urllib.parse import quote, urlsplit

from . import settings

HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
SECRET_PATTERNS = [re.compile(r"sk-[A-Za-z0-9_\-]{16,}")]


class ValidationError(Exception):
    def __init__(self, field: str, message: str, code: str = "invalid_input"):
        super().__init__(message)
        self.field, self.message, self.code = field, message, code


def validate_hash(value) -> str:
    value = (value or "").strip()
    if not HASH_RE.match(value):
        raise ValidationError("txn_hash", "Enter a full transaction hash: 0x followed by 64 hex characters.")
    return value.lower()


def validate_secret(field: str, value, label: str):
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) > 512 or re.search(r"[\s\x00-\x1f]", value):
        raise ValidationError(field, f"{label} contains invalid characters or is too long.")
    return value


def _check_public_host(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValidationError("rpc_url", f"Could not resolve the RPC host “{host}”.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            raise ValidationError("rpc_url", "RPC endpoints on private or local networks are not allowed.")


def resolve_rpc(url, key):
    """Return the final RPC URL (or '' for the server connection)."""
    url, key = (url or "").strip(), (key or "").strip()
    if not url:
        if key:
            raise ValidationError("rpc_key", "Add an RPC URL for this key, or clear the key to use the server connection.")
        return ""
    if len(url) > 2048 or re.search(r"[\s\x00-\x1f]", url):
        raise ValidationError("rpc_url", "RPC URL contains invalid characters or is too long.")
    has_placeholder = "{key}" in url
    if has_placeholder and not key:
        raise ValidationError("rpc_key", "The RPC URL contains {key}; supply the key or paste a complete endpoint.")
    if key and not has_placeholder:
        raise ValidationError("rpc_key", "Put {key} in the RPC URL where the key belongs, or clear the key field.")
    final = url.replace("{key}", quote(key, safe="")) if has_placeholder else url
    parts = urlsplit(final)
    if parts.scheme not in ("http", "https", "ws", "wss") or not parts.hostname:
        raise ValidationError("rpc_url", "RPC URL must start with http://, https://, ws:// or wss://.")
    if not settings.ALLOW_PRIVATE_RPC:
        _check_public_host(parts.hostname)
    return final


class Redactor:
    """Masks secrets supplied for one run before any text is stored or shown."""

    def __init__(self, *secrets):
        found = set()
        for s in secrets:
            if not s:
                continue
            found.add(s)
            if "://" in s:
                parts = urlsplit(s)
                found.add(s.split("://", 1)[1])
                last = parts.path.rstrip("/").rsplit("/", 1)[-1]
                if len(last) >= 12:
                    found.add(last)
                if parts.query:
                    found.add(parts.query)
                if parts.password:
                    found.add(parts.password)
        self._secrets = sorted((x for x in found if len(x) >= 4), key=len, reverse=True)

    def clean(self, text: str) -> str:
        for s in self._secrets:
            text = text.replace(s, "••••")
        for pat in SECRET_PATTERNS:
            text = pat.sub("••••", text)
        return text
