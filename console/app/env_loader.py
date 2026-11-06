"""Minimal .env reader so local launches need no shell exports.

Existing process environment always wins; the file only fills gaps. Values are
never logged. Only simple KEY=VALUE lines are supported (optional quotes,
optional leading ``export``, ``#`` comment lines).
"""
import os


def parse_env_text(text):
    values = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and all(ch.isalnum() or ch == "_" for ch in key) and not key[0].isdigit():
            values[key] = value
    return values


def load_env_file(path, environ=None):
    """Fill missing variables from ``path``. Returns the names that were set."""
    target = os.environ if environ is None else environ
    try:
        with open(path, "r", encoding="utf-8") as handle:
            parsed = parse_env_text(handle.read())
    except OSError:
        return []
    applied = []
    for key, value in parsed.items():
        if value == "":
            continue  # blank template entries must not mask real configuration
        if not target.get(key):
            target[key] = value
            applied.append(key)
    return applied
