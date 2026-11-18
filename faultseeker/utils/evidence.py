"""Shared normalization of model-supplied evidence and confidence values.

Used at BOTH boundaries: when the analyzer accepts a verdict entry, and when the report normalizer builds user-visible
evidence. Supported structures become readable text; everything else is dropped (and counted), never dumped as raw objects.
Nothing here executes model text: stringified containers are parsed with json / ast.literal_eval only.
"""
import ast
import json
import math
import re
from typing import Any, List, Optional, Tuple

EVIDENCE_TEXT_LIMIT = 2000
PROVIDER_ERROR_SENTINELS = {"an error occurred."}
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# (key, label) in display order. An empty label means the value is shown as plain text.
_TEXT_FIELDS = (("evidence", ""), ("observation", "Observation"), ("observations", "Observation"), ("fact", "Observation"),
                ("facts", "Observation"), ("hypothesis", "Hypothesis"), ("explanation", "Explanation"), ("reason", "Reason"),
                ("reasoning", "Reason"), ("description", ""), ("summary", ""), ("detail", ""), ("details", ""), ("text", ""),
                ("finding", ""))
# Never rendered: model self-assessment and provider/status bookkeeping.
_IGNORED_FIELDS = {"confidence", "confidence_score", "score", "probability", "error", "errors", "status", "severity"}


def _clean_text(text: str) -> str:
    text = _CONTROL.sub(" ", _ANSI.sub("", text)).strip()
    return text[:EVIDENCE_TEXT_LIMIT] + "…" if len(text) > EVIDENCE_TEXT_LIMIT else text


def is_error_sentinel(text: Any) -> bool:
    return isinstance(text, str) and text.strip().strip("\"'`").strip().casefold() in PROVIDER_ERROR_SENTINELS


def _container_from_text(text: str):
    """A dict/list a model wrote as text (JSON or a Python literal), or None. Never executes anything."""
    body = text.strip()
    if not (body[:1] in "{[" and len(body) <= 20000):
        return None
    for parse in (json.loads, ast.literal_eval):
        try:
            value = parse(body)
        except (ValueError, SyntaxError, MemoryError, RecursionError, TypeError):
            continue
        return value if isinstance(value, (dict, list)) else None
    return None


def _walk(value: Any, out: List[str], dropped: List[int], depth: int = 0) -> None:
    if value is None:
        return
    if depth > 6:
        dropped[0] += 1
        return
    if isinstance(value, str):
        container = _container_from_text(value)
        if container is not None:
            _walk(container, out, dropped, depth + 1)
            return
        text = _clean_text(value)
        if not text:
            return
        if is_error_sentinel(text):
            dropped[0] += 1
            return
        out.append(text)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk(item, out, dropped, depth + 1)
    elif isinstance(value, dict):
        parts: List[str] = []
        for key, label in _TEXT_FIELDS:
            if key in value:
                inner: List[str] = []
                _walk(value[key], inner, dropped, depth + 1)
                if inner:
                    text = "; ".join(inner)
                    parts.append(f"{label}: {text}" if label else text)
        if parts:
            out.append("; ".join(parts))
        elif any(k not in _IGNORED_FIELDS for k in value) or not value:
            dropped[0] += 1                      # an object with nothing readable in it: counted, never dumped
    else:
        dropped[0] += 1                          # numbers, booleans and other values are not evidence


def normalize_evidence(value: Any) -> Tuple[List[str], int]:
    """(readable evidence texts, number of supplied items that could not be used). None and empty text are neither."""
    out: List[str] = []
    dropped = [0]
    _walk(value, out, dropped)
    return out, dropped[0]


def normalize_confidence(value: Any) -> Optional[float]:
    """A finite confidence in (0, 1] as a float, or None. Booleans, None, non-numeric text, NaN, infinities, zero, negative
    numbers and values above 1 are all unsupported (the prompt defines the scale as 0.0-1.0)."""
    if isinstance(value, bool) or value is None or not isinstance(value, (int, float, str)):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0 < number <= 1 else None
