"""Private, bounded per-call evidence for the model boundary.

Purpose: let an offline reader tell apart (a) analyzed-function source present
in the request, (b) what the model answered (keys it returned: the analyzed
call id itself vs child call ids), (c) what binding rejected, and (d) what
survived aggregation - without re-running a model.

Design rules (tested):
- Observes the ADAPTED request (after every transform, immediately before the
  provider SDK call) and the provider response at receipt. Not a template.
- Credentials never reach prompts, but redaction is applied anyway to all text.
- Hard size limits; anything cut carries an explicit omission marker with the
  original length. Nothing is silently dropped.
- Fail-safe: callers wrap capture in try/except; capture can never alter
  dispatch, retries, or session state.
- Lives only in the run's private result under _debug.call_evidence. It is not
  copied into status, events, or the model_endpoint summary.
"""
import hashlib
import json
import re
import threading

MAX_CALLS = 80
HEAD_REQUEST = 2000
TAIL_REQUEST = 1500
HEAD_RESPONSE = 3000
TAIL_RESPONSE = 1000
TOTAL_TEXT_BUDGET = 450_000   # characters of captured text across all calls
MAX_IDS = 40
MAX_FEATURE_SCAN_CHARS = 400_000   # features/regex scan at most this much text
MAX_PARSE_CHARS = 200_000          # responses larger than this are not JSON-parsed
MAX_MESSAGES_SCAN = 200            # messages examined per request (head and last-user search)
MAX_LABEL = 120                    # model/phase/role/finish_reason/key strings

_CALL_ID = re.compile(r"0x[0-9a-fA-F]{8}_0x[0-9a-fA-F]{40}")
_SOURCE_MARKERS = {
    "pragma_solidity": re.compile(r"pragma\s+solidity", re.I),
    "contract_decl": re.compile(r"\bcontract\s+\w+"),
    "function_decl": re.compile(r"\bfunction\s+\w+\s*\("),
}
_REDACTIONS = [
    (re.compile(r"(?i)([\"']?(?:authorization|api[_-]?key|x-api-key|access[_-]?token|refresh[_-]?token|"
                r"id[_-]?token|client[_-]?secret|password|passwd|secret|token)[\"']?\s*[:=]\s*)"
                r"(\"[^\"]*\"|'[^']*')"), r"\1[REDACTED]"),
    (re.compile(r"(?i)([?&](?:api[_-]?key|key|token|access_token|auth|secret|sig|signature)=)[^&\s\"']+"),
     r"\1[REDACTED]"),
    (re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), "[REDACTED_JWT]"),
    (re.compile(r"\b(?:sk|pk|rk|key|tok)[-_][A-Za-z0-9_-]{16,}"), "[REDACTED_KEY]"),
    (re.compile(r"(?i)(authorization|api[_-]?key|x-api-key|access[_-]?token|refresh[_-]?token|"
                r"id[_-]?token|client[_-]?secret|password|passwd|secret|token)([\"']?\s*[:=]\s*[\"']?)[^\s\"',}\]]{6,}"),
     r"\1\2[REDACTED]"),
]


def redact(text):
    if not isinstance(text, str):
        return text
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def label(value, limit=MAX_LABEL):
    """Short, redacted, length-bounded string for any retained label or key."""
    return redact(str(value))[:limit]


MAX_HASH_CHARS = 1_500_000


def _within_budget(value, budget):
    """Cheap bounded walk BEFORE any serialization: True only if the structure
    is small enough (strings, containers, nodes, depth) to hash within budget."""
    stack, used, nodes = [(value, 0)], 0, 0
    while stack:
        v, d = stack.pop()
        nodes += 1
        if nodes > 20000 or d > 12:
            return False
        if isinstance(v, str):
            used += 6 * len(v)  # worst-case JSON escaping (\\uXXXX per char)
        elif isinstance(v, dict):
            used += 4 * len(v)
            if len(v) > 5000:
                return False
            for k, x in v.items():
                if not isinstance(k, str):
                    return False
                used += 6 * len(k)
                stack.append((x, d + 1))
        elif isinstance(v, (list, tuple)):
            used += len(v)
            if len(v) > 5000:
                return False
            stack.extend((x, d + 1) for x in v)
        elif v is None or isinstance(v, (bool, int, float)):
            used += 8
        else:
            return False
        if used > budget:
            return False
    return True


def sha16(value):
    """Digest of the canonical JSON of the WHOLE value. A bounded structural
    pre-check runs first; oversized or unbounded structures are not serialized
    at all (explicit marker). Identity only, not a wire hash."""
    if not _within_budget(value, MAX_HASH_CHARS):
        return "skipped_oversize"
    h = hashlib.sha256()
    n = 0
    try:
        for chunk in json.JSONEncoder(sort_keys=True, default=str).iterencode(value):
            n += len(chunk)
            if n > MAX_HASH_CHARS:
                return "skipped_oversize"
            h.update(chunk.encode())
    except Exception:
        return "unserializable"
    return h.hexdigest()[:16]


def bounded_sha16(value, total_chars):
    if total_chars > MAX_HASH_CHARS:
        return "skipped_oversize"
    return sha16(value)


_EDGE_MARGIN = 256
_EDGE_RUN = re.compile(r"\S+")


def bounded_text(text, head, tail):
    """Redacted text cut to head+tail with an explicit omission marker.

    Work is O(head+tail): only the retained edges (plus a margin so a pattern
    straddling the cut can still match) are ever redacted. A token cut in half
    by the boundary is dropped, so no partial credential survives at an edge.
    original_chars is the length of the INPUT, before redaction."""
    if not isinstance(text, str):
        return {"text": None, "original_chars": 0, "omitted_chars": 0}
    n = len(text)
    if n <= head + tail:
        return {"text": redact(text), "original_chars": n, "omitted_chars": 0}
    h = redact(text[:head + _EDGE_MARGIN])[:head]
    if text[head - 1:head + 1].strip() and len(text[head - 1:head + 1].strip()) == 2:
        h = h[:len(h) - len(_EDGE_RUN.findall(h[-_EDGE_MARGIN:])[-1])] if _EDGE_RUN.findall(h[-_EDGE_MARGIN:]) else h
    t = redact(text[-(tail + _EDGE_MARGIN):])[-tail:]
    if n > tail and text[-tail - 1:-tail + 1].strip() and len(text[-tail - 1:-tail + 1].strip()) == 2:
        m = _EDGE_RUN.match(t)
        if m:
            t = t[m.end():]
    omitted = n - len(h) - len(t)
    return {"text": h + "\n[...OMITTED %d CHARS...]\n" % omitted + t,
            "original_chars": n, "omitted_chars": omitted}


def _ids(text, limit=MAX_IDS):
    seen, out = set(), []
    for m in _CALL_ID.findall(text or ""):
        k = m.lower()
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out[:limit], max(0, len(seen) - limit)


def request_features(adapted_messages):
    """Program-computed facts about the ADAPTED messages (not template text)."""
    msgs = adapted_messages if isinstance(adapted_messages, list) else []
    return _features(msgs)[0]


def _features(msgs):
    parts, total, scanned = [], 0, 0
    unexamined = False
    for m in msgs[:MAX_MESSAGES_SCAN]:
        c = m.get("content") if isinstance(m, dict) else None
        if isinstance(c, list):
            # structured content blocks: scan text parts; anything else is
            # unexamined content, so the scan cannot be called complete.
            tx, room = [], max(0, MAX_FEATURE_SCAN_CHARS - scanned)
            for b in c[:200]:
                if isinstance(b, dict) and isinstance(b.get("text"), str) and set(b) <= {"type", "text"}:
                    t = b["text"]
                    total += len(t)
                    if room > 0:
                        tx.append(t[:room])
                        room -= len(tx[-1])
                else:
                    unexamined = True
            if len(c) > 200:
                unexamined = True
            parts.extend(tx)
            scanned += sum(len(x) for x in tx)
            c = None
        elif c is not None and not isinstance(c, str):
            unexamined = True
            c = None
        if isinstance(c, str):
            total += len(c)
            if scanned < MAX_FEATURE_SCAN_CHARS:
                chunk = c[:MAX_FEATURE_SCAN_CHARS - scanned]
                parts.append(chunk)
                scanned += len(chunk)
    full = "\n".join(parts)
    ids, ids_more = _ids(full)
    complete = not (total > scanned or len(msgs) > MAX_MESSAGES_SCAN or unexamined)
    return ({
        "message_count": len(msgs),
        "roles": [label(m.get("role"), 20) if isinstance(m, dict) else None for m in msgs[:60]],
        "total_chars": total,
        "scanned_chars": scanned,
        "scan_truncated": not complete,
        "unexamined_content": unexamined,
        "messages_not_scanned": max(0, len(msgs) - MAX_MESSAGES_SCAN),
        "source_markers": {k: len(rx.findall(full)) for k, rx in _SOURCE_MARKERS.items()},
        "call_ids_in_request": ids,
        "call_ids_in_request_more": ids_more,
    }, full, complete)


def response_features(content):
    """What the model answered: parse JSON when possible, list top-level keys."""
    out = {"chars": len(content) if isinstance(content, str) else 0,
           "json_parse": "not_text"}
    if not isinstance(content, str):
        return out
    if len(content) > MAX_PARSE_CHARS:
        out["json_parse"] = "skipped_oversize"
        ids, more = _ids(content[:MAX_FEATURE_SCAN_CHARS])
        out["call_ids_in_text"] = ids
        return out
    body = content.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", body, re.S)
    if fence:
        body = fence.group(1)
    try:
        parsed = json.loads(body)
    except Exception:
        out["json_parse"] = "failed"
        ids, more = _ids(content)
        out["call_ids_in_text"] = ids
        return out
    out["json_parse"] = "ok"
    out["json_type"] = type(parsed).__name__
    if isinstance(parsed, dict):
        keys = [label(k) for k in list(parsed)[:MAX_IDS]]
        out["top_level_keys"] = keys
        out["top_level_key_count"] = len(parsed)
        wrapper = parsed.get("vulnerable_functions") or parsed.get("functions")
        if len(parsed) == 1 and isinstance(wrapper, dict):
            out["wrapped_keys"] = [label(k) for k in list(wrapper)[:MAX_IDS]]
    elif isinstance(parsed, list):
        out["list_len"] = len(parsed)
    return out


class CallEvidence:
    """Bounded recorder. One per ModelEndpointSession."""

    def __init__(self):
        self.entries = []
        self.dropped_calls = 0
        self._text_used = 0
        self._lock = threading.Lock()
        # Optional callable(text, scan_complete) -> dict describing which of the
        # run's verified bound sources appear in the scanned request text.
        # Observation only; any error is swallowed at the call site below.
        self.bound_source_probe = None

    def _text(self, text, head, tail):
        b = bounded_text(text, head, tail)
        size = len(b["text"] or "")
        if self._text_used + size > TOTAL_TEXT_BUDGET:
            return {"text": None, "original_chars": b["original_chars"],
                    "omitted_chars": b["original_chars"],
                    "omission_reason": "total_text_budget_exhausted"}
        self._text_used += size
        return b

    def record_request(self, seq, phase, model, attempt, adapted_messages, family=None,
                       adapted_model=None):
        with self._lock:
            return self._record_request(seq, phase, model, attempt, adapted_messages,
                                        family, adapted_model)

    def _record_request(self, seq, phase, model, attempt, adapted_messages, family, adapted_model):
        if len(self.entries) >= MAX_CALLS:
            self.dropped_calls += 1
            return None
        msgs = adapted_messages if isinstance(adapted_messages, list) else []
        req_feats, full_text, complete = _features(msgs)
        bound = None
        if self.bound_source_probe is not None:
            try:
                bound = self.bound_source_probe(full_text, complete)
            except Exception:
                bound = {"status": "probe_error"}
        last_user = next((m for m in reversed(msgs[-MAX_MESSAGES_SCAN:])
                          if isinstance(m, dict) and m.get("role") == "user"), None)
        content = last_user.get("content") if isinstance(last_user, dict) else None
        entry = {"seq": seq, "phase": label(phase, 40), "model": label(model),
                 "adapted_model": label(adapted_model) if adapted_model is not None else None,
                 "attempt": attempt, "prompt_family": label(family, 40) if family else None,
                 "adapted_messages_sha256_16": (
                     "skipped_oversize_or_unexamined"
                     if (req_feats["unexamined_content"] or len(msgs) > MAX_MESSAGES_SCAN)
                     else bounded_sha16(msgs, req_feats["total_chars"])),
                 "request": req_feats,
                 "bound_sources": bound,
                 "analyzed_bucket": "not_recorded_at_transport",
                 "last_user_message": self._text(content, HEAD_REQUEST, TAIL_REQUEST),
                 "response": None}
        self.entries.append(entry)
        return entry

    def record_response(self, entry, content, finish_reason=None):
        if entry is None:
            return
        feats = response_features(content)
        feats["finish_reason"] = label(finish_reason, 40) if finish_reason is not None else None
        with self._lock:
            feats["text"] = self._text(content, HEAD_RESPONSE, TAIL_RESPONSE)
            entry["response"] = feats

    def snapshot(self):
        with self._lock:
            return self._snapshot()

    def _snapshot(self):
        return {"schema": 1,
                "note": "Private diagnostic. Adapted request captured at the provider "
                        "boundary; text is redacted and size-bounded, cuts are marked "
                        "OMITTED. Not proof of wire bytes.",
                "limits": {"max_calls": MAX_CALLS, "request_head": HEAD_REQUEST,
                           "request_tail": TAIL_REQUEST, "response_head": HEAD_RESPONSE,
                           "response_tail": TAIL_RESPONSE, "total_text_budget": TOTAL_TEXT_BUDGET},
                "dropped_calls": self.dropped_calls,
                "calls": json.loads(json.dumps(self.entries, default=str))}
