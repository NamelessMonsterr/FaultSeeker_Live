"""Normalizes raw pipeline output into the shape the frontend renders, flagging unusable output."""
import json
import re
from typing import Any, Dict, List

from . import settings

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
FUNCTION_KEY_RE = re.compile(r"^\S+_0x[0-9a-fA-F]{40}$")


def _split_key(key: str):
    name, sep, addr = str(key).rpartition("_")
    if sep and ADDRESS_RE.match(addr):
        return name or addr, addr.lower()
    return str(key), ""


def _as_evidence(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        out = []
        for v in value:
            out.extend(_as_evidence(v))
        return out
    if isinstance(value, dict):
        return [json.dumps(value, ensure_ascii=False)]
    text = str(value).strip()
    return [text] if text else []


def _flatten_ranking(value) -> List[str]:
    if isinstance(value, str):
        return []  # e.g. "An error occurred." from a failed model call
    if isinstance(value, dict):
        value = list(value.keys())
    if not isinstance(value, (list, tuple)):
        return []
    out = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif isinstance(item, dict):
            name = item.get("function") or item.get("name")
            if name:
                out.append(str(name))
    return out


def _shown(text: str, limit: int = 48) -> str:
    """A model-supplied name made safe and short enough to put in a warning."""
    text = "".join(c for c in str(text) if c.isprintable())[:limit]
    return text


def _match_ranked(entry: str, potential: Dict[str, Any], lower_index: Dict[str, str], by_name: Dict[str, List[str]]):
    """Resolves one ranking entry to the key of an analyzed function. Returns (key, why): key is None when it cannot be
    resolved, and why says exactly why ('unmatched' or 'ambiguous').

    Accepted forms, in order: the full key (`swap_0xaddr`, any case); `swap@0xaddr` / `swap::0xaddr`; a decorated name
    (`Contract.swap`, `swap(address,uint256)`, quoted/backticked); a bare function name that identifies ONE analyzed
    function. A bare name shared by several analyzed functions is never guessed."""
    def full(key):
        return key if key in potential else lower_index.get(key.lower())

    hit = full(entry)
    if hit:
        return hit, ""
    cleaned = entry.strip().strip("`'\"").strip()
    cleaned = re.sub(r"\s*\([^)]*\)\s*$", "", cleaned)             # swap(address,uint256) -> swap
    m = re.match(r"^(.+?)(?:@|::)(0x[0-9a-fA-F]{40})$", cleaned)
    if m:
        hit = full(f"{m.group(1)}_{m.group(2)}")
        if hit:
            return hit, ""
    if "." in cleaned and not ADDRESS_RE.match(cleaned):
        cleaned = cleaned.rsplit(".", 1)[1]                               # Contract.swap -> swap
        hit = full(cleaned)
        if hit:
            return hit, ""
    for exact in (True, False):
        matches = [k for name, keys in by_name.items() if (name == cleaned if exact else name.lower() == cleaned.lower()) for k in keys]
        if len(matches) == 1:
            return matches[0], ""
        if len(matches) > 1:
            return None, f"matches {len(matches)} analyzed functions"
    return None, "not an analyzed function"


def normalize(raw: Dict[str, Any], *, model_errors: int = 0) -> Dict[str, Any]:
    warnings: List[str] = []
    potential = raw.get("potentially_vulnerable_functions") or {}
    if not isinstance(potential, dict):
        potential = {}
    lower_index = {str(k).lower(): k for k in potential}
    by_name: Dict[str, List[str]] = {}
    for key in potential:
        by_name.setdefault(_split_key(key)[0], []).append(key)

    ranked_keys = _flatten_ranking(raw.get("ranked_suspicious_functions"))
    ranking, used, dropped = [], set(), []
    provider_error_leftovers = 0
    for key in ranked_keys:
        real, why = _match_ranked(key, potential, lower_index, by_name)
        if not real and not FUNCTION_KEY_RE.match(key):
            normalized_entry = str(key).strip()
            if (
                not normalized_entry
                or normalized_entry.casefold() == "an error occurred.".casefold()
            ):
                provider_error_leftovers += 1
            else:
                dropped.append((key, why))
            continue
        name, addr = _split_key(real or key)
        if real in used:
            continue
        if real:
            used.add(real)
        ranking.append({"rank": len(ranking) + 1, "function": name, "address": addr,
                        "evidence": _as_evidence(potential.get(real)) if real else []})

    candidates = []
    for key, ev in potential.items():
        if key in used:
            continue
        name, addr = _split_key(key)
        candidates.append({"function": name, "address": addr, "evidence": _as_evidence(ev)})

    problem = raw.get("ranking_problem")
    problem = _shown(problem, 200) if isinstance(problem, str) and problem.strip() else ""
    if dropped or provider_error_leftovers:
        total_dropped = len(dropped) + provider_error_leftovers
        shown = "; ".join(
            f"'{_shown(k)}' ({why})" for k, why in dropped[:3]
        )
        remaining = total_dropped - min(len(dropped), 3)
        more = f"; and {remaining} more" if remaining > 0 else ""
        detail = f": {shown}{more}" if shown else ""
        warnings.append(
            f"{total_dropped} ranking entr"
            f"{'y was' if total_dropped == 1 else 'ies were'} "
            f"not valid function names and were left out{detail}."
        )
    if not ranking and candidates:
        if problem:
            reason = f" Reason: {problem}."
        elif not ranked_keys:
            reason = " Reason: the ranking reply was empty or not a list of function names."
        else:
            reason = f" Reason: none of its {len(ranked_keys)} entries matched an analyzed function."
        warnings.append("The model did not return a usable ranking, so candidates are shown unranked." + reason)
        ranking = [dict(c, rank=i + 1, unranked=True) for i, c in enumerate(candidates)]
        candidates = []
    elif problem:
        warnings.append(f"The ranking request could not be used: {problem}.")
    if not ranking and not candidates:
        warnings.append("No potentially vulnerable functions were identified for this transaction.")
    if model_errors:
        warnings.append(f"{model_errors} model request(s) failed during this run, so the report may be incomplete.")

    debug = raw.get("_debug") or {}
    return {
        "kind": "live",
        "transaction_hash": raw.get("transaction_hash", ""),
        "chain": raw.get("chain", ""),
        "timestamp": raw.get("timestamp", ""),
        "duration": raw.get("duration"),
        "understanding": raw.get("transaction_understanding") if isinstance(raw.get("transaction_understanding"), str) else "",
        "ranking": ranking,
        "candidates": candidates,
        "stats": {"functions_to_inspect": debug.get("functions_to_inspect_count"),
                  "forensics_seconds": debug.get("forensics_duration"),
                  "analysis_seconds": debug.get("analysis_duration")},
        "warnings": warnings,
    }


def reference_capture() -> Dict[str, Any]:
    """A saved capture. Uses captures/capture.json when present; otherwise builds a clearly-labelled
    reference from the benchmark ground truth (the known vulnerable location, not model output)."""
    if settings.CAPTURE_FILE.exists():
        try:
            data = json.loads(settings.CAPTURE_FILE.read_text(encoding="utf-8"))
            data["kind"] = "capture"
            data.setdefault("warnings", [])
            return data
        except (OSError, ValueError):
            pass
    from .presets import ground_truth_by_hash
    entry = ground_truth_by_hash(settings.DEFAULT_CAPTURE_TX)
    if not entry:
        return {}
    ranking = []
    for loc_key, parts in (entry.get("location") or {}).items():
        addr = loc_key.split("#", 1)[0]
        fn = ""
        for p in parts:
            segs = p.split("#")
            if len(segs) >= 3 and not re.match(r"^\d+:\d+$", segs[-1]):
                fn = segs[-1]
        ranking.append({"rank": len(ranking) + 1, "function": fn or "(see location)", "address": addr.lower(),
                        "evidence": [f"Benchmark ground truth: {entry.get('cause', 'unknown cause')}",
                                     f"Annotated location: {loc_key}"]})
    lost = f" Reported loss: {entry['lost']}." if entry.get("lost") else ""
    return {
        "kind": "capture",
        "transaction_hash": entry["tx"], "chain": entry["chain"], "timestamp": entry.get("time", ""),
        "duration": None,
        "understanding": (f"{entry.get('name', 'Exploit')} — cause: {entry.get('cause', 'unknown')}.{lost} "
                          "This is the annotated ground truth from the FaultSeeker benchmark, shown as a "
                          "reference for what a correct report points at. It is not output from a live run."),
        "ranking": ranking, "candidates": [], "stats": {},
        "warnings": ["Reference capture built from the benchmark ground truth. No model was run."],
    }
