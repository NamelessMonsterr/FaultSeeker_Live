"""Normalizes raw pipeline output into the shape the frontend renders, flagging unusable output."""
import json
import re
from typing import Any, Dict, List

from faultseeker.utils.evidence import is_error_sentinel, normalize_evidence
from faultseeker.utils.identity import IdentityError, resolve_identity

from . import settings

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
FUNCTION_KEY_RE = re.compile(r"^\S+_0x[0-9a-fA-F]{40}$")


def _split_key(key: str):
    name, sep, addr = str(key).rpartition("_")
    if sep and ADDRESS_RE.match(addr):
        return name or addr, addr.lower()
    return str(key), ""


def _as_evidence(value) -> List[str]:
    """Readable evidence text for a model-supplied value (see utils.evidence): never a JSON dump of an object."""
    return normalize_evidence(value)[0]


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


def _short_identity(identity) -> str:
    """`function@0x1234567890...` -> `function@0x123456…7890` for a warning line (model-independent, bounded)."""
    name, _, address = str(identity).partition("@")
    name = _shown(name, 40)
    return f"{name}@{address[:8]}…{address[-4:]}" if len(address) > 14 else f"{name}@{_shown(address, 20)}"


def _match_ranked(entry: str, findings: Dict[str, Any], by_name: Dict[str, List[str]]):
    """Resolves one ranking entry to the key of an ACCEPTED finding. Returns (key, why): key is None when it cannot be
    resolved, and why says exactly why. The entry must name exactly one accepted finding: nothing is invented.

    Any spelling with an address (complete key, abbreviated `0x45e1…148b`, `swap@0xaddr`, `swap::0xaddr`, quoted, `Contract.swap_0x…`,
    `swap(address)_0x…`) goes through the shared identity rule: function-name case is preserved, only the address is
    case-insensitive, and ambiguity is rejected. A bare function name (no address; `swap`, `Contract.swap`, `swap(address,uint256)`)
    is accepted only when it identifies ONE accepted finding."""
    try:
        return resolve_identity(entry, list(findings)), ""
    except IdentityError as exc:
        if exc.kind == "ambiguous":
            return None, f"matches {exc.count} analyzed functions"
        if exc.kind in ("unknown", "too_short"):
            return None, "not an analyzed function"
    cleaned = entry.strip().strip("`'\"").strip()
    cleaned = re.sub(r"\s*\([^)]*\)\s*$", "", cleaned)             # swap(address,uint256) -> swap
    if "." in cleaned:
        cleaned = cleaned.rsplit(".", 1)[1]                              # Contract.swap -> swap
    matches = by_name.get(cleaned, [])
    if len(matches) == 1:
        return matches[0], ""
    if len(matches) > 1:
        return None, f"matches {len(matches)} analyzed functions"
    return None, "not an analyzed function"


_COVERAGE_STATUS = ("no_candidates", "complete", "limited")


def _count(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _coverage(raw_cov) -> Any:
    """The coverage block the UI shows, or None when absent/malformed. Lists are reduced to counts."""
    if not isinstance(raw_cov, dict) or raw_cov.get("status") not in _COVERAGE_STATUS:
        return None
    if not isinstance(raw_cov.get("candidates"), int) or isinstance(raw_cov.get("candidates"), bool):
        return None
    omitted = raw_cov.get("omitted")
    failed = raw_cov.get("failed")
    return {"status": raw_cov["status"], "limited": raw_cov.get("limited") is True, "candidates": _count(raw_cov.get("candidates")),
            "selected": _count(raw_cov.get("selected")), "analyzed": _count(raw_cov.get("analyzed")),
            "omitted_count": len(omitted) if isinstance(omitted, list) else 0,
            "failed_count": len(failed) if isinstance(failed, list) else 0,
            "evidence_limited": raw_cov["evidence_limited"] if isinstance(raw_cov.get("evidence_limited"), bool) else None,
            "reduced_count": _count(raw_cov.get("reduced_count")), "source_missing_count": _count(raw_cov.get("source_missing_count")),
            "selection_rejected": _count(raw_cov.get("selection_rejected")),
            "selection_replies_ignored": _count(raw_cov.get("selection_replies_ignored"))}


_EXECUTION = ("completed", "failed", "omitted")
_EVIDENCE = ("complete", "reduced", "source_missing", "reduced_source_missing", "not_analyzed")


def _is_reduction(reason) -> bool:
    return "input budget" in str(reason) or "model input limit" in str(reason)


def _short_addr(address: str) -> str:
    return f"{address[:8]}…{address[-4:]}" if ADDRESS_RE.match(address) else _shown(address, 14)


def _functions(raw_list) -> List[Dict[str, Any]]:
    """Per-function results for the report: execution outcome and evidence adequacy kept apart, reductions as readable counts."""
    out: List[Dict[str, Any]] = []
    if not isinstance(raw_list, list):
        return out
    for item in raw_list[:300]:
        if not isinstance(item, dict) or item.get("execution") not in _EXECUTION or item.get("evidence") not in _EVIDENCE:
            continue
        function, address = item.get("function"), item.get("address")
        if not (isinstance(function, str) and function and isinstance(address, str)):
            continue
        record = {"function": _shown(function, 80), "address": address.lower() if ADDRESS_RE.match(address) else "",
                  "execution": item["execution"], "evidence": item["evidence"], "reductions": []}
        for r in (item.get("reductions") or [])[:12] if isinstance(item.get("reductions"), list) else []:
            if isinstance(r, dict) and isinstance(r.get("section"), str) and isinstance(r.get("step"), str):
                record["reductions"].append({"step": _shown(r["step"], 40), "section": _shown(r["section"], 80),
                                             "tier": _shown(str(r.get("tier", "")), 20), "action": "omitted" if r.get("action") == "omitted" else "shortened",
                                             "original_bytes": _count(r.get("original_bytes")), "kept_bytes": _count(r.get("kept_bytes"))})
        if item["execution"] == "failed" and isinstance(item.get("failure"), str):
            record["failure"] = _shown(item["failure"], 240)
        out.append(record)
    return out


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def normalize(raw: Dict[str, Any], *, model_errors: int = 0) -> Dict[str, Any]:
    warnings: List[str] = []
    potential = raw.get("potentially_vulnerable_functions") or {}
    if not isinstance(potential, dict):
        potential = {}

    # Accept findings: a valid identity and readable evidence. Junk is counted and surfaced, never promoted.
    findings: Dict[str, List[str]] = {}
    canonical: Dict[tuple, str] = {}
    bad_identity = no_evidence = dropped_items = 0
    for key, value in potential.items():
        if not (isinstance(key, str) and FUNCTION_KEY_RE.match(key)):
            bad_identity += 1
            continue
        texts, dropped = normalize_evidence(value)
        dropped_items += dropped
        if not texts:
            no_evidence += 1
            continue
        name, addr = _split_key(key)
        if (name, addr) in canonical:
            findings[canonical[(name, addr)]].extend(texts)
        else:
            canonical[(name, addr)] = key
            findings[key] = list(texts)
    by_name: Dict[str, List[str]] = {}
    for key in findings:
        by_name.setdefault(_split_key(key)[0], []).append(key)

    ranked_keys = _flatten_ranking(raw.get("ranked_suspicious_functions"))
    ranking, used, dropped = [], set(), []
    provider_error_leftovers = 0
    for key in ranked_keys:
        real, why = _match_ranked(key, findings, by_name)
        if not real:
            if not key.strip() or is_error_sentinel(key):
                provider_error_leftovers += 1
            else:
                dropped.append((key, why))
            continue
        if real in used:
            continue
        used.add(real)
        name, addr = _split_key(real)
        ranking.append({"rank": len(ranking) + 1, "function": name, "address": addr, "evidence": findings[real]})

    candidates = []
    for key, ev in findings.items():
        if key in used:
            continue
        name, addr = _split_key(key)
        candidates.append({"function": name, "address": addr, "evidence": ev})

    problem = raw.get("ranking_problem")
    problem = _shown(problem, 200) if isinstance(problem, str) and problem.strip() else ""
    if dropped or provider_error_leftovers:
        total_dropped = len(dropped) + provider_error_leftovers
        shown = "; ".join(f"'{_shown(k)}' ({why})" for k, why in dropped[:3])
        remaining = total_dropped - min(len(dropped), 3)
        more = f"; and {remaining} more" if remaining > 0 else ""
        detail = f": {shown}{more}" if shown else ""
        warnings.append(f"{total_dropped} ranking entr{'y was' if total_dropped == 1 else 'ies were'} "
                        f"not valid function names and were left out{detail}.")
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

    # Findings that were not accepted (identity or evidence), and evidence that could not be shown.
    if bad_identity:
        warnings.append(f"{bad_identity} model finding{_plural(bad_identity, '', 's')} had an identifier that is not "
                        f"<function>_<address> and {_plural(bad_identity, 'was', 'were')} not shown.")
    if no_evidence:
        warnings.append(f"{no_evidence} model finding{_plural(no_evidence, '', 's')} had no usable evidence and "
                        f"{_plural(no_evidence, 'was', 'were')} not shown as {_plural(no_evidence, 'a finding', 'findings')}.")
    if dropped_items:
        warnings.append(f"{dropped_items} evidence item{_plural(dropped_items, '', 's')} could not be shown "
                        "(unsupported structure, empty text or a model error message) and "
                        f"{_plural(dropped_items, 'was', 'were')} left out.")
    rejections = raw.get("verdict_rejections")
    if isinstance(rejections, dict):
        counts = {str(k): v for k, v in rejections.items() if isinstance(v, int) and not isinstance(v, bool) and v > 0}
        total = sum(counts.values())
        if total:
            reasons = "; ".join(f"{_shown(k, 60)}: {v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:4])
            warnings.append(f"{total} model verdict {_plural(total, 'entry was', 'entries were')} rejected ({reasons}) "
                            "and not shown as findings.")

    # Coverage: what was analyzed, and what a missing finding can and cannot mean.
    coverage = _coverage(raw.get("coverage"))
    if not ranking and not candidates:
        if coverage and coverage["status"] == "no_candidates":
            warnings.append("No candidate functions were found in this transaction, so no function was analyzed.")
        elif coverage and coverage["limited"]:
            n = coverage["analyzed"]
            warnings.append(f"No potentially vulnerable functions were identified among the {n} analyzed "
                            f"function{_plural(n, '', 's')}; this is not a clean result because other candidates were not analyzed.")
        elif coverage and coverage["evidence_limited"]:
            warnings.append("No potentially vulnerable functions were identified, but the evidence the model saw was limited "
                            f"(reduced for {coverage['reduced_count']}, source missing for {coverage['source_missing_count']} analyzed "
                            "function(s)); this is not a clean result.")
        else:
            warnings.append("No potentially vulnerable functions were identified for this transaction.")
    if coverage and coverage["limited"]:
        omitted, total_c, failed = coverage["omitted_count"], coverage["candidates"], coverage["failed_count"]
        if omitted:
            why = ("the model narrowed the list to the functions it judged most likely"
                   + (f"; {coverage['selection_rejected']} unknown name(s) in its selection were ignored" if coverage["selection_rejected"] else ""))
            warnings.append(f"{omitted} of {total_c} candidate functions were not analyzed ({why}); their absence from the findings "
                            "is not evidence that they are safe.")
        if failed:
            warnings.append(f"{failed} candidate function{_plural(failed, '', 's')} could not be analyzed; the absence of a finding "
                            f"for {_plural(failed, 'it', 'them')} is not evidence of safety.")

    gaps = raw.get("evidence_gaps")
    if isinstance(gaps, dict) and gaps:
        shortened = [k for k, v in gaps.items() if isinstance(v, list) and any(_is_reduction(x) for x in v)]
        no_source = [k for k, v in gaps.items() if not (isinstance(v, list) and v and all(_is_reduction(x) for x in v))]
        if no_source:
            shown = ", ".join(_short_identity(k) for k in no_source[:3])
            more = f", and {len(no_source) - 3} more" if len(no_source) > 3 else ""
            warnings.append(f"No source code was available for {len(no_source)} analyzed function{'' if len(no_source) == 1 else 's'} "
                            f"({shown}{more}); their verdicts rest on the call trace alone, so \"no finding\" for them is not evidence "
                            "that they are safe.")
        if shortened:
            shown = ", ".join(_short_identity(k) for k in shortened[:3])
            more = f", and {len(shortened) - 3} more" if len(shortened) > 3 else ""
            warnings.append(f"Evidence was reduced to fit the model input budget for {len(shortened)} analyzed function"
                            f"{'' if len(shortened) == 1 else 's'} ({shown}{more}), so the model did not see all of it; "
                            "\"no finding\" for them is not evidence that they are safe.")
    lookups = raw.get("source_lookups")
    if isinstance(lookups, dict) and lookups:
        items = [(a, v) for a, v in lookups.items() if isinstance(a, str) and ADDRESS_RE.match(a) and isinstance(v, dict)
                 and isinstance(v.get("summary"), str)]
        for address, info in items[:3]:
            chain = _shown(str(info.get("chain", "")), 16)
            warnings.append(f"Contract source lookup for {_short_addr(address)}{f' [{chain}]' if chain else ''}: {_shown(info['summary'], 420)}")
        if len(items) > 3:
            warnings.append(f"Source was also unavailable for {len(items) - 3} more contract{_plural(len(items) - 3, '', 's')}.")
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
        "coverage": coverage,
        "functions": _functions(raw.get("function_results")),
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
