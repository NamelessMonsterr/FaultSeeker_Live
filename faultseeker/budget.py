"""Model/provider-aware input budgeting.

UNITS. The budget is expressed in ESTIMATED TOKENS, never characters. Without a tokenizer dependency a token count cannot be known
exactly, so the estimator is a documented upper bound: tokens(text) = ceil(UTF-8 bytes / bytes_per_token). With the default
bytes_per_token = 1.0 this is a conservative ceiling (a byte-level BPE token covers at least one byte; a tokenizer that falls back to
bytes emits at most one token per byte), so a request judged to fit by this estimate does not exceed the context window because of
the tokenizer. A larger bytes_per_token (an operator calibration, 1.0-8.0) is trusted as configured and is NOT verified.

A request fits when   estimated tokens of every message actually sent (system + retained history + the new user message, each with a
fixed per-message overhead)   +   the reserved output   +   a safety margin   <=   the context window.

WHERE THE LIMITS COME FROM, highest precedence first:
  1. FAULTSEEKER_CONTEXT_TOKENS_<MODEL>, FAULTSEEKER_OUTPUT_RESERVE_TOKENS_<MODEL>, FAULTSEEKER_BYTES_PER_TOKEN_<MODEL>
     (<MODEL> = the registry model id upper-cased, every non-alphanumeric character replaced by "_": gpt-4o-mini -> GPT_4O_MINI)
  2. the model's "limits" block in config/models.json (documented provider values, each with its source URL and check date)
  3. FAULTSEEKER_DEFAULT_CONTEXT_TOKENS (only for models without a registry limits block)
  4. a built-in conservative fallback (openai_compatible 8,192 tokens, ollama 4,096 tokens): an assumption about an UNKNOWN model, not
     a claim about any model. Models whose id comes from the environment (codex-proxy, mercury) have no verifiable limit here.
The output reserve is, highest first: the override, the max_completion_tokens/max_tokens the request actually sends, the model's
documented max output tokens, a built-in fallback (2,048 / 1,024 for ollama).
Invalid values are rejected when the model is resolved; nothing is silently clamped.
"""
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

MIN_CONTEXT_TOKENS = 1024
MAX_CONTEXT_TOKENS = 10_000_000
MIN_USABLE_INPUT_TOKENS = 512
PER_MESSAGE_TOKENS = 16                       # chat framing per message; documented per-message overhead is a few tokens, this is a ceiling
FALLBACK_CONTEXT_TOKENS = {"openai_compatible": 8192, "ollama": 4096}
FALLBACK_OUTPUT_RESERVE = {"openai_compatible": 2048, "ollama": 1024}
LIMIT_KEYS = {"context_tokens", "max_output_tokens", "bytes_per_token", "source", "verified"}
UNIT = "estimated tokens (UTF-8 bytes / bytes_per_token, a conservative upper bound)"


class BudgetConfigError(ValueError):
    """An invalid limits block or override. Names the setting, never echoes secrets."""


class BudgetExceeded(Exception):
    """The REQUIRED content alone does not fit. detail holds sizes only (never the text)."""

    def __init__(self, message: str, **detail):
        super().__init__(message)
        self.detail = detail


def env_key(model_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", model_id or "").upper()


@dataclass(frozen=True)
class InputBudget:
    model_id: str
    context_tokens: int
    output_reserve_tokens: int
    bytes_per_token: float
    margin_tokens: int
    per_message_tokens: int = PER_MESSAGE_TOKENS
    sources: Dict[str, str] = field(default_factory=dict)         # setting -> where its value came from

    @property
    def input_limit_tokens(self) -> int:
        return self.context_tokens - self.output_reserve_tokens - self.margin_tokens

    def tokens(self, text: str) -> int:
        return math.ceil(len(str(text).encode("utf-8", "replace")) / self.bytes_per_token)

    def message_tokens(self, messages: Sequence[Mapping[str, Any]]) -> int:
        return sum(self.tokens(m.get("content") or "") + self.per_message_tokens for m in messages)

    def bytes_for_tokens(self, tokens: int) -> int:
        return max(int(tokens * self.bytes_per_token), 0)

    def describe(self) -> Dict[str, Any]:
        return {"model": self.model_id, "unit": UNIT, "context_tokens": self.context_tokens,
                "output_reserve_tokens": self.output_reserve_tokens, "margin_tokens": self.margin_tokens,
                "input_limit_tokens": self.input_limit_tokens, "bytes_per_token": self.bytes_per_token,
                "sources": dict(self.sources)}


def _integer(raw: Any, name: str, low: int, high: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        raise BudgetConfigError(f"{name} must be a whole number of tokens.")
    try:
        value = int(str(raw).strip(), 10)
    except ValueError:
        raise BudgetConfigError(f"{name} must be a whole number of tokens.") from None
    if not low <= value <= high:
        raise BudgetConfigError(f"{name} must be between {low:,} and {high:,} tokens.")
    return value


def _ratio(raw: Any, name: str) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        raise BudgetConfigError(f"{name} must be a number between 1.0 and 8.0.")
    try:
        value = float(str(raw).strip())
    except ValueError:
        raise BudgetConfigError(f"{name} must be a number between 1.0 and 8.0.") from None
    if not (math.isfinite(value) and 1.0 <= value <= 8.0):
        raise BudgetConfigError(f"{name} must be a number between 1.0 and 8.0.")
    return value


def validate_limits(model_id: str, raw: Any) -> Optional[dict]:
    """The registry 'limits' block of one model, validated (None when the model has none)."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise BudgetConfigError(f"Model '{model_id}': limits must be an object.")
    unknown = set(raw) - LIMIT_KEYS
    if unknown:
        raise BudgetConfigError(f"Model '{model_id}': unsupported limits {sorted(unknown)}; allowed: {sorted(LIMIT_KEYS)}.")
    if "context_tokens" not in raw:
        raise BudgetConfigError(f"Model '{model_id}': limits needs context_tokens.")
    out = {"context_tokens": _integer(raw["context_tokens"], f"Model '{model_id}': limits.context_tokens", MIN_CONTEXT_TOKENS, MAX_CONTEXT_TOKENS)}
    if "max_output_tokens" in raw:
        out["max_output_tokens"] = _integer(raw["max_output_tokens"], f"Model '{model_id}': limits.max_output_tokens", 1, out["context_tokens"] - 1)
    if "bytes_per_token" in raw:
        out["bytes_per_token"] = _ratio(raw["bytes_per_token"], f"Model '{model_id}': limits.bytes_per_token")
    for key in ("source", "verified"):
        if key in raw:
            if not isinstance(raw[key], str):
                raise BudgetConfigError(f"Model '{model_id}': limits.{key} must be text.")
            out[key] = raw[key]
    return out


def resolve_budget(model_id: str, limits: Optional[dict], provider_type: str, extra_params: Mapping[str, Any],
                   environ: Mapping[str, str]) -> InputBudget:
    """The effective budget of one model under the documented precedence. Raises BudgetConfigError on any invalid value."""
    key = env_key(model_id)
    sources: Dict[str, str] = {}

    def env(name: str) -> str:
        return (environ.get(name, "") or "").strip()

    fallback_ctx = FALLBACK_CONTEXT_TOKENS.get(provider_type, 8192)
    override = env(f"FAULTSEEKER_CONTEXT_TOKENS_{key}")
    if override:
        context = _integer(override, f"FAULTSEEKER_CONTEXT_TOKENS_{key}", MIN_CONTEXT_TOKENS, MAX_CONTEXT_TOKENS)
        sources["context_tokens"] = f"env FAULTSEEKER_CONTEXT_TOKENS_{key}"
    elif limits:
        context = limits["context_tokens"]
        sources["context_tokens"] = "registry limits" + (f" ({limits['source']})" if limits.get("source") else "")
    elif env("FAULTSEEKER_DEFAULT_CONTEXT_TOKENS"):
        context = _integer(env("FAULTSEEKER_DEFAULT_CONTEXT_TOKENS"), "FAULTSEEKER_DEFAULT_CONTEXT_TOKENS", MIN_CONTEXT_TOKENS, MAX_CONTEXT_TOKENS)
        sources["context_tokens"] = "env FAULTSEEKER_DEFAULT_CONTEXT_TOKENS (fallback)"
    else:
        context = fallback_ctx
        sources["context_tokens"] = "built-in conservative fallback (unknown model)"

    requested = [extra_params[k] for k in ("max_completion_tokens", "max_tokens") if isinstance(extra_params.get(k), int)
                 and not isinstance(extra_params.get(k), bool)]
    reserve_override = env(f"FAULTSEEKER_OUTPUT_RESERVE_TOKENS_{key}")
    if reserve_override:
        reserve = _integer(reserve_override, f"FAULTSEEKER_OUTPUT_RESERVE_TOKENS_{key}", 1, MAX_CONTEXT_TOKENS)
        sources["output_reserve_tokens"] = f"env FAULTSEEKER_OUTPUT_RESERVE_TOKENS_{key}"
        if requested and reserve < max(requested):
            raise BudgetConfigError(f"FAULTSEEKER_OUTPUT_RESERVE_TOKENS_{key} is below the max_tokens the request sends.")
    elif requested:
        reserve = max(requested)
        sources["output_reserve_tokens"] = "the max_tokens/max_completion_tokens the request sends"
    elif limits and limits.get("max_output_tokens"):
        reserve = limits["max_output_tokens"]
        sources["output_reserve_tokens"] = "registry limits.max_output_tokens"
    else:
        reserve = FALLBACK_OUTPUT_RESERVE.get(provider_type, 2048)
        sources["output_reserve_tokens"] = "built-in conservative fallback"

    ratio_override = env(f"FAULTSEEKER_BYTES_PER_TOKEN_{key}")
    if ratio_override:
        ratio, sources["bytes_per_token"] = _ratio(ratio_override, f"FAULTSEEKER_BYTES_PER_TOKEN_{key}"), f"env FAULTSEEKER_BYTES_PER_TOKEN_{key}"
    elif limits and "bytes_per_token" in limits:
        ratio, sources["bytes_per_token"] = limits["bytes_per_token"], "registry limits"
    else:
        ratio, sources["bytes_per_token"] = 1.0, "default (conservative upper bound)"

    margin = max(256, context // 50)
    if context - reserve - margin < MIN_USABLE_INPUT_TOKENS:
        raise BudgetConfigError(f"Model '{model_id}': a context of {context:,} tokens leaves no usable input after reserving {reserve:,} "
                                f"output tokens and a {margin:,}-token margin. Raise the context or lower the output reserve.")
    return InputBudget(model_id=model_id, context_tokens=context, output_reserve_tokens=reserve, bytes_per_token=ratio,
                       margin_tokens=margin, sources=sources)


# ------------------------------------------------------------------------------------------------ evidence reduction

REQUIRED = "required"
# Reduced in THIS order when a request does not fit: least valuable evidence first. REQUIRED text is never reduced.
REDUCTION_ORDER = ("history", "context", "source", "trace")


@dataclass
class Part:
    label: str
    text: str
    tier: str = REQUIRED          # REQUIRED | one of REDUCTION_ORDER


@dataclass
class Fitted:
    text: str
    reductions: List[Dict[str, Any]]


def _marker(label: str, omitted: int) -> str:
    return f'\n[… {omitted} bytes omitted from "{label}" to fit the model input budget …]\n'


def _shorten(text: str, label: str, keep_total: int):
    """(shortened text, bytes of the original kept). The head (2/3) and the tail (1/3) survive, with a visible marker between."""
    data = text.encode("utf-8", "replace")
    if keep_total >= len(data):
        return text, len(data)
    marker = _marker(label, len(data))
    avail = keep_total - len(marker.encode("utf-8"))
    if avail <= 0:
        return _marker(label, len(data)).strip("\n"), 0
    head_n = avail * 2 // 3
    tail_n = avail - head_n
    head = data[:head_n].decode("utf-8", "ignore")
    tail = data[len(data) - tail_n:].decode("utf-8", "ignore") if tail_n else ""
    kept = len(head.encode("utf-8")) + len(tail.encode("utf-8"))
    return head + _marker(label, len(data) - kept) + tail, kept


def _size(text: str) -> int:
    return len(text.encode("utf-8", "replace"))


def fit_parts(parts: Sequence[Part], room_bytes: int) -> Fitted:
    """Joins `parts` into at most room_bytes UTF-8 bytes. Reduction priority (defined and tested): history, then context, then source,
    then trace; REQUIRED parts (instructions, candidate identity, the task, the closing contract) are never reduced. Within a tier the
    kept share is the same fraction of each part. A reduced part always keeps a visible marker and its head and tail; a part that
    cannot keep anything becomes the marker alone (recorded as omitted). Raises BudgetExceeded when the REQUIRED text alone, or
    everything with all reducible tiers omitted, still exceeds room_bytes."""
    texts = [p.text for p in parts]
    total = sum(_size(t) for t in texts)
    reductions: List[Dict[str, Any]] = []
    marker_floor = _size(_marker("x" * 40, 10 ** 7))
    for tier in REDUCTION_ORDER:
        if total <= room_bytes:
            break
        idx = [i for i, p in enumerate(parts) if p.tier == tier and _size(parts[i].text) > marker_floor + 64]
        if not idx:
            continue
        original = {i: parts[i].text for i in idx}
        base = total - sum(_size(original[i]) for i in idx)

        def build(f: float):
            out = {}
            for i in idx:
                out[i] = _shorten(original[i], parts[i].label, int(_size(original[i]) * f))
            return out

        built = build(0.0)
        if base + sum(_size(t) for t, _ in built.values()) <= room_bytes:        # some reduction short of omission is enough
            low, high = 0.0, 1.0
            for _ in range(28):
                mid = (low + high) / 2
                trial = build(mid)
                if base + sum(_size(t) for t, _ in trial.values()) <= room_bytes:
                    low = mid
                else:
                    high = mid
            built = build(low)
        for i in idx:
            texts[i], kept = built[i]
            reductions.append({"section": parts[i].label, "tier": tier, "original_bytes": _size(original[i]), "kept_bytes": kept,
                               "action": "omitted" if kept == 0 else "shortened"})
        total = base + sum(_size(t) for t, _ in built.values())
    if total > room_bytes:
        required = sum(_size(parts[i].text) for i in range(len(parts)) if parts[i].tier == REQUIRED)
        raise BudgetExceeded("the required content does not fit the input budget", required_bytes=required, room_bytes=room_bytes,
                             total_bytes=total, reductions=reductions)
    return Fitted("".join(texts), reductions)
