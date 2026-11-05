"""Operator-selected model routes; visitor keys never choose a destination."""
import os
import math
import json
from urllib.parse import urlsplit


ITERA_PREFIX = "itera/"
ITERA_DEFAULT_BASE_URL = "https://api.iteracompute.com/v1"
# Console alias -> Itera's published model id (the free tier model; verified via GET /v1/models).
ITERA_UPSTREAM_MODELS = {"itera/qwen3.8-27b": "qwen/qwen3.8-27b"}
ITERA_MAX_INPUT_BYTES = 98304
INCEPTION_MAX_INPUT_BYTES = 262144  # bounded serialized input, not a token estimate


class ModelInputLimitError(ValueError):
    """A complete request exceeds the configured provider input policy."""


INCEPTION_PREFIX = "inception/"
INCEPTION_DEFAULT_BASE_URL = "https://api.inceptionlabs.ai/v1"
INCEPTION_UPSTREAM_MODELS = {"inception/mercury-3": "mercury-3"}


def model_call_timeout(models=()):
    """Keep operator caps; Itera's documented example allows queue + generation."""
    models = tuple(models)
    default = ("180" if any(str(model).startswith(ITERA_PREFIX) for model in models)
               else "120" if any(str(model).startswith(INCEPTION_PREFIX) for model in models)
               else "60")
    return float(os.getenv("FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS",
                          os.getenv("FAULTSEEKER_LLM_TIMEOUT_SECS", default)))


def model_preflight_timeout(models=()):
    default = "180" if any(str(model).startswith(ITERA_PREFIX) for model in models) else "120"
    return float(os.getenv("FAULTSEEKER_MODEL_PREFLIGHT_SECS", default))


def adapt_request(model, kwargs, *, phase="analysis"):
    """Adapt requests to explicit operator-selected provider contracts.

    The console model id carries an ``itera/`` alias so it can never share a route
    or credential with the Groq ``qwen/`` models. Itera's free Qwen is a reasoning
    model. Use its documented ``reasoning=false`` control for a visible answer;
    reasoning parameters for other providers are not interchangeable. Other models
    are returned unchanged. See https://iteracompute.com/docs.html.
    """
    input_limit = (INCEPTION_MAX_INPUT_BYTES if str(model).startswith(INCEPTION_PREFIX)
                   else ITERA_MAX_INPUT_BYTES if str(model).startswith(ITERA_PREFIX) else None)
    if input_limit is not None and len(json.dumps(kwargs.get("messages", []), ensure_ascii=False).encode("utf-8")) > input_limit:
        raise ModelInputLimitError("Complete model input exceeds the bounded input policy.")
    if str(model).startswith(INCEPTION_PREFIX):
        if model not in INCEPTION_UPSTREAM_MODELS:
            raise ValueError("The selected Inception model is not configured.")
        adapted = dict(kwargs)
        adapted["model"] = INCEPTION_UPSTREAM_MODELS[model]
        # Mercury chat accepts 0.5..1.0; legacy agents request temperature0.
        temperature = adapted.get("temperature", 0)
        if (not isinstance(temperature, (int, float)) or isinstance(temperature, bool)
                or not math.isfinite(temperature) or not 0 <= temperature <= 1):
            raise ValueError("Inception temperature must be between 0 and 1.")
        # Preserve the caller's preference for low variance within this route's
        # supported range. This does not establish the cause of past truncation.
        adapted["temperature"] = max(0.5, temperature)
        if "max_tokens" in adapted and "max_completion_tokens" in adapted:
            raise ValueError("Conflicting Inception output-token limits.")
        # Mercury3 normal budget includes reasoning and visible output.
        # Keep this bounded at the documented normal default; no automatic escalation.
        # https://docs.inceptionlabs.ai/api-reference/chat/create-a-chat-completion
        limit = adapted.pop("max_tokens", adapted.get("max_completion_tokens", 24576))
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 24576:
            raise ValueError("Inception output-token limit must be between 1 and 24576.")
        adapted["max_completion_tokens"] = limit
        effort = adapted.setdefault("reasoning_effort", os.getenv("INCEPTION_REASONING_EFFORT", "instant" if phase == "preflight" else "low"))
        if effort not in ("instant", "low", "medium", "high"):
            raise ValueError("Unsupported Inception reasoning effort.")
        return adapted
    if not str(model).startswith(ITERA_PREFIX):
        return kwargs
    adapted = dict(kwargs)
    adapted["model"] = ITERA_UPSTREAM_MODELS.get(str(model), str(model)[len(ITERA_PREFIX):])
    extra = dict(adapted.get("extra_body") or {})
    adapted.pop("reasoning_effort", None)
    extra.pop("reasoning_effort", None)
    extra["reasoning"] = False
    adapted["extra_body"] = extra
    return adapted


def resolve_route(model, provider_url=None, provider_env="OPENAI_API_KEY"):
    if model.startswith(INCEPTION_PREFIX):
        endpoint = os.getenv("INCEPTION_BASE_URL") or INCEPTION_DEFAULT_BASE_URL
        key_env = "INCEPTION_API_KEY"
        setting = "INCEPTION_BASE_URL"
    elif model.startswith(ITERA_PREFIX):
        # Operator-set endpoint only; visitor input never chooses the destination.
        endpoint = os.getenv("ITERA_BASE_URL") or ITERA_DEFAULT_BASE_URL
        key_env = "ITERA_API_KEY"
        setting = "ITERA_BASE_URL"
    elif model.startswith("gpt-6.1-sol-"):
        endpoint = os.getenv("CODEX_PROXY_BASE_URL") or os.getenv("OPENAI_BASE_URL")
        key_env = "OPENAI_API_KEY"
        setting = "CODEX_PROXY_BASE_URL"
    elif provider_env == "OPENAI_API_KEY" or model.startswith("gpt-"):
        endpoint = os.getenv("OPENAI_DIRECT_BASE_URL")
        key_env = "OPENAI_DIRECT_API_KEY"
        setting = "OPENAI_DIRECT_BASE_URL"
    else:
        override = {"GROQ_API_KEY": "GROQ_BASE_URL", "NARAROUTER_API_KEY": "NARAROUTER_BASE_URL"}.get(provider_env)
        endpoint = (os.getenv(override) if override else None) or provider_url
        key_env = provider_env
        setting = override or "provider endpoint"
    if not endpoint:
        raise ValueError(f"Configure {setting} for the selected model; no alternate endpoint will be used.")
    parsed = urlsplit(str(endpoint))
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("The configured model endpoint must be an HTTP(S) URL without userinfo.")
    return str(endpoint), key_env
