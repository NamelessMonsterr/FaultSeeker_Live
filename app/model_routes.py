"""Operator-selected model routes; visitor keys never choose a destination."""
import os
from urllib.parse import urlsplit


ITERA_PREFIX = "itera/"
ITERA_DEFAULT_BASE_URL = "https://api.iteracompute.com/v1"
MERCURY_PREFIX = "mercury-"
MERCURY_DEFAULT_BASE_URL = "https://api.inceptionlabs.ai/v1"
# Mercury 3 reasoning effort: docs describe "medium" as general-purpose use;
# "low" is for latency-sensitive chat. Env-overridable, default medium.
MERCURY_DEFAULT_REASONING_EFFORT = "medium"
# Console alias -> Itera's published model id (the free tier model; verified via GET /v1/models).
ITERA_UPSTREAM_MODELS = {"itera/qwen3.8-27b": "qwen/qwen3.8-27b"}


def adapt_request(model, kwargs):
    """Rewrite a request for the operator-selected Itera route.

    The console model id carries an ``itera/`` alias so it can never share a route
    or credential with the Groq ``qwen/`` models. Itera's free Qwen is a reasoning
    model: without ``reasoning_effort=none`` it spends the whole completion budget
    on reasoning and returns an empty answer. Other models are returned unchanged.
    """
    if str(model).startswith(MERCURY_PREFIX):
        adapted = dict(kwargs)
        extra = dict(adapted.get("extra_body") or {})
        # Mercury spends reasoning tokens before any visible answer; the
        # transport's tiny preflight cap (8) starves a reasoning reply into an
        # empty answer, which the transport correctly treats as invalid. Tiny
        # probes get a small floor and no reasoning instead.
        cap = adapted.get("max_tokens")
        tiny = isinstance(cap, int) and cap < 64
        extra["reasoning_effort"] = ("instant" if tiny else os.getenv(
            "FAULTSEEKER_MERCURY_REASONING_EFFORT", MERCURY_DEFAULT_REASONING_EFFORT))
        adapted["extra_body"] = extra
        if tiny:
            adapted["max_tokens"] = 64
        # Mercury accepts temperature only in [0.5, 1.0]; out-of-range values are
        # silently reset to 1.0 upstream (with a warning), so clamp explicitly.
        temp = adapted.get("temperature")
        if isinstance(temp, (int, float)) and not isinstance(temp, bool):
            adapted["temperature"] = min(1.0, max(0.5, float(temp)))
        return adapted
    if not str(model).startswith(ITERA_PREFIX):
        return kwargs
    adapted = dict(kwargs)
    adapted["model"] = ITERA_UPSTREAM_MODELS.get(str(model), str(model)[len(ITERA_PREFIX):])
    extra = dict(adapted.get("extra_body") or {})
    extra["reasoning_effort"] = "none"
    adapted["extra_body"] = extra
    return adapted


def resolve_route(model, provider_url=None, provider_env="OPENAI_API_KEY"):
    if model.startswith(ITERA_PREFIX):
        # Operator-set endpoint only; visitor input never chooses the destination.
        endpoint = os.getenv("ITERA_BASE_URL") or ITERA_DEFAULT_BASE_URL
        key_env = "ITERA_API_KEY"
        setting = "ITERA_BASE_URL"
    elif model.startswith(MERCURY_PREFIX):
        # Operator-set endpoint only; visitor input never chooses the destination.
        endpoint = os.getenv("INCEPTION_BASE_URL") or MERCURY_DEFAULT_BASE_URL
        key_env = "INCEPTION_API_KEY"
        setting = "INCEPTION_BASE_URL"
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
