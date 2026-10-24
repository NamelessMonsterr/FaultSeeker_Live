"""Operator-selected model routes; visitor keys never choose a destination."""
import os
from urllib.parse import urlsplit


def resolve_route(model, provider_url=None, provider_env="OPENAI_API_KEY"):
    if model.startswith("gpt-6.1-sol-"):
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
