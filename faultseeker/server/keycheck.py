"""API-key validation against the provider the key belongs to.

Outcomes:
  valid          the provider accepted the key
  invalid        the provider said the key is wrong (HTTP 401)
  unavailable    we could not find out: outage, timeout, rate limit, redirect, 403/404/5xx or any unexpected answer.
                 This is NOT treated as valid.
  not_supported  the provider is configured with key_validation "none"; the key is used unchecked and the first
                 model call will fail fast if it is wrong.

A key is only ever sent to the base URL of its own provider. Redirects are not followed, so a provider cannot bounce
the Authorization header to another host.
"""
from dataclasses import dataclass
from typing import Optional

import httpx

VALID, INVALID, UNAVAILABLE, NOT_SUPPORTED = "valid", "invalid", "unavailable", "not_supported"


@dataclass(frozen=True)
class KeyCheck:
    status: str
    detail: str = ""


async def check_key(provider, base_url: Optional[str], key: str, *, transport: Optional[httpx.AsyncBaseTransport] = None,
                    timeout: float = 8.0) -> KeyCheck:
    if provider.type != "openai_compatible" or provider.key_validation == "none":
        return KeyCheck(NOT_SUPPORTED, "This provider has no key check configured.")
    if not base_url:
        return KeyCheck(UNAVAILABLE, "The provider's base URL is not configured.")
    url = base_url.rstrip("/") + "/models"
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, transport=transport) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {key}"})
    except httpx.TimeoutException:
        return KeyCheck(UNAVAILABLE, f"{provider.label} did not answer in time.")
    except httpx.HTTPError as exc:
        return KeyCheck(UNAVAILABLE, f"Could not reach {provider.label} ({type(exc).__name__}).")
    code = resp.status_code
    if code == 200:
        return KeyCheck(VALID)
    if code == 401:
        return KeyCheck(INVALID, f"{provider.label} rejected this key.")
    if code in (404, 405, 501):
        return KeyCheck(UNAVAILABLE, f"{provider.label} does not offer a key check at /models (HTTP {code}). "
                                     "If that is expected, set key_validation to \"none\" for it in the model registry.")
    if 300 <= code < 400:
        return KeyCheck(UNAVAILABLE, f"{provider.label} redirected the key check (HTTP {code}); not following it.")
    return KeyCheck(UNAVAILABLE, f"{provider.label} answered the key check with HTTP {code}.")
