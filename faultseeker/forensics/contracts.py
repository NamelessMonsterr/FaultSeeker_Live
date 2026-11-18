"""Typed reply contracts for the Stage 1 forensics model calls.

Each contract turns one model reply into a validated value or raises. A provider failure (ProviderFailure) and an unusable
reply (ForensicsModelError) are never converted into an empty victim list or a clean address classification. The agents'
structured-reply budget (query_json) is used exactly once per operation: there is no retry loop around it here.
"""
from typing import Dict, List

from faultseeker.utils.agent import ModelResponseError

ZERO_ADDRESS = "0x" + "0" * 40


class ForensicsModelError(RuntimeError):
    """A Stage 1 model reply stayed unusable after the agent's own structured-reply attempts.

    The message names the operation and the problem, never the reply itself (nothing the model echoed can leak)."""

    def __init__(self, operation: str, problem: str):
        super().__init__(f"Stage 1 {operation}: the model reply was unusable ({problem})")
        self.operation = operation


def ask_list(agent, prompt: str, operation: str) -> list:
    """The reply as a JSON/Python-literal LIST. ProviderFailure passes through; anything else unusable is a ForensicsModelError."""
    try:
        reply = agent.query_json(prompt, expect=(list, tuple))
    except ModelResponseError as exc:
        from faultseeker.utils.agent import ProviderFailure
        if isinstance(exc, ProviderFailure):
            raise
        raise ForensicsModelError(operation, str(exc)[:160]) from None
    return list(reply)


def parse_victims(reply: list, balance_change: Dict[str, dict]) -> List[str]:
    """Addresses of the reply that are in the balance-change summary (matched case-insensitively, returned as keyed there),
    excluding the zero address and duplicates. Entries that are not text are ignored; an explicit [] is a valid answer."""
    by_lower = {str(k).lower(): k for k in balance_change}
    out: List[str] = []
    for item in reply:
        if not isinstance(item, str):
            continue
        key = by_lower.get(item.strip().lower())
        if key and key.lower() != ZERO_ADDRESS and key not in out:
            out.append(key)
    return out


def parse_roles(reply: list, operation: str = "address role classification") -> List[str]:
    """The role strings of the reply. A non-empty list without any usable text entry is unusable, not 'no roles'."""
    roles = [item.strip() for item in reply if isinstance(item, str) and item.strip()]
    if reply and not roles:
        raise ForensicsModelError(operation, "the list holds no role text")
    return roles


def is_flagged(roles: List[str]) -> bool:
    """True when the reply says the address is unknown or potentially vulnerable (case-insensitive: 'Vulnerable' counts)."""
    lowered = {r.casefold() for r in roles}
    return "unknown" in lowered or "vulnerable" in lowered
