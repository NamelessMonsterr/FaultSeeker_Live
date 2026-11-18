"""One identity rule for model-supplied function identities, shared by the verdict boundary and the report boundary.

An identity is `<function>_<address>`. The function name is case-sensitive (Solidity); only the address is case-insensitive.
A supplied spelling (complete, abbreviated `0x45e1…148b`, quoted, `Contract.`-prefixed, `name(args)`-decorated, `name@0x…`,
`name::0x…`) is reduced to its parts and must then resolve to exactly ONE member of the allowed set. Nothing outside the allowed
set is ever produced, repaired or guessed.
"""
import re
from typing import Iterable, Optional, Tuple

_TAIL = re.compile(r'(?:@|::|_)(0x[0-9a-fA-F]+)(?:(?:…|\.\.\.)([0-9a-fA-F]+))?$')


class IdentityError(ValueError):
    """The text names no allowed identity. kind: 'malformed', 'too_short', 'unknown' or 'ambiguous' (count = number of matches)."""

    def __init__(self, kind: str, count: int = 0):
        super().__init__(kind)
        self.kind, self.count = kind, count


def parse_identity(key: str) -> Optional[Tuple[str, str, str]]:
    """(function name, address digits as typed incl. 0x, suffix digits) or None when `key` carries no address."""
    text = key.strip().strip("`'\"").strip()
    text = re.sub(r'\s*\([^)]*\)\s*(?=(?:@|::|_)0x)', '', text)
    m = _TAIL.search(text)
    if not m or m.start() == 0:
        return None
    name = text[:m.start()].strip()
    if '.' in name:
        name = name.rsplit('.', 1)[1]
    if not name or any(c.isspace() for c in name):
        return None
    return name, m.group(1), m.group(2) or ''


def resolve_identity(key, identifiers: Iterable[str]) -> str:
    """The one member of `identifiers` (each `<function>_<0x…40 hex>`) that `key` names. Raises IdentityError otherwise."""
    if not isinstance(key, str):
        raise IdentityError('malformed')
    parsed = parse_identity(key)
    if not parsed:
        raise IdentityError('malformed')
    name, digits, suffix = parsed
    digits_l, suffix_l = digits.lower(), suffix.lower()
    complete = len(digits) == 42 and not suffix
    if not complete and len(digits) - 2 + len(suffix) < 6:
        raise IdentityError('too_short')
    hits = []
    for identifier in identifiers:
        cand_name, _, cand_addr = identifier.rpartition('_')
        cand_addr = cand_addr.lower()
        if cand_name != name:
            continue
        if (cand_addr == digits_l) if complete else (cand_addr.startswith(digits_l) and cand_addr.endswith(suffix_l)):
            hits.append(identifier)
    hits = list(dict.fromkeys(hits))
    if len(hits) == 1:
        return hits[0]
    raise IdentityError('ambiguous', len(hits)) if hits else IdentityError('unknown')
