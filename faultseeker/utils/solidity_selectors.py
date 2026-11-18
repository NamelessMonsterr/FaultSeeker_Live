"""4-byte function selectors computed from Solidity source, so a call that the trace shows only as a bare selector
(`568d8cd9`) can be matched to the verified source of the function it calls (`performOperations`).

`cast run` prints an unknown selector as is, while the downloaded source is indexed by function NAME. Without this bridge
the source of a selector-named function is never supplied to the analysis, even though the contract is verified and was
downloaded. Standard library only (a small Keccak-256, which is not hashlib's SHA3-256).
"""
import re
from typing import Dict, List, Optional

_MASK = (1 << 64) - 1
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]


def _rol(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _MASK if n else x


def _keccak_f(a: List[int]) -> None:
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a[:] = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROT[x][y])
        a[:] = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data) + b"\x01"
    padded += b"\x00" * (-len(padded) % rate)
    padded[-1] |= 0x80
    state = [0] * 25
    for off in range(0, len(padded), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(padded[off + 8 * i: off + 8 * i + 8], "little")
        _keccak_f(state)
    return b"".join(w.to_bytes(8, "little") for w in state)[:32]


def selector_of(signature: str) -> str:
    """'transfer(address,uint256)' -> 'a9059cbb'"""
    return keccak256(signature.encode()).hex()[:8]


_ELEMENTARY = re.compile(r"^(address|bool|string|bytes|bytes([1-9]|[12][0-9]|3[0-2])|u?int([0-9]+)?|u?fixed([0-9]+x[0-9]+)?)$")
_STORAGE_WORDS = re.compile(r"\b(calldata|memory|storage|payable|indexed)\b")


def _type_declarations(text: str):
    contracts = set(re.findall(r"\b(?:contract|interface|library)\s+([A-Za-z_]\w*)", text))
    enums = set(re.findall(r"\benum\s+([A-Za-z_]\w*)", text))
    return contracts, enums


def _type_options(raw: str, contracts, enums) -> Optional[List[str]]:
    """The possible ABI types of one parameter declaration (a list, because an unknown user-defined type name may be a
    contract/interface -> address or an enum -> uint8; structs are not resolvable here and give None). A guess can never
    produce a false match: callers only accept a signature whose selector equals the one being looked for."""
    raw = _STORAGE_WORDS.sub(" ", raw).strip()
    if not raw:
        return None
    m = re.match(r"^([A-Za-z_][\w.]*)((?:\[[0-9]*\])*)$", raw.split()[0])
    if not m:
        return None
    base, suffix = m.group(1).split(".")[-1], m.group(2)
    if base == "uint":
        base = "uint256"
    elif base == "int":
        base = "int256"
    elif base == "byte":
        base = "bytes1"
    if base in contracts:
        return ["address" + suffix]
    if base in enums:
        return ["uint8" + suffix]
    if _ELEMENTARY.match(base):
        return [base + suffix]
    return ["address" + suffix, "uint8" + suffix]          # unknown user-defined type: contract/interface or enum


def _split_params(params: str) -> Optional[List[str]]:
    out, depth, cur = [], 0, ""
    for ch in params:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if depth != 0:
        return None
    if cur.strip() or out:
        out.append(cur)
    return [p for p in out if p.strip()] if params.strip() else []


MAX_SIGNATURE_CANDIDATES = 16


def signature_candidates(function_source: str, context: str = "") -> List[str]:
    """Canonical signatures (`name(type,type)`) the text of one Solidity function can have: one when every parameter type is
    resolvable, a few when some are unknown user-defined types, none when a parameter is a struct/function type."""
    m = re.search(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", function_source)
    if not m:
        return []
    name, start, depth, i = m.group(1), m.end(), 1, m.end()
    while i < len(function_source) and depth:
        depth += {"(": 1, ")": -1}.get(function_source[i], 0)
        i += 1
    if depth:
        return []
    params = _split_params(re.sub(r"//[^\n]*|/\*.*?\*/", "", function_source[start:i - 1], flags=re.S))
    if params is None:
        return []
    contracts, enums = _type_declarations(context or function_source)
    signatures = [[]]
    for p in params:
        options = _type_options(p, contracts, enums)
        if not options:
            return []
        signatures = [sig + [o] for sig in signatures for o in options][:MAX_SIGNATURE_CANDIDATES]
    return [f"{name}({','.join(sig)})" for sig in signatures]


def selector_from_function_source(function_source: str, context: str = "") -> Optional[str]:
    """The selector when the signature is unambiguous (every parameter type resolvable), else None."""
    sigs = signature_candidates(function_source, context)
    return selector_of(sigs[0]) if len(sigs) == 1 else None


def function_matches_selector(function_source: str, selector: str, context: str = "") -> bool:
    """True when some reading of the function's parameter types hashes to `selector` (cryptographically exact)."""
    target = normalize_selector(selector)
    return any(selector_of(sig) == target for sig in signature_candidates(function_source, context))


def is_bare_selector(token: str) -> bool:
    return bool(re.fullmatch(r"(?:0x)?[0-9a-fA-F]{8}", (token or "").strip()))


def normalize_selector(token: str) -> str:
    return token.strip().lower().removeprefix("0x")
