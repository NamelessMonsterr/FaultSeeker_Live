"""Function identity for trace nodes, independent of how `cast` prints them.

`cast run` prints a call either with the raw 4-byte selector (`a9059cbb(…)`) or with a decoded name
(`transfer(0x…, 5)`). Which one you get depends on the Foundry version (1.9.0 decodes well-known selectors by
itself), on its signature cache and on whether an online lookup succeeded. The analyzer's rules key off function
names (flash-loan lists) and off "is this still a bare selector" (the hashed-name check), so that variance used to
change the analysis.

canonicalize() maps both formats onto one identity using a bundled, versioned table of well-known signatures
(known_selectors.json). Selectors that are in the table become their names; selectors that are not stay bare selectors
(the original "unresolved function" behaviour); decoded names pass through. Extra signatures can be added with
FAULTSEEKER_SELECTOR_TABLE (path to a JSON object of {"selector": "signature"}).
"""
import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Tuple

_BUNDLED = Path(__file__).with_name("known_selectors.json")
_SELECTOR = re.compile(r"^(?:0x)?([0-9a-fA-F]{8})$")


@lru_cache(maxsize=8)
def _load(extra_path: Optional[str]) -> Tuple[Dict[str, str], Dict[str, Tuple[str, ...]]]:
    table = json.loads(_BUNDLED.read_text(encoding="utf-8"))
    if extra_path:
        table.update(json.loads(Path(extra_path).read_text(encoding="utf-8")))
    table = {k.lower().removeprefix("0x"): v for k, v in table.items()}
    by_name: Dict[str, list] = {}
    for sel, sig in table.items():
        by_name.setdefault(sig.split("(", 1)[0], []).append(sel)
    return table, {name: tuple(sels) for name, sels in by_name.items()}


def table() -> Dict[str, str]:
    return dict(_load(os.environ.get("FAULTSEEKER_SELECTOR_TABLE") or None)[0])


def canonicalize(token: str) -> Tuple[str, Optional[str]]:
    """Return (function, selector) for the function token printed by cast.

    function is a name when one is known, otherwise the bare selector. selector is the 4-byte selector when it is
    known: always for raw tokens, and for decoded names only when the name maps to exactly one table entry."""
    token = (token or "").strip()
    sigs, by_name = _load(os.environ.get("FAULTSEEKER_SELECTOR_TABLE") or None)
    m = _SELECTOR.match(token)
    if m:
        selector = m.group(1).lower()
        sig = sigs.get(selector)
        return (sig.split("(", 1)[0] if sig else selector), selector
    candidates = by_name.get(token, ())
    return token, (candidates[0] if len(candidates) == 1 else None)
