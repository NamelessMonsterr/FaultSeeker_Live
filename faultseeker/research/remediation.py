from typing import Dict, List


REMEDIATION_RULES = {
    "reentrancy": [
        "Apply checks-effects-interactions before external calls.",
        "Add OpenZeppelin ReentrancyGuard or an equivalent mutex.",
        "Avoid untrusted callbacks before balance/accounting updates are committed.",
    ],
    "access_control": [
        "Gate privileged functions with explicit role checks.",
        "Add initialization guards for proxy implementations.",
        "Audit delegatecall targets and restrict upgrade authority.",
    ],
    "price": [
        "Use time-weighted or multi-source oracle prices.",
        "Reject stale or single-block manipulated reserves.",
        "Add slippage and liquidity sanity checks around swaps.",
    ],
    "precision": [
        "Use fixed-point math with explicit rounding direction.",
        "Add invariant tests around share-price and exchange-rate calculations.",
    ],
    "flash": [
        "Model same-transaction liquidity effects before accepting state transitions.",
        "Require oracle and reserve checks after flash-loan-sensitive operations.",
    ],
}


def suggest_remediations(vuln_hint: str, signals: Dict) -> List[str]:
    """Return remediation suggestions for a confirmed vulnerability hint.

    Match only on vuln_hint (the caller-supplied vulnerability label), not on
    the signals dict repr. Matching the serialized dict causes false positives:
    e.g. signals={"reentrancy": False} contains the word "reentrancy" as a key
    even though the signal value is explicitly False.
    """
    # Normalize the hint string only; never serialize or match signal dict keys.
    hint_text = str(vuln_hint or "").lower()
    suggestions = []
    for keyword, rules in REMEDIATION_RULES.items():
        if keyword in hint_text:
            suggestions.extend(rules)
    return suggestions or ["Add invariant tests and manually review the highlighted trace path before remediation."]
