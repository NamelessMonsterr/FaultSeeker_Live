from collections import defaultdict
from typing import Any, Dict, Iterable, List


class TemporalAttackCorrelator:
    """Correlates transaction-level outputs into campaign-level clusters."""

    # Sentinel values used by _campaign_key when identity is absent.
    _UNKNOWN_ATTACKER = "unknown_attacker"
    _UNKNOWN_VICTIM = "unknown_victim"

    def correlate(self, results: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        groups = defaultdict(list)
        for result in results:
            key = self._campaign_key(result)
            groups[key].append(result)

        campaigns = []
        for key, items in groups.items():
            if len(items) < 2:
                continue
            # Campaigns whose key contains only unknown sentinels share no real
            # identity evidence. Label them so callers can distinguish confirmed
            # from unidentified clusters; never discard them silently.
            has_unknown_identity = (
                self._UNKNOWN_ATTACKER in key or self._UNKNOWN_VICTIM in key
            )
            campaigns.append(
                {
                    "campaign_key": key,
                    "transaction_count": len(items),
                    "chains": sorted({str(item.get("chain", "")) for item in items}),
                    "max_priority_score": max(float(item.get("priority_score", 0.0) or 0.0) for item in items),
                    "transaction_hashes": [item.get("transaction_hash") or item.get("txn_hash") for item in items],
                    # True when attacker or victim identity is absent for every item;
                    # these groupings share no verified on-chain identity evidence.
                    "identity_unresolved": has_unknown_identity,
                }
            )
        campaigns.sort(key=lambda item: (item["transaction_count"], item["max_priority_score"]), reverse=True)
        return campaigns

    def _campaign_key(self, result: Dict[str, Any]) -> str:
        attackers = result.get("potential_attacker") or result.get("attack_analysis", {}).get("potential_attackers", [])
        victims = result.get("potential_victim") or result.get("attack_analysis", {}).get("potential_victims", [])
        attacker = str(attackers[0]).lower() if attackers else "unknown_attacker"
        victim = str(victims[0]).lower() if victims else "unknown_victim"
        chain = str(result.get("chain") or result.get("transaction", {}).get("chain") or "unknown")
        return f"{chain}:{attacker}:{victim}"
