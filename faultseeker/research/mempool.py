from dataclasses import dataclass
from typing import Dict


@dataclass
class MempoolRiskAlert:
    transaction_hash: str
    chain: str
    risk_score: float
    reason: str
    should_alert: bool


class MempoolRiskScorer:
    """Pre-confirmation scoring over lightweight pending transaction metadata."""

    def __init__(self, alert_threshold: float = 0.65):
        self.alert_threshold = alert_threshold

    def score_pending(self, pending_tx: Dict, chain: str = "eth") -> MempoolRiskAlert:
        input_data = str(pending_tx.get("input", "")).lower()
        value = self._value_eth(pending_tx.get("value", 0))
        risk = 0.0
        reasons = []
        if len(input_data) > 2000:
            risk += 0.2
            reasons.append("large calldata")
        if any(selector in input_data for selector in ("flash", "swap", "borrow", "liquidat")):
            risk += 0.25
            reasons.append("high-risk DeFi keyword")
        if value > 10:
            risk += 0.2
            reasons.append("large value movement")
        if not pending_tx.get("to"):
            risk += 0.2
            reasons.append("contract creation")
        risk = min(1.0, risk)
        return MempoolRiskAlert(
            transaction_hash=str(pending_tx.get("hash", "")),
            chain=chain,
            risk_score=round(risk, 4),
            reason=", ".join(reasons) if reasons else "no elevated pre-confirmation signal",
            should_alert=risk >= self.alert_threshold,
        )

    @staticmethod
    def _value_eth(value) -> float:
        try:
            if isinstance(value, str) and value.startswith("0x"):
                return int(value, 16) / 1e18
            return float(value) / 1e18
        except Exception:
            return 0.0
