import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Sequence


FEATURE_NAMES = [
    "pattern_match",
    "code_evidence",
    "txn_consistency",
    "llm_confidence",
    "trace_entropy",
    "call_depth",
    "state_delta",
    "token_flow_anomaly",
]


# Contract for actual runtime scorer components plus measured trace context.
# call_depth: maximum call-tree edges below a root (root=0), not address count.
# state_delta: number of observed canonical storage-write events, when available.
# token_flow_anomaly: the existing interaction-graph heuristic, not native profit.
# Models trained on trace proxies under these names are NOT compatible.
RUNTIME_FEATURE_CONTRACT = "faultseeker.runtime-components.v1"


class CalibrationInputError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require_runtime_calibrator(model):
    if getattr(model, 'trained', False) is not True:
        raise CalibrationInputError('model_untrained')
    if (getattr(model, 'input_contract', None) != RUNTIME_FEATURE_CONTRACT
            or list(getattr(model, 'feature_names', [])) != FEATURE_NAMES):
        raise CalibrationInputError('feature_contract_unverified')


def runtime_feature_row(components, signals):
    if not isinstance(components, dict) or not isinstance(signals, dict):
        raise CalibrationInputError('features_unavailable')
    if signals.get('feature_contract') != RUNTIME_FEATURE_CONTRACT:
        raise CalibrationInputError('features_unavailable')
    row = {name: components.get(name) if index < 4 else signals.get(name)
           for index, name in enumerate(FEATURE_NAMES)}
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(value) for value in row.values()):
        raise CalibrationInputError('features_unavailable')
    return row


@dataclass
class CalibrationMetrics:
    brier_score: float
    expected_calibration_error: float
    bins: List[Dict[str, float]] = field(default_factory=list)


class LogisticConfidenceCalibrator:
    """Small dependency-free logistic calibrator for exploit probability."""

    def __init__(self, feature_names: Sequence[str] = FEATURE_NAMES, input_contract: str | None = None):
        self.feature_names = list(feature_names)
        self.input_contract = input_contract
        self.weights = [0.0 for _ in self.feature_names]
        self.bias = 0.0
        self.means = [0.0 for _ in self.feature_names]
        self.scales = [1.0 for _ in self.feature_names]
        self.trained = False

    def fit(
        self,
        rows: Iterable[Dict[str, Any]],
        labels: Iterable[int],
        epochs: int = 600,
        learning_rate: float = 0.08,
        l2: float = 0.001,
    ) -> "LogisticConfidenceCalibrator":
        matrix = [self._raw_features(row) for row in rows]
        y = [1 if int(label) else 0 for label in labels]
        if not matrix or len(matrix) != len(y):
            raise ValueError("Calibration training requires equal non-empty rows and labels")

        self._fit_scaler(matrix)
        x = [self._scale(values) for values in matrix]
        self.weights = [0.0 for _ in self.feature_names]
        self.bias = self._logit((sum(y) + 0.5) / (len(y) + 1.0))

        for _ in range(max(1, epochs)):
            grad_w = [0.0 for _ in self.feature_names]
            grad_b = 0.0
            for values, label in zip(x, y):
                pred = self._sigmoid(self.bias + sum(w * v for w, v in zip(self.weights, values)))
                err = pred - label
                grad_b += err
                for idx, value in enumerate(values):
                    grad_w[idx] += err * value

            n = float(len(x))
            self.bias -= learning_rate * grad_b / n
            for idx in range(len(self.weights)):
                grad = grad_w[idx] / n + l2 * self.weights[idx]
                self.weights[idx] -= learning_rate * grad

        self.trained = True
        return self

    def predict_proba(self, row: Dict[str, Any]) -> float:
        self._validate_parameters()
        values = self._scale(self._raw_features(row))
        score = self.bias + sum(w * v for w, v in zip(self.weights, values))
        return self._sigmoid(score)

    def evaluate(self, rows: Iterable[Dict[str, Any]], labels: Iterable[int], bins: int = 10) -> CalibrationMetrics:
        probabilities = [self.predict_proba(row) for row in rows]
        y = [1 if int(label) else 0 for label in labels]
        if not probabilities or len(probabilities) != len(y):
            raise ValueError("Calibration evaluation requires equal non-empty rows and labels")

        brier = sum((p - label) ** 2 for p, label in zip(probabilities, y)) / len(y)
        bin_rows = self.reliability_bins(probabilities, y, bins=bins)
        ece = sum(item["weight"] * abs(item["accuracy"] - item["confidence"]) for item in bin_rows)
        return CalibrationMetrics(
            brier_score=round(brier, 6),
            expected_calibration_error=round(ece, 6),
            bins=bin_rows,
        )

    def reliability_bins(self, probabilities: Sequence[float], labels: Sequence[int], bins: int = 10) -> List[Dict[str, float]]:
        buckets = []
        total = len(probabilities)
        for idx in range(bins):
            low = idx / bins
            high = (idx + 1) / bins
            members = [
                (p, label)
                for p, label in zip(probabilities, labels)
                if low <= p < high or (idx == bins - 1 and p == 1.0)
            ]
            if not members:
                buckets.append({"low": low, "high": high, "count": 0, "weight": 0.0, "confidence": 0.0, "accuracy": 0.0})
                continue
            confidence = sum(p for p, _ in members) / len(members)
            accuracy = sum(label for _, label in members) / len(members)
            buckets.append(
                {
                    "low": round(low, 4),
                    "high": round(high, 4),
                    "count": len(members),
                    "weight": len(members) / total,
                    "confidence": round(confidence, 6),
                    "accuracy": round(accuracy, 6),
                }
            )
        return buckets

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature_names": self.feature_names,
            "weights": self.weights,
            "bias": self.bias,
            "means": self.means,
            "scales": self.scales,
            "trained": self.trained,
            "input_contract": self.input_contract,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogisticConfidenceCalibrator":
        model = cls(data.get("feature_names", FEATURE_NAMES), input_contract=data.get("input_contract"))
        model.weights = [float(v) for v in data.get("weights", model.weights)]
        model.bias = float(data.get("bias", 0.0))
        model.means = [float(v) for v in data.get("means", model.means)]
        model.scales = [float(v) for v in data.get("scales", model.scales)]
        model.trained = data.get("trained", False)
        if type(model.trained) is not bool:
            raise ValueError("Calibration trained state must be boolean")
        model._validate_parameters()
        return model

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "LogisticConfidenceCalibrator":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    def _validate_parameters(self) -> None:
        if self.input_contract is not None and (not isinstance(self.input_contract, str) or not self.input_contract):
            raise ValueError("Calibration input contract must be a nonempty string or null")
        names = self.feature_names
        if (not names or any(not isinstance(name, str) or not name for name in names)
                or len(set(names)) != len(names)):
            raise ValueError("Calibration feature names must be nonempty and unique")
        vectors = (self.weights, self.means, self.scales)
        if any(len(vector) != len(names) for vector in vectors):
            raise ValueError("Calibration vector lengths must match feature names")
        if not math.isfinite(self.bias) or any(not math.isfinite(v) for vector in vectors for v in vector):
            raise ValueError("Calibration parameters must be finite")
        if any(scale <= 0 for scale in self.scales):
            raise ValueError("Calibration scales must be positive")

    def _raw_features(self, row: Dict[str, Any]) -> List[float]:
        values = [float(row.get(name, 0.0) or 0.0) for name in self.feature_names]
        if any(not math.isfinite(value) for value in values):
            raise ValueError("Calibration features must be finite")
        return values

    def _fit_scaler(self, matrix: List[List[float]]) -> None:
        n = len(matrix)
        self.means = [sum(row[idx] for row in matrix) / n for idx in range(len(self.feature_names))]
        self.scales = []
        for idx, mean in enumerate(self.means):
            variance = sum((row[idx] - mean) ** 2 for row in matrix) / n
            self.scales.append(math.sqrt(variance) or 1.0)

    def _scale(self, values: List[float]) -> List[float]:
        return [(value - mean) / scale for value, mean, scale in zip(values, self.means, self.scales)]

    @staticmethod
    def _sigmoid(value: float) -> float:
        if value >= 0:
            z = math.exp(-value)
            return 1.0 / (1.0 + z)
        z = math.exp(value)
        return z / (1.0 + z)

    @staticmethod
    def _logit(probability: float) -> float:
        p = min(1.0 - 1e-9, max(1e-9, probability))
        return math.log(p / (1.0 - p))
