"""Structural label-leakage prevention for the FaultSeeker++ evaluation harness.

The legacy harness (``run_research_experiments.py``) computed scores from the
ground-truth ``label`` column, which makes every reported metric a restatement
of the labels rather than a measurement of the system. This module makes that
class of bug *impossible* rather than merely discouraged: scorers receive a
mapping that raises on any attempt to read a label-bearing field.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable, Dict, Iterable, List

# Fields that reveal the ground truth (directly or by proxy) and must never be
# visible to a scorer under evaluation.
FORBIDDEN_FIELDS = frozenset(
    {
        "label",
        "labels",
        "y",
        "y_true",
        "ground_truth",
        "is_exploit",
        "class",
        "vuln_type",
        "pool_status",
        "validation_status",
        "merge_blocker",
        "analysis",
        "source",
        "sources",
        "dasp_classification",
        "swc_registry_classification",
        "uncategorized",
        "benign_category",
        "label_source",
        "matched_non_scam_address",
        "source_incident_id",
        "title",
    }
)


class LeakageError(RuntimeError):
    """Raised when a scorer attempts to read a ground-truth-bearing field."""


class GuardedFeatures(Mapping):
    """Read-only feature mapping that refuses to expose label-bearing fields.

    Any read of a forbidden key raises :class:`LeakageError` instead of
    returning a value, so a leaking scorer fails loudly at evaluation time.
    """

    __slots__ = ("_data", "_accessed")

    def __init__(self, data: Mapping[str, Any]):
        self._data: Dict[str, Any] = {
            k: v for k, v in data.items() if _normalize(k) not in FORBIDDEN_FIELDS
        }
        self._accessed: set = set()

    def __getitem__(self, key: str) -> Any:
        norm = _normalize(key)
        if norm in FORBIDDEN_FIELDS:
            raise LeakageError(
                f"Scorer attempted to read ground-truth field {key!r}. "
                "Scores must be derived from transaction/trace features only."
            )
        self._accessed.add(norm)
        return self._data[key]

    # ``dict.get`` must not silently bypass the guard.
    def get(self, key: str, default: Any = None) -> Any:
        norm = _normalize(key)
        if norm in FORBIDDEN_FIELDS:
            raise LeakageError(
                f"Scorer attempted to read ground-truth field {key!r} via get(). "
                "Scores must be derived from transaction/trace features only."
            )
        self._accessed.add(norm)
        return self._data.get(key, default)

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str) and _normalize(key) in FORBIDDEN_FIELDS:
            raise LeakageError(
                f"Scorer attempted to probe ground-truth field {key!r}."
            )
        return key in self._data

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"GuardedFeatures({sorted(self._data)!r})"

    @property
    def accessed_fields(self) -> List[str]:
        return sorted(self._accessed)


def _normalize(key: str) -> str:
    return str(key).strip().lstrip("\ufeff").strip('"').lower()


def audit_scorer(
    scorer: Callable[[Mapping[str, Any]], float],
    rows: Iterable[Mapping[str, Any]],
    labels: Iterable[int],
) -> Dict[str, Any]:
    """Run ``scorer`` under the guard and report leakage / separability findings.

    Two independent checks:

    1. **Structural** - did the scorer try to read a forbidden field?
    2. **Statistical** - are the score distributions of the two classes
       perfectly disjoint? Perfect separation on real forensic data is
       implausible and is the signature of the legacy label-reading scorers,
       so it is surfaced as a warning rather than silently accepted.
    """
    rows = list(rows)
    labels = [int(x) for x in labels]
    scores: List[float] = []
    leaked = False
    leak_message = ""

    for row in rows:
        guarded = GuardedFeatures(row)
        try:
            scores.append(float(scorer(guarded)))
        except LeakageError as exc:
            leaked = True
            leak_message = str(exc)
            break

    findings: Dict[str, Any] = {
        "leaked": leaked,
        "leak_message": leak_message,
        "scored_rows": len(scores),
    }

    if not leaked and scores and len(set(labels[: len(scores)])) == 2:
        pos = [s for s, y in zip(scores, labels) if y == 1]
        neg = [s for s, y in zip(scores, labels) if y == 0]
        perfectly_separable = bool(pos and neg and min(pos) > max(neg))
        findings["perfectly_separable"] = perfectly_separable
        findings["positive_score_range"] = [min(pos), max(pos)] if pos else []
        findings["negative_score_range"] = [min(neg), max(neg)] if neg else []
        if perfectly_separable:
            findings["warning"] = (
                "Score distributions are perfectly disjoint across classes. "
                "Verify the scorer is not deriving values from labels or from "
                "a feature that is only populated for one class."
            )

    return findings
