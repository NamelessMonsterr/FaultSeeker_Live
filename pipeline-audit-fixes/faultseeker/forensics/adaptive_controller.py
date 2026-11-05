from copy import deepcopy
from typing import Any, Dict, Iterable, List

from faultseeker.research.ablation import AblationConfig
from faultseeker.research.failure_aware_localization import FailureAwareExploitGraphLocalizer


class AdaptiveFailureAwareController:
    """
    Deterministic fallback controller for weak Stage 1 localization states.

    The first dependable trigger is an empty functions-to-inspect set. When the
    normal heuristics produce no candidates, this controller expands from the
    trace graph and preserves the activated fallback metadata for evaluation.
    """

    DEFAULT_MAX_CANDIDATES = 25

    def __init__(
        self,
        localizer: FailureAwareExploitGraphLocalizer | None = None,
        ablation: AblationConfig | None = None,
    ):
        self.localizer = localizer or FailureAwareExploitGraphLocalizer()
        self.ablation = ablation or AblationConfig.full_system()

    def apply(
        self,
        functions_to_inspect: Dict[str, List[Dict[str, Any]]],
        tx_analysis: Dict[str, Any],
        token_filter_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        before_count = self._count(functions_to_inspect)

        # Ablation: when FAEGL is disabled the controller is a no-op, so the
        # empty-candidate-set recovery genuinely does not happen.
        if not self.ablation.enabled("faegl"):
            return {
                "activated": False,
                "trigger": "",
                "modes": [],
                "before_count": before_count,
                "after_count": before_count,
                "functions_added": 0,
                "algorithm_decision": {"ablated": True, "component": "faegl"},
            }

        algorithm_decision = self.localizer.decide(functions_to_inspect, tx_analysis, token_filter_result).to_dict()
        decision = {
            "activated": False,
            "trigger": "",
            "modes": [],
            "before_count": before_count,
            "after_count": before_count,
            "functions_added": 0,
            "algorithm_decision": algorithm_decision,
        }
        if before_count > 0:
            return decision

        candidates = self._graph_expansion_candidates(tx_analysis, token_filter_result, algorithm_decision)
        functions_to_inspect.setdefault("others", [])
        functions_to_inspect["others"].extend(candidates)

        after_count = self._count(functions_to_inspect)
        decision.update(
            {
                "activated": after_count > before_count,
                "trigger": "functions_to_inspect_count == 0",
                "modes": algorithm_decision.get("selected_modes") or ["graph_expansion"],
                "after_count": after_count,
                "functions_added": after_count - before_count,
            }
        )
        return decision

    def _graph_expansion_candidates(
        self,
        tx_analysis: Dict[str, Any],
        token_filter_result: Dict[str, Any],
        algorithm_decision: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        address_scores = self._address_scores(token_filter_result)
        nodes = list(self._iter_trace_nodes(tx_analysis.get("trace", {})))
        nodes.extend(tx_analysis.get("flatten_trace", []) or [])

        candidates = []
        seen = set()
        for node in nodes:
            if not isinstance(node, dict):
                continue
            if not self._is_inspectable_call(node):
                continue
            candidate = self._candidate_from_node(node, address_scores)
            depth = candidate.get("depth", 0)
            depth_key = tuple(depth) if isinstance(depth, list) else depth
            key = (
                candidate.get("address", "").lower(),
                candidate.get("function", ""),
                candidate.get("call_type", ""),
                depth_key,
            )
            if key in seen:
                continue
            seen.add(key)
            candidates.append(candidate)

        ranked = self.localizer.rank_candidates(
            candidates,
            algorithm_decision.get("features", {}),
            address_scores,
        )
        return ranked[: self.DEFAULT_MAX_CANDIDATES]

    @staticmethod
    def _count(functions_to_inspect: Dict[str, List[Dict[str, Any]]]) -> int:
        return sum(len(value or []) for value in functions_to_inspect.values())

    @staticmethod
    def _address_scores(token_filter_result: Dict[str, Any]) -> Dict[str, int]:
        if not isinstance(token_filter_result, dict):
            return {}
        inspected = token_filter_result.get("address_to_be_inspected", {}) or {}
        return {str(address).lower(): 2 for address in inspected}

    def _iter_trace_nodes(self, node: Any, depth: int = 0) -> Iterable[Dict[str, Any]]:
        if isinstance(node, list):
            for child in node:
                yield from self._iter_trace_nodes(child, depth)
            return
        if not isinstance(node, dict):
            return

        copy_node = dict(node)
        copy_node.setdefault("depth", depth)
        yield copy_node
        for child in node.get("children", []) or []:
            yield from self._iter_trace_nodes(child, depth + 1)

    @staticmethod
    def _is_inspectable_call(node: Dict[str, Any]) -> bool:
        call_type = str(node.get("call_type") or node.get("type") or "").lower()
        node_type = str(node.get("type") or "").lower()
        function = str(node.get("function") or "").lower()
        if call_type == "staticcall":
            return False
        if function == "approve":
            return False
        return node_type in {"call", "delegatecall"} or call_type in {"call", "delegatecall"}

    @staticmethod
    def _candidate_from_node(node: Dict[str, Any], address_scores: Dict[str, int]) -> Dict[str, Any]:
        candidate = deepcopy(node)
        candidate.pop("children", None)
        address = str(candidate.get("address") or candidate.get("callee") or "").lower()
        call_type = str(candidate.get("call_type") or candidate.get("type") or "").lower()
        priority = address_scores.get(address, 0)
        if call_type == "delegatecall":
            priority += 2
            candidate["proxy_unwrapped"] = True
        if candidate.get("value") not in (None, "", "0", "0x0", 0):
            priority += 1
        candidate["_adaptive_priority"] = priority
        candidate["_adaptive_fallback"] = True
        return candidate
