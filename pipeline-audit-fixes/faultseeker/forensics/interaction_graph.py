from collections import Counter
from itertools import islice
from typing import Any, Dict, Iterable, List

import networkx as nx


class TransactionInteractionGraph:
    """Transaction Interaction Graph with contracts, EOAs, storage slots, and tokens."""

    def __init__(self):
        self.graph = nx.MultiDiGraph()

    @classmethod
    def from_analysis(cls, txn_seq: Dict[str, Any], tx_analysis: Dict[str, Any], txn_info: Dict[str, Any] | None = None):
        tig = cls()
        tig.add_trace(tx_analysis.get("trace", {}))
        tig.add_storage_events(tx_analysis.get("storage_events") or txn_seq.get("storage_events") or [])
        tig.add_token_transfers((txn_info or {}).get("token_transfer", {}))
        return tig

    def add_trace(self, trace: Any) -> None:
        for parent, child in self._trace_edges(trace):
            caller = self._addr(parent, fallback="root")
            callee = self._addr(child, fallback="unknown")
            call_type = str(child.get("call_type") or child.get("type") or "call").lower()
            self.graph.add_node(caller, kind="contract_or_eoa")
            self.graph.add_node(callee, kind="contract_or_eoa")
            self.graph.add_edge(caller, callee, kind=call_type, function=child.get("function", ""), value=child.get("value", 0))

    def add_storage_events(self, events: Iterable[Dict[str, Any]]) -> None:
        for event in events or []:
            address = str(event.get("address") or "").lower()
            slot = str(event.get("slot") or "")
            if not address or not slot:
                continue
            slot_id = f"{address}:slot:{slot}"
            self.graph.add_node(address, kind="contract_or_eoa")
            self.graph.add_node(slot_id, kind="storage_slot")
            self.graph.add_edge(address, slot_id, kind="sstore", depth=event.get("depth", 0))

    def add_token_transfers(self, token_transfer: Dict[str, Any]) -> None:
        for edge in token_transfer.get("edges", []) if isinstance(token_transfer, dict) else []:
            source = str(edge.get("source") or edge.get("from") or "").lower()
            target = str(edge.get("target") or edge.get("to") or "").lower()
            label = str(edge.get("label") or "")
            if not source or not target:
                continue
            token_id = f"token:{label.split()[0] if label else 'unknown'}"
            self.graph.add_node(source, kind="contract_or_eoa")
            self.graph.add_node(target, kind="contract_or_eoa")
            self.graph.add_node(token_id, kind="token")
            self.graph.add_edge(source, target, kind="transfer", token=token_id, label=label)

    def metrics(self) -> Dict[str, Any]:
        kinds = Counter(data.get("kind", "unknown") for _, data in self.graph.nodes(data=True))
        edge_kinds = Counter(data.get("kind", "unknown") for _, _, data in self.graph.edges(data=True))
        simple = nx.DiGraph()
        simple.add_nodes_from(self.graph.nodes)
        simple.add_edges_from((u, v) for u, v in self.graph.edges())
        # Enumerating every simple cycle grows exponentially. Retain enough for
        # the saturated heuristic, and report the count honestly as a lower bound.
        cycle_limit = 1000
        cycles = list(islice(nx.simple_cycles(simple), cycle_limit + 1))
        cycles_truncated = len(cycles) > cycle_limit
        cycles = cycles[:cycle_limit]
        delegate_edges = edge_kinds.get("delegatecall", 0)
        transfer_edges = edge_kinds.get("transfer", 0)
        sstore_edges = edge_kinds.get("sstore", 0)
        anomaly_score = min(1.0, 0.15 * len(cycles) + 0.2 * delegate_edges + 0.1 * transfer_edges + 0.1 * sstore_edges)
        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "node_kinds": dict(kinds),
            "edge_kinds": dict(edge_kinds),
            "cycle_count": len(cycles),
            "cycle_count_truncated": cycles_truncated,
            "cycle_count_kind": "lower_bound" if cycles_truncated else "exact",
            "delegatecall_edges": delegate_edges,
            "transfer_edges": transfer_edges,
            "storage_slot_edges": sstore_edges,
            "anomaly_score": round(anomaly_score, 4),
            "motifs": self.motifs(cycles),
        }

    def motifs(self, cycles: List[List[str]] | None = None) -> List[str]:
        cycles = cycles if cycles is not None else []
        edge_kinds = Counter(data.get("kind", "unknown") for _, _, data in self.graph.edges(data=True))
        motifs = []
        if cycles:
            motifs.append("recursive_cycle")
        if edge_kinds.get("delegatecall", 0):
            motifs.append("proxy_delegatecall")
        if edge_kinds.get("sstore", 0) and edge_kinds.get("transfer", 0):
            motifs.append("state_delta_plus_token_flow")
        if edge_kinds.get("transfer", 0) >= 3:
            motifs.append("token_flow_fanout")
        return motifs

    def _trace_edges(self, trace: Any) -> Iterable[tuple[Dict[str, Any], Dict[str, Any]]]:
        pending = [(trace, None, frozenset())]
        while pending:
            node, parent, ancestors = pending.pop()
            if not isinstance(node, (dict, list)):
                continue
            identity = id(node)
            if identity in ancestors:
                raise ValueError("Cyclic trace object")
            lineage = ancestors | {identity}
            if isinstance(node, list):
                pending.extend((item, parent, lineage) for item in reversed(node))
                continue
            if parent is not None:
                yield parent, node
            pending.extend((child, node, lineage)
                           for child in reversed(node.get("children", []) or [])
                           if isinstance(child, dict))

    @staticmethod
    def _addr(node: Dict[str, Any], fallback: str) -> str:
        return str(node.get("address") or node.get("callee") or node.get("to") or fallback).lower()
