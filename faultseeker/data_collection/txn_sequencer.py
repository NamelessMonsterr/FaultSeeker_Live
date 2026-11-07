import json
from faultseeker.data_collection.txn_replayer import TransactionReplayer
from faultseeker.data_collection.trace_parser import TraceParser, TraceNode
from faultseeker.data_collection.trace_visualizer import TraceGraphGenerator, TransactionTraceVisualizer


class TransactionSequencer:
    def __init__(self):
        self.replayer = TransactionReplayer()
        self.parser = TraceParser()
        self.generator = TraceGraphGenerator()
        self.visualizer = TransactionTraceVisualizer()
    
    def analyze_trace(self, trace_text, depth_limit=1000):
        root_node = self.parser.parse(trace_text,depth_limit)
        if root_node:
            self.visualizer.build_graph_from_tree(root_node)
        return root_node.to_dict() if root_node else None
    
    def generate_text_representation(self, root_node):
        return self.generator.generate(root_node)
    
    def visualize_trace(self, figsize=(12, 10)):
        return self.visualizer.draw_graph(figsize=figsize)
    
    def visualize_address_relation(self):
        return self.visualizer.draw_address_relation()
    
    def save_visualization(self, filename="transaction_trace_graph.png"):
        self.visualizer.save_graph(filename)
    
    def display_gas_summary(self):
        self.visualizer.display_gas_summary()
    
    def export_to_json(self, root_node, filename="transaction_trace.json"):
        if isinstance(root_node, TraceNode):
            root_node = root_node.to_dict()
            
        with open(filename, 'w') as f:
            json.dump(root_node, f, indent=2)
    
    def run(self, txn_hash: str, chain: str) -> dict:
        """
        Analyze transaction sequence for given transaction hash and chain.

        Args:
            txn_hash: Transaction hash
            chain: Chain identifier (eth, bsc, poly, etc.)

        Returns:
            Dictionary containing transaction sequence analysis results
        """
        # Get trace from replayer (uses cache internally)
        trace_text = self.replayer.run(txn_hash, chain)
        if not trace_text:
            return {}

        # Analyze trace
        root_node = self.analyze_trace(trace_text)
        if not root_node:
            return {}

        # Build result
        address_relation = self.visualize_address_relation()
        result = {
            "transaction_hash": txn_hash,
            "chain": chain,
            "trace": root_node,
            "address_relation": address_relation,
            "address_calls": self.parser.address_call_memo,
            "created_address": self.parser.created_address,
        }

        return result


