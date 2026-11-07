"""
Data structures for Stage 1: Transaction-Level Forensics results.

This module defines structured data classes for passing results from
Stage 1 (Forensics) to Stage 2 (Function Analysis).
"""
import json
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class ForensicsResult:

    # Transaction identification
    transaction_hash: str
    chain: str

    # Trace analysis results
    trace: Dict[str, Any] = field(default_factory=dict)
    repeated_patterns: Dict[str, List] = field(default_factory=dict)
    function_calls_to_expand_loc: Dict[str, List] = field(default_factory=dict)
    address_calls_with_created_contract: List[Dict] = field(default_factory=list)
    flatten_trace: List[Dict] = field(default_factory=list)
    function_call_loc_memo: Dict[str, List] = field(default_factory=dict)

    # Address classification results
    address_to_be_inspected: Dict[str, Any] = field(default_factory=dict)
    inspected_address: Dict[str, Any] = field(default_factory=dict)
    same_function_calls: Dict[str, List] = field(default_factory=dict)
    potential_attacker: List[str] = field(default_factory=list)
    potential_victim: List[str] = field(default_factory=list)

    # Fund flow analysis results
    balance_change: Dict[str, Dict] = field(default_factory=dict)
    address_memo: Dict[str, Dict] = field(default_factory=dict)

    # Functions to inspect (main output for Stage 2)
    functions_to_be_inspected: Dict[str, List] = field(default_factory=lambda: {
        'flashloan_callback': [],
        'function_name_with_hash': [],
        'function_name_with_hash_children': [],
        'call_with_created_contract': [],
        'others': []
    })

    # Metadata
    duration: Optional[float] = None
    timestamp: Optional[str] = None

    def get_all_functions_to_inspect(self) -> List[Dict]:
        """
        Get a flat list of all functions to inspect across all categories.

        Returns:
            List of all function dicts that need detailed analysis
        """
        all_functions = []
        for category, functions in self.functions_to_be_inspected.items():
            all_functions.extend(functions)
        return all_functions

    def get_function_count(self) -> int:
        """
        Get total count of functions identified for inspection.

        Returns:
            Total number of functions to inspect
        """
        return len(self.get_all_functions_to_inspect())

    def get_functions_by_priority(self) -> List[Dict]:
        priority_order = [
            'flashloan_callback',
            'function_name_with_hash',
            'call_with_created_contract',
            'function_name_with_hash_children',
            'others'
        ]

        prioritized_functions = []
        for category in priority_order:
            if category in self.functions_to_be_inspected:
                prioritized_functions.extend(self.functions_to_be_inspected[category])

        return prioritized_functions

    def to_dict(self, include_internal: bool = False) -> Dict[str, Any]:
        """
        Convert ForensicsResult to dictionary for serialization.

        Args:
            include_internal: If True, includes large internal data (trace, flatten_trace, etc.)
                            for debugging. If False (default), only includes human-readable summary.

        Returns:
            Dictionary representation organized by category
        """
        result = {
            # ===== Transaction Identification =====
            'transaction': {
                'hash': self.transaction_hash,
                'chain': self.chain,
                'analysis_duration': self.duration,
                'timestamp': self.timestamp
            },

            # ===== Summary Statistics =====
            'summary': {
                'total_functions_to_inspect': self.get_function_count(),
                'repeated_patterns_detected': sum(len(v) for v in self.repeated_patterns.values()),
                'addresses_to_inspect': len(self.address_to_be_inspected),
                'addresses_inspected': len(self.inspected_address),
                'created_contract_calls': len(self.address_calls_with_created_contract),
                'potential_attackers': len(self.potential_attacker),
                'potential_victims': len(self.potential_victim)
            },

            # ===== Attack Analysis =====
            'attack_analysis': {
                'potential_attackers': self.potential_attacker,
                'potential_victims': self.potential_victim,
                'address_labels': self.address_memo,
                'balance_changes': self.balance_change
            },

            # ===== Function Analysis =====
            'function_analysis': {
                'functions_to_inspect': self.functions_to_be_inspected,
                'repeated_patterns': self.repeated_patterns,
                'calls_with_created_contracts': self.address_calls_with_created_contract
            },

            # ===== Address Classification =====
            'address_classification': {
                'addresses_to_inspect': self.address_to_be_inspected,
                'inspected_addresses': self.inspected_address,
                'same_function_calls': self.same_function_calls
            }
        }

        # Include internal data only if requested (for debugging)
        if include_internal:
            result['_internal'] = {
                'trace': self.trace,
                'flatten_trace': self.flatten_trace,
                'function_call_loc_memo': self.function_call_loc_memo,
                'function_calls_to_expand_loc': self.function_calls_to_expand_loc
            }

        return result
        
    def save_to_json(self, filename: str, include_internal: bool = False) -> None:
        """
        Save ForensicsResult to a JSON file.

        Args:
            filename: Path to save JSON file
            include_internal: If True, includes large internal data for debugging
        """
        with open(filename, 'w') as f:
            json.dump(self.to_dict(include_internal=include_internal), f, indent=2)

    def to_summary(self) -> Dict[str, Any]:
        """
        Get a concise summary of forensics results.

        Returns:
            Dictionary with only high-level statistics and key findings
        """
        return {
            'transaction': {
                'hash': self.transaction_hash,
                'chain': self.chain
            },
            'summary': {
                'total_functions_to_inspect': self.get_function_count(),
                'repeated_patterns_detected': sum(len(v) for v in self.repeated_patterns.values()),
                'addresses_to_inspect': len(self.address_to_be_inspected),
                'potential_attackers': len(self.potential_attacker),
                'potential_victims': len(self.potential_victim)
            },
            'key_findings': {
                'potential_attackers': self.potential_attacker,
                'potential_victims': self.potential_victim,
                'top_suspicious_functions': list(self.functions_to_be_inspected.keys())[:5]
            }
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ForensicsResult':
        """
        Create ForensicsResult from flat dictionary (internal use).

        Args:
            data: Dictionary with flat field names matching dataclass attributes

        Returns:
            ForensicsResult instance
        """
        return cls(**data)

    @classmethod
    def from_json_dict(cls, data: Dict[str, Any]) -> 'ForensicsResult':
        """
        Create ForensicsResult from nested JSON dictionary (from to_dict() output).

        Args:
            data: Nested dictionary from to_dict() method

        Returns:
            ForensicsResult instance
        """
        # Extract from nested structure
        txn = data.get('transaction', {})
        attack = data.get('attack_analysis', {})
        func = data.get('function_analysis', {})
        addr = data.get('address_classification', {})
        internal = data.get('_internal', {})

        return cls(
            transaction_hash=txn.get('hash', ''),
            chain=txn.get('chain', ''),
            duration=txn.get('analysis_duration'),
            timestamp=txn.get('timestamp'),

            # Attack analysis
            potential_attacker=attack.get('potential_attackers', []),
            potential_victim=attack.get('potential_victims', []),
            address_memo=attack.get('address_labels', {}),
            balance_change=attack.get('balance_changes', {}),

            # Function analysis
            functions_to_be_inspected=func.get('functions_to_inspect', {}),
            repeated_patterns=func.get('repeated_patterns', {}),
            address_calls_with_created_contract=func.get('calls_with_created_contracts', []),

            # Address classification
            address_to_be_inspected=addr.get('addresses_to_inspect', {}),
            inspected_address=addr.get('inspected_addresses', {}),
            same_function_calls=addr.get('same_function_calls', {}),

            # Internal data (if present)
            trace=internal.get('trace', {}),
            flatten_trace=internal.get('flatten_trace', []),
            function_call_loc_memo=internal.get('function_call_loc_memo', {}),
            function_calls_to_expand_loc=internal.get('function_calls_to_expand_loc', {})
        )

    @classmethod
    def load_from_json(cls, filename: str) -> 'ForensicsResult':
        """
        Load ForensicsResult from a JSON file.

        Args:
            filename: Path to JSON file

        Returns:
            ForensicsResult instance
        """
        with open(filename, 'r') as f:
            data = json.load(f)
        return cls.from_json_dict(data)

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"ForensicsResult(txn={self.transaction_hash[:10]}..., "
            f"chain={self.chain}, "
            f"functions_to_inspect={self.get_function_count()})"
        )
