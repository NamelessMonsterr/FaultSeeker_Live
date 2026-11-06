from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class RankingResult:
    repeated_patterns: List[Dict] = field(default_factory=list)
    address_calls_with_created_contract_in_params: Dict[str, Dict] = field(default_factory=dict)
    functions_to_be_inspected: Dict[str, Dict] = field(default_factory=dict)
    address_list: List[str] = field(default_factory=list)


class FunctionRanker:
    def __init__(self):
        """Initialize the function ranker."""
        # Read-only functions and standard safe state-changing functions to filter out
        # (not typically vulnerable, focus analysis on custom functions)
        self.filtered_functions = [
            # ERC20 read-only
            'totalsupply', 'balanceof', 'allowance', 'decimals', 'name', 'symbol',
            # ERC721 read-only
            'ownerof', 'tokenuri', 'getapproved', 'isapprovedforall',
            # Uniswap/DEX read-only
            'token0', 'token1', 'getreserves', 'getamountout', 'getamountin',
            'getamountsout', 'getamountsin', 'factory', 'pair', 'getpair',
            # Other common read-only
            'paused', 'owner', 'admin', 'ispaused', 'totalshares', 'pricepershare',
            # Standard state-changing (usually safe)
            'transfer', 'transferfrom', 'approve',
            # Common swap variants (routing functions, usually safe)
            'swapexacttokensfortokenssupportingfeeontransfertokens',
            'swapexacttokensfortokens', 'swapexacttokensfornative',
            'swapexacttokensfornativetokens', 'swapnativetokensfortokens',
            'swapnativetokensfortokenswithfeeontransfertokens'
        ]

        # Extended filter for created contract analysis
        # Include additional Aave/protocol-specific safe functions
        self.extended_filtered_functions = self.filtered_functions + [
            # Aave-specific safe functions
            'transferunderlyingto', 'transferfromunderlying',
            'approveunderlying', 'allowanceunderlying',
            # Additional swap variants
            'swapnativetokensfortokenswithfeeontransfertokenssupportingfeeontransfertokens',
            'algebraswapcallback'
        ]

    def rank(self, forensics_result, tx_analysis: dict) -> RankingResult:
        """
        Rank functions for detailed analysis.

        Args:
            forensics_result: ForensicsResult from Stage 1
            tx_analysis: Prepared transaction analysis data

        Returns:
            RankingResult containing ranked functions and patterns
        """
        address_list = []
        functions_to_be_inspected = {}
        address_calls_with_created_contract_in_params = {}
        address_calls_with_created_contract_in_params_memo = {}
        function_call_memo = {}
        repeated_patterns = []

        # Process repeated patterns
        repeated_patterns_memo = set()
        for _, value in tx_analysis['repeated_patterns'].items():
            for pattern in value:
                if (len(pattern['pattern']) > 1) or (pattern['repeats']) > 3:
                    if len(pattern['pattern']) == 1:
                        if pattern['pattern'][0]['call_type'] == 'staticcall':
                            continue

                    # Check if pattern contains only filtered functions
                    check = sum([1 for i in pattern['pattern']
                               if (i['function'] is None) or
                               (i['function'].lower() in self.filtered_functions)])

                    if check == 0:
                        repeated_memo_key = tuple(
                            (i['function'], str(i.get('address') or '').lower())
                            for i in pattern['pattern']
                        )
                        if repeated_memo_key not in repeated_patterns_memo:
                            repeated_patterns_memo.add(repeated_memo_key)
                            repeated_patterns.append(deepcopy(pattern))


        # Process calls with created contracts in params
        for call in forensics_result.address_calls_with_created_contract:
            if call['function'].lower() in self.extended_filtered_functions:
                continue

            key = call['function']
            if key not in address_calls_with_created_contract_in_params:
                address_calls_with_created_contract_in_params[key] = {
                    'count': 0,
                    'calls': [],
                    'address': [],
                }
                address_calls_with_created_contract_in_params_memo[key] = []

            if call['address'] not in address_list:
                address_list.append(call['address'])

            if str(call['depth']) not in address_calls_with_created_contract_in_params_memo[key]:
                address_calls_with_created_contract_in_params_memo[key].append(str(call['depth']))
                address_calls_with_created_contract_in_params[key]['count'] += 1
                address_calls_with_created_contract_in_params[key]['calls'].append({
                    'gas': call['gas'],
                    'address': call['address'],
                    'params': call['params'] if len(call['params']) < 200 else f"{call['params'][:200]}...",
                    'depth': call['depth']
                })
                if call['address'] not in address_calls_with_created_contract_in_params[key]['address']:
                    address_calls_with_created_contract_in_params[key]['address'].append(call['address'])

        # Process functions to be inspected
        for _, value in forensics_result.functions_to_be_inspected.items():
            if value:
                for call in value:
                    if call['function'].lower() in self.extended_filtered_functions:
                        continue

                    key = call['function'] + '_' + call['address']
                    if key not in functions_to_be_inspected:
                        functions_to_be_inspected[key] = {
                            'count': 0,
                            'calls': []
                        }
                        function_call_memo[key] = []

                    if call['address'] not in address_list:
                        address_list.append(call['address'])

                    if str(call['depth']) not in function_call_memo[key]:
                        function_call_memo[key].append(str(call['depth']))
                        functions_to_be_inspected[key]['count'] += 1
                        functions_to_be_inspected[key]['calls'].append({
                            'gas': call['gas'],
                            'params': call['params'] if len(call['params']) < 200 else f"{call['params'][:200]}...",
                            'depth': call['depth']
                        })

        # Fallback: if no functions found, use function_call_loc_memo
        if len(functions_to_be_inspected) == 0:
            for function_call in tx_analysis['function_call_loc_memo']:
                function_call_key = function_call.replace('::', '_')
                function_call_value = {
                    'count': len(tx_analysis['function_call_loc_memo'][function_call]),
                    'calls': [
                        {
                            'gas': call['gas'],
                            'params': call['params'],
                            'depth': call['depth']
                        }
                        for call in tx_analysis['function_call_loc_memo'][function_call]
                    ]
                }
                functions_to_be_inspected[function_call_key] = function_call_value

        # Non-dropping priority hint: present targets at addresses observed in
        # value flow (token balance deltas, attacker/victim candidates) before
        # raw call-count order. Every candidate is retained; only presentation
        # order changes, so budget-limited runs reach the suspicious core first
        # instead of exhausting the budget on high-frequency boilerplate.
        flow_addresses = set()
        balance_change = getattr(forensics_result, 'balance_change', None) or {}
        if isinstance(balance_change, dict):
            flow_addresses.update(str(a).lower() for a in balance_change.keys())
        for addrs in (getattr(forensics_result, 'potential_attacker', None) or [],
                      getattr(forensics_result, 'potential_victim', None) or []):
            flow_addresses.update(str(a).lower() for a in addrs)

        def _priority(item):
            key, value = item
            address = key.rsplit('_', 1)[-1].lower() if '_' in key else ''
            return (0 if address in flow_addresses else 1, -value['count'])

        # Sort functions by value-flow participation, then count (descending)
        functions_to_be_inspected = sorted(
            functions_to_be_inspected.items(),
            key=_priority
        )
        functions_to_be_inspected = {
            k: {'count': v['count'], 'calls': v['calls']}
            for k, v in functions_to_be_inspected
            if v['count'] > 0
        }

        return RankingResult(
            repeated_patterns=repeated_patterns,
            address_calls_with_created_contract_in_params=address_calls_with_created_contract_in_params,
            functions_to_be_inspected=functions_to_be_inspected,
            address_list=address_list
        )

    def get_function_call_depth(self, function_call: str, tx_analysis: dict) -> int:
        """
        Get the maximum call depth for a function.

        Args:
            function_call: Function call identifier (format: "function_address")
            tx_analysis: Transaction analysis data

        Returns:
            Maximum call depth
        """
        temp = function_call.rsplit('_', 1)
        function_name = temp[0].lower()
        address = temp[1].lower()
        key = f"{function_name}::{address}"

        current_depth = 0
        if key in tx_analysis['function_call_loc_memo']:
            for call in tx_analysis['function_call_loc_memo'][key]:
                if len(call['depth']) > current_depth:
                    current_depth = len(call['depth'])

        return current_depth
