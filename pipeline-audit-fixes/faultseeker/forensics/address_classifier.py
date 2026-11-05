import json
from copy import deepcopy
from faultseeker.data_collection.txn_sequencer import TransactionSequencer
from faultseeker.data_collection.txn_info_collector import TransactionInfoCollector
from faultseeker.forensics.trace_analyzer import TraceAnalyzer
from faultseeker.forensics.fund_flow_analyzer import FundFlowAnalyzer
from faultseeker.prompts.forensics.address_classification_prompts import AddressClassificationPrompts
from faultseeker.utils.utils import build_agent, get_common_address_lower
from faultseeker.core.llm_router import HybridLLMRouter, build_routed_agent
from typing import Optional


class AddressClassifier:

    def __init__(self,
                 model='gpt-4o-mini',
                 router: Optional[HybridLLMRouter] = None):
        self.model = model
        self.router = router
        self.txn_sequencer = TransactionSequencer()
        self.txn_info_collector = TransactionInfoCollector()
        self.fundflow_analyzer = FundFlowAnalyzer(model=model)
        self.agent = build_routed_agent('', router=self.router, agent_role='AddressClassifier', system_prompt='') if router else build_agent('', model)
        self.prompts = AddressClassificationPrompts()
        self.address_inspected = {}
        self.same_function_calls = {}
        self.potential_attacker = []
        self.potential_victim = []

    def _update_potential_attacker_victim(self):
        for addr in self.fundflow_analysis_result['potential_attacker']:
            if addr not in self.txn_seq['created_address']:
                self.potential_attacker.append(addr)
        self.potential_victim = deepcopy(self.fundflow_analysis_result['potential_victim'])
    
    def _filter_address_based_on_victim_attacker(self):
        self.address_to_be_inspected = {}
        self._update_potential_attacker_victim()
        address_to_be_filteted = deepcopy(self.potential_attacker)
        if len(self.potential_victim) > 3:
            address_to_be_filteted.extend(self.potential_victim)
        address_to_be_filteted.extend(self.txn_seq['created_address'])
        for addr in self.tx_analysis['address_calls']:
            if addr.lower() not in address_to_be_filteted:
                if addr in self.tx_analysis['address_calls']:
                    self.address_to_be_inspected[addr]= {'function_calls': self.tx_analysis['address_calls'][addr]}         
                    if addr in self.fundflow_analysis_result['address_memo']:           
                        self.address_to_be_inspected[addr]['label'] = self.fundflow_analysis_result['address_memo'][addr]['label']
                    else:
                        self.address_to_be_inspected[addr]['label'] = ''
    
    def _find_address_with_same_function_calls(self):
        memo = {}
        for addr in self.address_to_be_inspected:
            key = str(self.address_to_be_inspected[addr])
            if key not in memo:
                memo[key] = []
            memo[key].append(addr)
        for key in memo:
            if len(memo[key]) > 3:
                if key not in self.same_function_calls:
                    self.same_function_calls[key] = []
                self.same_function_calls[key].extend(memo[key])
                for addr in memo[key]:
                    if addr in self.address_to_be_inspected:
                        del self.address_to_be_inspected[addr]
    
    def _identify_role_of_address(self):
        self._find_address_with_same_function_calls()
        common_address = get_common_address_lower(self.txn_seq['chain'])
        for addr in self.address_to_be_inspected:
            if addr in common_address:
                self.address_inspected[addr] = self.address_to_be_inspected[addr]
                self.address_inspected[addr]['role'] = ['common_address']
                continue
            address_call_summary = deepcopy(self.address_to_be_inspected[addr])
            address_call_summary['function_calls'] = list(self.address_to_be_inspected[addr]['function_calls'].keys())
            address_call_summary['address'] = addr
            addr_prompt = self.prompts.identify_role_of_address + 'The address call information is as follows:' + json.dumps(address_call_summary)
            addr_result = self.agent.query(addr_prompt, format='dict')
            if addr_result:
                if 'unknown' not in addr_result:
                    if 'vulnerable' not in addr_result:
                        self.address_inspected[addr] = address_call_summary
                        self.address_inspected[addr]['role'] = addr_result
                self.address_to_be_inspected[addr]['role'] = addr_result

        for addr in self.address_inspected:
            if addr in self.address_to_be_inspected:
                del self.address_to_be_inspected[addr]
    
    def run(self, txn_hash: str, chain: str) -> dict:
        """
        Classify addresses involved in the transaction.

        Args:
            txn_hash: Transaction hash
            chain: Chain identifier (eth, bsc, poly, etc.)

        Returns:
            Dictionary containing address classification results
        """
        # Initialize state
        self.address_inspected = {}
        self.same_function_calls = {}
        self.potential_attacker = []
        self.potential_victim = []
        self.txn_hash = txn_hash

        # Collect data using refactored methods
        self.txn_seq = self.txn_sequencer.run(txn_hash, chain)
        self.txn_info = self.txn_info_collector.run(txn_hash, chain)

        if not (self.txn_seq and self.txn_info):
            return None

        if not self.txn_info.get('transaction_hash'):
            return None

        # Analyze trace and fund flow
        self.tx_analysis = TraceAnalyzer(self.txn_seq, self.txn_info, self.model).run()
        self.fundflow_analysis_result = self.fundflow_analyzer.run(self.txn_info)

        if not self.fundflow_analysis_result:
            return None

        # Classify addresses
        self._filter_address_based_on_victim_attacker()
        self._identify_role_of_address()

        # Build result
        result = {
            'chain': self.txn_seq['chain'],
            'txn_hash': self.txn_hash,
            'potential_victim': self.potential_victim,
            'potential_attacker': self.potential_attacker,
            'inspected_address': self.address_inspected,
            'address_to_be_inspected': self.address_to_be_inspected,
            'same_function_calls': self.same_function_calls,
            'repeated_patterns': self.tx_analysis['repeated_patterns'],
            'function_calls_to_expand_loc': self.tx_analysis['function_calls_to_expand_loc'],
            'address_calls_with_created_contract_in_params': self.tx_analysis['address_calls_with_created_contract_in_params'],
            'balance_change': self.fundflow_analysis_result.get('balance_change', {}),
            'address_memo': self.fundflow_analysis_result.get('address_memo', {})
        }

        return result
