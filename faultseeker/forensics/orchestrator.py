import os
from copy import deepcopy
import time
from faultseeker.data_collection.txn_sequencer import TransactionSequencer
from faultseeker.data_collection.txn_info_collector import TransactionInfoCollector
from faultseeker.forensics.trace_analyzer import TraceAnalyzer
from faultseeker.forensics.address_classifier import AddressClassifier
from faultseeker.forensics.result import ForensicsResult
from faultseeker.utils.utils import build_agent


class ForensicsOrchestrator:

    def __init__(self,
                 model='gpt-4o-mini',
                 cache_dir='./data/cache/forensics'):
        os.makedirs(cache_dir, exist_ok=True)
        self.cache_dir = cache_dir
        self.model = model

        self.txn_sequencer = TransactionSequencer()
        self.txn_info_collector = TransactionInfoCollector()
        self.address_classifier = AddressClassifier(model)
        self.agent = build_agent('', model)
        
        self.address_inspected = {}
        self.same_funciton_calls = {}
        self.potential_attacker = []
        self.potential_victim = []
        self.functions_to_be_inspected = {
            'flashloan_callback': [],
            'function_name_with_hash': [],
            'function_name_with_hash_children': [],
            'call_with_created_contract': [],
            'others':[]
        }

    
    def _get_function_calls_by_loc(self, loc):
        current_cut = self.trace
        for l in loc:
            current_cut = current_cut[l]['children']
        return current_cut
    
    def _update_function_calls_to_be_inspected(self, function_calls, keyword, function_name):
        for function_call in function_calls:
            if (function_call['type'] in ['call', 'delegatecall']) and (function_call['call_type'] not in ['staticcall']):
                if function_call['call_type'] == 'delegatecall':
                    if function_call['function'] != function_name:
                            function_call_detail = deepcopy(function_call)
                            del function_call_detail['children']
                            self.functions_to_be_inspected[keyword].append(function_call_detail)                    
                    self._update_function_calls_to_be_inspected(function_call['children'], keyword, function_call['function'])
                else:
                    if function_call['address'].lower() in self.token_filter_result['address_to_be_inspected']:
                        if function_call['function'] not in ['approve']:
                            function_call_detail = deepcopy(function_call)
                            del function_call_detail['children']
                            self.functions_to_be_inspected[keyword].append(function_call_detail)
                    if (len(function_call['children']) == 1) and (function_call['children'][0]['function'] == function_call['function']):
                        function_call_detail = deepcopy(function_call['children'][0])
                        del function_call_detail['children']
                        self.functions_to_be_inspected[keyword].append(function_call_detail)
                        
                        
    def check_flashloan_fallback_execution(self):
        for loc in self.token_filter_result['function_calls_to_expand_loc']['flashloan_callback']:
            function_calls = self._get_function_calls_by_loc(loc['depth'])
            self._update_function_calls_to_be_inspected(function_calls,'flashloan_callback',loc['function'])
                
    def check_function_name_with_hash(self):
        for loc in self.token_filter_result['function_calls_to_expand_loc']['name_in_hash']:
            function_calls = self._get_function_calls_by_loc(loc['depth'])
            self._update_function_calls_to_be_inspected(function_calls,'function_name_with_hash_children',loc['function'])
            function_call = deepcopy(self._get_function_calls_by_loc(loc['depth'][:-1])[loc['depth'][-1]])
            del function_call['children']
            self.functions_to_be_inspected['function_name_with_hash'].append(function_call)
            
    def check_call_with_created_contract(self):
        for loc in self.token_filter_result['address_calls_with_created_contract_in_params']:
            function_calls = self._get_function_calls_by_loc(loc['depth'])
            self._update_function_calls_to_be_inspected(function_calls,'call_with_created_contract',loc['function'])
            
    def get_other_functions_to_be_inspected(self):
        if sum([len(v) for v in self.functions_to_be_inspected.values()]) == 0:
            for address in self.token_filter_result['address_to_be_inspected']:
                for function_call in self.token_filter_result['address_to_be_inspected'][address]['function_calls']:
                    for function in self.token_filter_result['address_to_be_inspected'][address]['function_calls'][function_call]:
                        if (function['type'] in ['call', 'delegatecall']) and (function['call_type'] not in ['staticcall']):
                            self.functions_to_be_inspected['others'].append(function)
                    

    
    def run(self, txn_hash: str, chain: str):
        # Initialize state
        self.address_inspected = {}
        self.same_funciton_calls = {}
        self.potential_attacker = []
        self.potential_victim = []
        self.functions_to_be_inspected = {
            'flashloan_callback': [],
            'function_name_with_hash': [],
            'function_name_with_hash_children': [],
            'call_with_created_contract': [],
            'others': []
        }
        self.txn_hash = txn_hash

        start = time.time()

        # Collect transaction data using refactored methods
        print("      → Collecting transaction sequence...")
        self.txn_seq = self.txn_sequencer.run(txn_hash, chain)

        print("      → Collecting transaction info...")
        self.txn_info = self.txn_info_collector.run(txn_hash, chain)

        if not (self.txn_seq and self.txn_info):
            return None

        # Analyze execution trace
        print("      → Analyzing execution trace...")
        self.tx_analysis = TraceAnalyzer(self.txn_seq, self.txn_info, self.model).run()

        if not self.tx_analysis:
            return None

        if not self.txn_info.get('transaction_hash'):
            return None

        self.trace = [self.tx_analysis['trace']]

        # Classify addresses
        print("      → Classifying addresses...")
        self.token_filter_result = self.address_classifier.run(txn_hash, chain)

        # Identify vulnerable functions
        print("      → Identifying vulnerable functions...")
        self.check_flashloan_fallback_execution()
        self.check_function_name_with_hash()
        self.check_call_with_created_contract()
        self.get_other_functions_to_be_inspected()

        # Create ForensicsResult
        result = ForensicsResult(
            transaction_hash=self.txn_hash,
            chain=self.txn_seq['chain'],
            trace=self.tx_analysis['trace'],
            repeated_patterns=self.tx_analysis.get('repeated_patterns', {}),
            function_calls_to_expand_loc=self.tx_analysis.get('function_calls_to_expand_loc', {}),
            address_calls_with_created_contract=self.tx_analysis.get('address_calls_with_created_contract_in_params', []),
            flatten_trace=self.tx_analysis.get('flatten_trace', []),
            function_call_loc_memo=self.tx_analysis.get('function_call_loc_memo', {}),
            address_to_be_inspected=self.token_filter_result.get('address_to_be_inspected', {}),
            inspected_address=self.token_filter_result.get('inspected_address', {}),
            same_function_calls=self.token_filter_result.get('same_function_calls', {}),
            potential_attacker=self.token_filter_result.get('potential_attacker', []),
            potential_victim=self.token_filter_result.get('potential_victim', []),
            balance_change=self.token_filter_result.get('balance_change', {}),
            address_memo=self.token_filter_result.get('address_memo', {}),
            functions_to_be_inspected=self.functions_to_be_inspected,
            duration=time.time() - start
        )
        
        if result and self.cache_dir:
            result.save_to_json(os.path.join(self.cache_dir, f"{txn_hash}.json"))

        # Return forensics result along with data needed for Stage 2
        return result, self.txn_seq, self.txn_info
