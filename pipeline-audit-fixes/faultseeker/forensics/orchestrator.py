import os
from copy import deepcopy
import time
from faultseeker.data_collection.txn_sequencer import TransactionSequencer
from faultseeker.data_collection.txn_info_collector import TransactionInfoCollector
from faultseeker.forensics.trace_analyzer import TraceAnalyzer
from faultseeker.forensics.address_classifier import AddressClassifier
from faultseeker.forensics.result import ForensicsResult
from faultseeker.forensics.signal_extractor import SignalExtractor
from faultseeker.forensics.adaptive_controller import AdaptiveFailureAwareController
from faultseeker.forensics.interaction_graph import TransactionInteractionGraph
from faultseeker.forensics import rule_classifier
from faultseeker.utils.utils import build_agent
from faultseeker.core.llm_router import HybridLLMRouter, build_routed_agent
from faultseeker.research.ablation import AblationConfig
from faultseeker.research.cost_tracker import CostTracker
from faultseeker.research.calibration import (RUNTIME_FEATURE_CONTRACT, CalibrationInputError,
                                              require_runtime_calibrator, runtime_feature_row)
from contextlib import nullcontext
from typing import Optional


class ForensicsOrchestrator:

    def __init__(self,
                 model='gpt-4o-mini',
                 cache_dir='./data/cache/forensics',
                 router: Optional[HybridLLMRouter] = None,
                 ablation: Optional[AblationConfig] = None,
                 cost_tracker: Optional[CostTracker] = None,
                 no_llm: bool = False):
        os.makedirs(cache_dir, exist_ok=True)
        self.cache_dir = cache_dir
        self.model = model
        self.router = router
        self.ablation = ablation or AblationConfig.full_system()
        self.cost_tracker = cost_tracker
        self.no_llm = no_llm
        if no_llm and router is not None:
            raise ValueError('Deterministic mode cannot use a model router')

        # Propagate to the router so --disable-llm-routing and cost accounting
        # apply to the real query path, not just to this object.
        if self.router is not None:
            if ablation is not None:
                self.router.ablation = self.ablation
            if cost_tracker is not None:
                self.router.cost_tracker = cost_tracker

        self.txn_sequencer = TransactionSequencer()
        self.txn_info_collector = TransactionInfoCollector()
        self.adaptive_controller = AdaptiveFailureAwareController(ablation=self.ablation)
        self.address_classifier = None if no_llm else AddressClassifier(model, router=router)
        self.agent = None if no_llm else (build_routed_agent('', router=self.router, agent_role='AddressClassifier', system_prompt='') if router else build_agent('', model))
        
        self.address_inspected = {}
        self.same_function_calls = {}
        self.potential_attacker = []
        self.potential_victim = []
        self.functions_to_be_inspected = {
            'flashloan_callback': [],
            'function_name_with_hash': [],
            'function_name_with_hash_children': [],
            'call_with_created_contract': [],
            'others':[]
        }

    
    def _calibrated_confidence(self, features):
        """Optional calibrated exploit probability (paper section 5.3).

        Runs only when calibration is enabled AND a trained calibrator exists at
        FAULTSEEKER_CALIBRATOR_PATH. Returns None otherwise, so an untrained
        deployment reports no probability rather than a fabricated one.
        """
        self.calibration_status = {'status': 'not_applied', 'reason': 'disabled'}
        if not self.ablation.enabled('calibration'):
            return None
        path = os.environ.get('FAULTSEEKER_CALIBRATOR_PATH', '')
        if not path or not os.path.exists(path):
            self.calibration_status = {'status': 'not_applied', 'reason': 'no_model'}
            return None
        if getattr(self, '_calibrator', None) is None:
            try:
                from faultseeker.research.calibration import LogisticConfidenceCalibrator
                self._calibrator = LogisticConfidenceCalibrator.load(path)
            except Exception as exc:
                print(f'      [!] Calibrator load failed ({exc}); skipping calibration')
                self._calibrator = False
        if not self._calibrator:
            self.calibration_status = {'status': 'not_applied', 'reason': 'invalid_model'}
            return None
        try:
            require_runtime_calibrator(self._calibrator)
            row = runtime_feature_row(features, features)
            probability = self._calibrator.predict_proba(row)
        except Exception as exc:
            reason = exc.reason if isinstance(exc, CalibrationInputError) else 'calibration_failed'
            self.calibration_status = {'status': 'not_applied', 'reason': reason}
            return None
        self.calibration_status = {'status': 'applied'}
        return probability

    def _stage(self, name):
        """Time a pipeline stage when a CostTracker is attached, else no-op."""
        if self.cost_tracker is None:
            return nullcontext()
        return self.cost_tracker.stage(name)

    def _get_function_calls_by_loc(self, loc):
        current_cut = self.trace
        for loc_idx in loc:
            current_cut = current_cut[loc_idx]['children']
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
        if not self.token_filter_result or 'function_calls_to_expand_loc' not in self.token_filter_result:
            return
        for loc in self.token_filter_result['function_calls_to_expand_loc'].get('flashloan_callback', []):
            function_calls = self._get_function_calls_by_loc(loc['depth'])
            self._update_function_calls_to_be_inspected(function_calls,'flashloan_callback',loc['function'])
                
    def check_function_name_with_hash(self):
        if not self.token_filter_result or 'function_calls_to_expand_loc' not in self.token_filter_result:
            return
        for loc in self.token_filter_result['function_calls_to_expand_loc'].get('name_in_hash', []):
            function_calls = self._get_function_calls_by_loc(loc['depth'])
            self._update_function_calls_to_be_inspected(function_calls,'function_name_with_hash_children',loc['function'])
            function_call = deepcopy(self._get_function_calls_by_loc(loc['depth'][:-1])[loc['depth'][-1]])
            del function_call['children']
            self.functions_to_be_inspected['function_name_with_hash'].append(function_call)
            
    def check_call_with_created_contract(self):
        if not self.token_filter_result or 'address_calls_with_created_contract_in_params' not in self.token_filter_result:
            return
        for loc in self.token_filter_result['address_calls_with_created_contract_in_params']:
            function_calls = self._get_function_calls_by_loc(loc['depth'])
            self._update_function_calls_to_be_inspected(function_calls,'call_with_created_contract',loc['function'])
            
    def get_other_functions_to_be_inspected(self):
        if not self.token_filter_result or 'address_to_be_inspected' not in self.token_filter_result:
            return
        if sum([len(v) for v in self.functions_to_be_inspected.values()]) == 0:
            for address in self.token_filter_result['address_to_be_inspected']:
                for function_call in self.token_filter_result['address_to_be_inspected'][address]['function_calls']:
                    for function in self.token_filter_result['address_to_be_inspected'][address]['function_calls'][function_call]:
                        if (function['type'] in ['call', 'delegatecall']) and (function['call_type'] not in ['staticcall']):
                            self.functions_to_be_inspected['others'].append(function)
                    

    
    def run(self, txn_hash: str, chain: str):
        # Initialize state
        self.address_inspected = {}
        self.same_function_calls = {}
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
        print("      [+] Collecting transaction sequence...")
        self.txn_seq = self.txn_sequencer.run(txn_hash, chain)

        print("      [+] Collecting transaction info...")
        self.txn_info = self.txn_info_collector.run(txn_hash, chain)

        if not self.txn_seq:
            print("      [Error] Failed to collect transaction sequence trace! Is RPC node online/archive?")
            return None, None, None
            
        if not self.txn_info:
            print("      [Error] Failed to collect transaction block info! Missing or invalid hash.")
            return None, None, None

        # Analyze execution trace
        print("      [+] Analyzing execution trace...")
        trace_options = {'no_llm': True} if getattr(self, 'no_llm', False) else {}
        self.tx_analysis = TraceAnalyzer(self.txn_seq, self.txn_info, self.model, **trace_options).run()

        if not self.tx_analysis:
            print("      [Error] Failed to analyze execution trace!")
            return None, None, None

        # â”€â”€ Pre-LLM signal extraction + rule classification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        print("      [+] Extracting deterministic signals...")
        with self._stage('stage1_signal_extraction'):
            self.signals = SignalExtractor(
                txn_seq=self.txn_seq,
                tx_analysis=self.tx_analysis,
                txn_hash=txn_hash,
                chain=chain,
            ).run()

        # Ablation: when the transaction interaction graph is disabled, no graph
        # features are produced at all (rather than a score being adjusted).
        if self.ablation.enabled('tig'):
            with self._stage('stage1_interaction_graph'):
                self.graph_reasoning = TransactionInteractionGraph.from_analysis(
                    self.txn_seq,
                    self.tx_analysis,
                    self.txn_info,
                ).metrics()
        else:
            self.graph_reasoning = {'ablated': True, 'component': 'tig'}
        self.signals.raw['graph_reasoning'] = self.graph_reasoning
        self.signals.raw['trace_entropy'] = self._trace_entropy(self.tx_analysis.get('flatten_trace', []))
        measured_depth = self._trace_max_depth(self.tx_analysis.get('canonical_trace') or self.tx_analysis.get('trace'))
        self.signals.raw['call_depth_max'] = measured_depth
        self.signals.raw['call_depth'] = measured_depth
        self.signals.raw['feature_contract'] = RUNTIME_FEATURE_CONTRACT
        storage_available = self.signals.raw.get('reentrancy_context', {}).get('storage_trace_available', False)
        self.signals.raw['state_delta'] = len(self.tx_analysis.get('storage_events') or self.txn_seq.get('storage_events') or []) if storage_available else None
        self.signals.raw['token_flow_anomaly'] = self.graph_reasoning.get('anomaly_score')

        # Calibration (paper section 5.3) is now on the real scoring path.
        calibrated = self._calibrated_confidence({
            'pattern_match': self.signals.raw.get('pattern_match'),
            'code_evidence': self.signals.raw.get('code_evidence'),
            'txn_consistency': self.signals.raw.get('txn_consistency'),
            'llm_confidence': self.signals.raw.get('llm_confidence'),
            'trace_entropy': self.signals.raw.get('trace_entropy', 0.0),
            'call_depth': self.signals.raw.get('call_depth_max', 0),
            'token_flow_anomaly': self.signals.raw.get('token_flow_anomaly', 0.0),
            'state_delta': self.signals.raw.get('state_delta'),
            'feature_contract': RUNTIME_FEATURE_CONTRACT,
        })
        self.signals.raw['calibrated_confidence'] = calibrated
        self.signals.raw['calibration'] = getattr(self, 'calibration_status', {'status': 'not_applied', 'reason': 'unavailable'})
        self.signals.raw['ablation'] = self.ablation.to_dict()

        rule_verdict, rule_conf, matched_rule, vuln_type_hint = rule_classifier.classify(self.signals)
        print(f"      [+] Rule verdict: {rule_classifier.describe(rule_verdict, rule_conf, matched_rule, vuln_type_hint)}")
        self.rule_verdict = rule_verdict
        self.rule_confidence = rule_conf
        self.matched_rule = matched_rule
        self.vuln_type_hint = vuln_type_hint

        if getattr(self, 'no_llm', False):
            if str(self.txn_info.get('transaction_hash') or '').lower() != str(txn_hash).lower():
                raise ValueError('Transaction information does not match the requested hash')
            # Observations only: never enter address/model classification or
            # populate attacker/victim/function findings from unperformed work.
            result = ForensicsResult(
                transaction_hash=txn_hash, chain=chain,
                trace=self.tx_analysis['trace'],
                repeated_patterns=self.tx_analysis.get('repeated_patterns', {}),
                flatten_trace=self.tx_analysis.get('flatten_trace', []),
                function_call_loc_memo=self.tx_analysis.get('function_call_loc_memo', {}),
                rule_verdict=rule_verdict, rule_confidence=rule_conf,
                matched_rule=matched_rule, vuln_type_hint=vuln_type_hint,
                signals=self.signals.raw, duration=time.time() - start)
            return result, self.txn_seq, self.txn_info

        if not self.txn_info.get('transaction_hash'):
            return None, None, None

        self.trace = [self.tx_analysis['trace']]

        # Classify addresses
        print("      [+] Classifying addresses...")
        self.token_filter_result = self.address_classifier.run(txn_hash, chain)

        # Identify vulnerable functions
        print("      [+] Identifying vulnerable functions...")
        self.check_flashloan_fallback_execution()
        self.check_function_name_with_hash()
        self.check_call_with_created_contract()
        self.get_other_functions_to_be_inspected()
        self.adaptive_fallback = self.adaptive_controller.apply(
            self.functions_to_be_inspected,
            self.tx_analysis,
            self.token_filter_result,
        )
        if self.adaptive_fallback.get('activated'):
            print(
                "      [+] Adaptive fallback added "
                f"{self.adaptive_fallback.get('functions_added', 0)} inspection candidates"
            )

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
            adaptive_fallback=self.adaptive_fallback,
            duration=time.time() - start,
            # â”€â”€ Signal layer outputs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            rule_verdict=self.rule_verdict,
            rule_confidence=self.rule_confidence,
            matched_rule=self.matched_rule,
            vuln_type_hint=self.vuln_type_hint,
            signals=self.signals.raw,
        )
        
        if result and self.cache_dir:
            result.save_to_json(os.path.join(self.cache_dir, f"{txn_hash}.json"))

        # Return forensics result along with data needed for Stage 2
        return result, self.txn_seq, self.txn_info

    @staticmethod
    def _trace_max_depth(trace):
        maximum = None
        pending = [(trace, 0, frozenset())]
        while pending:
            node, depth, ancestors = pending.pop()
            if not isinstance(node, (dict, list)) or not node:
                continue
            if id(node) in ancestors:
                raise ValueError('Cyclic trace cannot define call depth')
            lineage = ancestors | {id(node)}
            if isinstance(node, list):
                pending.extend((child, depth, lineage) for child in node)
            else:
                maximum = depth if maximum is None else max(maximum, depth)
                pending.extend((child, depth + 1, lineage) for child in node.get('children', []) or [])
        return maximum

    @staticmethod
    def _trace_entropy(flatten_trace):
        if not flatten_trace:
            return 0.0
        from collections import Counter
        import math

        labels = [
            str(item.get('function') or item.get('call_type') or item.get('type') or 'unknown')
            for item in flatten_trace
            if isinstance(item, dict)
        ]
        if not labels:
            return 0.0
        total = len(labels)
        entropy = 0.0
        for count in Counter(labels).values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        max_entropy = math.log2(total) if total > 1 else 1.0
        return round(entropy / max_entropy, 6) if max_entropy else 0.0
