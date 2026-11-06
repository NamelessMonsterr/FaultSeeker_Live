import math
import re
import json
import logging
import networkx as nx
from copy import deepcopy
import time
from faultseeker.data_collection.contract_downloader import ContractDownloader
from faultseeker.function_analysis.function_ranker import RankingResult
from faultseeker.prompts.function_analysis import (
    OrchestrationSessionPrompts,
    TaskCoordinatorPrompts,
    WorkerPrompts,
    VulnerabilityAnalysisPrompts,
    LocalTaskPrompts,
)
from faultseeker.prompts.local_model_prompts import get_worker_prompts, get_vuln_prompts, is_local_model
from faultseeker.utils.utils import build_agent
from faultseeker.core.llm_router import HybridLLMRouter, build_routed_agent
from faultseeker.forensics.result import extract_reentrancy_analysis, compute_priority_breakdown
from faultseeker.research.cost_tracker import CostTracker
from contextlib import nullcontext
from typing import Optional
from faultseeker.function_analysis.retrieval_contract import RetrievalContractMixin, RetrievalContractError


class AnalysisIncompleteError(RuntimeError):
    kind = 'analysis_incomplete'

    def __init__(self, reason):
        self.reason = reason
        super().__init__(f'Analysis incomplete ({reason}).')


class FunctionAnalyzer(RetrievalContractMixin):

    def __init__(self,
                 model='gpt-4o-mini',
                 router: Optional[HybridLLMRouter] = None,
                 cost_tracker: Optional[CostTracker] = None):
        self.txn_analyzer_model = model
        self.router = router
        self.cost_tracker = cost_tracker

        # Prompt selection: always use the LOCAL model name to pick prompt complexity.
        # In hybrid mode, `model` might be 'gemini-2.0-flash' (Stage 2) but agents
        # still run phi3:mini for Tier 1/2 — we must load simplified prompts for those.
        prompt_model = model
        if router and hasattr(router, 'local_model') and router.local_model:
            prompt_model = router.local_model  # e.g. 'phi3:mini'

        self.session_prompts = OrchestrationSessionPrompts()
        self.task_prompts = TaskCoordinatorPrompts()
        self.function_prompts = get_worker_prompts(prompt_model)      # local-aware
        self.vulnerability_prompts = get_vuln_prompts(prompt_model)   # local-aware
        self.local_task_prompts = LocalTaskPrompts()

        # Initialize agents — use routed agent builder when router is provided
        self.reasoning_agent = build_routed_agent(self.session_prompts.function_call_reasoning_init, router=self.router, agent_role='reasoning_agent', system_prompt=self.session_prompts.function_call_reasoning_init) if router else build_agent(self.session_prompts.function_call_reasoning_init, model)
        self.generation_agent = build_routed_agent(self.session_prompts.function_call_task_generation_init, router=self.router, agent_role='generation_agent', system_prompt=self.session_prompts.function_call_task_generation_init) if router else build_agent(self.session_prompts.function_call_task_generation_init, model)
        self.processing_agent = build_routed_agent(self.session_prompts.function_call_info_processing_init, router=self.router, agent_role='processing_agent', system_prompt=self.session_prompts.function_call_info_processing_init) if router else build_agent(self.session_prompts.function_call_info_processing_init, model)
        self.organization_agent = build_routed_agent(self.session_prompts.function_call_organization_init, router=self.router, agent_role='organization_agent', system_prompt=self.session_prompts.function_call_organization_init) if router else build_agent(self.session_prompts.function_call_organization_init, model)
        self.children_call_filtering_agent = build_routed_agent(self.session_prompts.function_call_children_call_filtering_init, router=self.router, agent_role='children_call_filtering', system_prompt=self.session_prompts.function_call_children_call_filtering_init) if router else build_agent(self.session_prompts.function_call_children_call_filtering_init, model)
        self.agent = build_routed_agent("", router=self.router, agent_role='ranking_agent', system_prompt="") if router else build_agent("", model)
        
        self.task_tree = ''
        self.function_call_info_summary = {}
        self.current_task = ''
        self.processing_result = ''
        self.understanding_result = ''
        self.potentially_vulnerable_functions = {}
        self.children_call_memo_single = {}
        self.children_call_memo = {}
        self.repeated_patterns = []

    def _stage(self, name):
        """Time a pipeline stage when a CostTracker is attached, else no-op."""
        if self.cost_tracker is None:
            return nullcontext()
        return self.cost_tracker.stage(name)

        
        
    def _retrieve_chidlren_calls_memo_single(self, function, address):
        if f'{function}_{address}' in self.children_call_memo:
            self.children_call_memo_single = self.children_call_memo[f'{function}_{address}']
    
    def select_high_appearance_count_children_calls(self):
        function_info = {}
        # Filter out read-only functions and standard safe state-changing functions
        filtered_list = [
            # ERC20 read-only functions
            'totalSupply', 'balanceOf', 'allowance', 'decimals', 'name', 'symbol',
            # ERC721 read-only functions
            'ownerOf', 'balanceOf', 'tokenURI', 'getApproved', 'isApprovedForAll',
            # Uniswap/DEX read-only functions
            'token0', 'token1', 'getReserves', 'getAmountOut', 'getAmountIn',
            'getAmountsOut', 'getAmountsIn', 'factory', 'pair', 'getPair',
            # Other common read-only functions
            'paused', 'owner', 'admin', 'isPaused', 'totalShares', 'pricePerShare',
            # Standard state-changing functions (usually safe)
            'transfer', 'transferFrom', 'approve'
        ]
        filtered_list = [func.lower() for func in filtered_list]
        selected_functions = {}
        functions_to_be_included = {}
        for k,v in self.children_call_memo_single.items():
            function_name = k.split('::')[0]
            v_param_lower = str(v['params']).lower()
            for vi in self.txn_seq['created_address']:
                if vi.lower() in v_param_lower:
                    v['note'] = f"created address {vi} in params (this could suggest a risky action for insufficient validation if related to token transfers)"
                    function_info[k] = {'count': v['count'],'note': v['note']}
                    break
            if function_name.lower() not in filtered_list:
                selected_functions[k] = v
                if function_name.lower().startswith('set'):
                    functions_to_be_included[function_name] = v
        self.children_call_memo_single = selected_functions
        for k,v in sorted(self.children_call_memo_single.items(), key=lambda x: x[1]['count'], reverse=True)[:33]:
            if k not in function_info:
                function_info[k] = v['count']
        for k,v in sorted(functions_to_be_included.items(), key=lambda x: x[1]['count'], reverse=True)[:3]:
            if k not in function_info:
                function_info[k] = v['count']
        return function_info
    
    


    def _perform_task(self):
        if 'description' in self.current_task:
            self.current_task['task_description'] = self.current_task['description']
        if 'additional_information' not in self.current_task:
            self.current_task['additional_information'] = ''
        self.current_task['additional_information'] = self._retrieve_additional_info(str(self.current_task['additional_information'])+ self.current_task['task_description'])
        processing_prompt = self.function_prompts.function_call_info_processing.format(
            selected_task = json.dumps(self.current_task)
        )
        self.processing_result = self.processing_agent.query(processing_prompt, format='str')
        logging.info(f"Processing result: {self.processing_result}")

    def _select_task(self):
        task_selection_prompt = self.function_prompts.function_call_task_selection.format(
            task_tree = self.task_tree,
            function_call_info_summary = self.function_call_info_summary,
            current_understanding = self.understanding_result
        )
        self.current_task = self.generation_agent.query(task_selection_prompt)
        count = 0
        while (not isinstance(self.current_task, dict)) and (count < 3):
            self.current_task = self.generation_agent.query('The task is not in standard JSON format. Please reformat the task into a standard JSON format.')
            count += 1
        logging.info(f"Selected task: {self.current_task}")
        return self.current_task   # ← callers use this to detect timeouts (empty = timed out)

            
    def _update_task_tree(self):
        prompt = self.task_prompts.update_task_tree.format(
            task_tree = self.task_tree,
            current_understanding = self.understanding_result,
            task_completed = self.processing_result
        )
        result = self.reasoning_agent.query(prompt, format='str')
        self.task_tree = result
        logging.info(f"Task tree: {self.task_tree}")

    def _update_current_understanding(self, is_init=False):
        understanding_prompt = self.function_prompts.function_call_organization_function_call.format(
            function_call_info_summary=json.dumps(self.function_call_info_summary))
        if not is_init:
            # The processing agent is a separate conversation. Its new evidence
            # must be supplied explicitly; repeating the initial call summary
            # leaves the next selection/adequacy check without that task result.
            understanding_prompt += (
                '\nRevise the prior understanding using the completed task below. '
                'Preserve supported earlier observations, incorporate new results, '
                'and distinguish evidence, hypotheses, contradictions and missing data. '
                'Do not treat an unverified task assertion as established fact.\n'
                + json.dumps({'previous_understanding': self.understanding_result,
                              'completed_task': self.current_task,
                              'task_result': self.processing_result}))
        self.understanding_result = self.organization_agent.query(understanding_prompt, format='str')
        logging.info(f"Current understanding: {self.understanding_result}")

    def _update_potentially_vulnerable_function(self):
        return self._recover_finding_update(self._update_potentially_vulnerable_function_once)

    def _update_potentially_vulnerable_function_once(self):
        prompt = self.vulnerability_prompts.update_potentially_vulnerable_function
        prompt += "Current understanding:" + self.understanding_result
        prompt += "Current task:" + json.dumps(self.current_task)
        prompt += 'Analysis result of current task:' + json.dumps(self.processing_result)
        prompt += 'Prior analysis observations (unverified; independently check evidence before including a finding): ' + str(self.cheatsheet)
        prompt += ' Deterministic context is unverified and may describe legitimate activity; it is not proof of a vulnerability: ' + json.dumps({
            'rule_prediction': getattr(self, 'rule_verdict', 'UNKNOWN'),
            'category_hint': getattr(self, 'vuln_type_hint', ''),
            'observations': getattr(self, 'signals_raw', {}),
        })
        result = self.organization_agent.query(prompt)
        logging.info(f"Vulnerable function: {result}")
        if not isinstance(result, dict):
            raise ValueError("Invalid finding response: expected an object")
        pending = {}
        meta_keys = {"status", "role", "task", "instructions_received", "output_format",
                     "analysis_pending", "none", "notes", "message", "summary", "reasoning", "explanation"}
        for key, value in result.items():
            if isinstance(key, str) and key.lower() in meta_keys:
                continue
            if isinstance(key, str) and '::' in key:
                key = key.replace('::', '_')
            if isinstance(key, str) and '_' not in key and key.startswith('0x') and len(key) == 42:
                # Task prose can mention several functions and even mistake an
                # address prefix for a selector. Only a unique observed binding
                # can supply the missing function identity without guessing.
                memo = getattr(self, 'tx_analysis', {}).get('function_call_loc_memo', {})
                matching = {mk.rsplit('::', 1)[0] for mk in memo
                            if isinstance(mk, str) and '::' in mk
                            and mk.rsplit('::', 1)[1].lower() == key.lower()}
                if len(matching) != 1:
                    raise ValueError('Invalid finding entry: unresolved address-only target')
                key = f"{next(iter(matching)).lower()}_{key.lower()}"
            if isinstance(value, (list, tuple)) and len(value) == 2:
                evidence, confidence = value
            elif isinstance(value, dict) and 'evidence' in value and 'confidence_score' in value:
                evidence, confidence = value['evidence'], value['confidence_score']
            else:
                raise ValueError("Invalid finding entry: missing evidence or confidence")
            if (not isinstance(key, str) or '_' not in key
                    or not isinstance(evidence, str) or not evidence.strip()
                    or isinstance(confidence, bool) or not isinstance(confidence, (int, float))
                    or not math.isfinite(confidence) or not 0 <= confidence <= 1):
                raise ValueError("Invalid finding entry: invalid target, evidence or confidence")
            pending[key] = (evidence, confidence, self._get_function_call_depth(key))
        if result and not pending:
            raise ValueError('Invalid finding response: metadata is not an empty finding set')
        # Reject malformed replies atomically rather than retaining only their
        # valid subset as a normal-looking complete analysis.
        for key, (evidence, confidence_score, depth) in pending.items():
            if key not in self.potentially_vulnerable_functions:
                self.potentially_vulnerable_functions[key] = {
                    'confidence_score': [confidence_score], 'evidence': [evidence], 'depth': depth,
                }
            else:
                self.potentially_vulnerable_functions[key]['confidence_score'].append(confidence_score)
                self.potentially_vulnerable_functions[key]['evidence'].append(evidence)

    def _update_children_call_memo(self, function_call, function_name=''):
        for i in function_call:
            if (i['function'] == function_name) and (i['call_type'] == 'delegatecall'):
                self._update_children_call_memo(i['children'])
            elif i['type'] not in ['return']:
                ii = deepcopy(i)
                del ii['children']
                key = f"{i['function']}::{i['address']}"
                if key not in self.children_call_memo_single:
                    self.children_call_memo_single[key] = {
                        'count': 1,
                        'call_details':ii,
                        'params': [i['params']],
                    }
                else:
                    self.children_call_memo_single[key]['count'] += 1
                    if i['params'] not in self.children_call_memo_single[key]['params']:
                        self.children_call_memo_single[key]['params'].append(i['params'])
                self._update_children_call_memo(i['children'])

    
    def _temp_check(self):
        return False
    
    def _initial_task_tree(self):
        summary = self.function_call_info_summary or {}
        sources = summary.get('function_source_code') or []
        provided = isinstance(sources, list) and any(
            isinstance(source, dict) and any(
                isinstance(source.get(key), str) and source[key].strip()
                for key in ('source_code', 'content')
            ) for source in sources
        )
        source_state = 'provided, binding unverified; check provenance' if provided else 'unavailable; do not infer implementation'
        summary_state = 'provided' if summary else 'unavailable'
        return (f'1. Basic Function Call Info Gathering - [in progress]\n'
                f'   1.1 Call summary - ({summary_state})\n'
                f'   1.2 Address relations - (use supplied evidence; completeness unverified)\n'
                f'   1.3 Function source - ({source_state})\n')

    @staticmethod
    def _execution_context(txn_info):
        info = txn_info if isinstance(txn_info, dict) else {}
        raw_status = info.get('status')
        status = raw_status.strip().lower() if isinstance(raw_status, str) else ''
        outcome = ('success' if status in {'success', 'successful'} else
                   'reverted' if status in {'failed', 'reverted'} else 'unknown')
        source = info.get('_source')
        source = source if isinstance(source, str) and source in {'html_scrape', 'rpc_fallback'} else 'unspecified'
        return {'reported_outcome': outcome, 'source': source,
                'receipt_binding': 'unverified',
                'interpretation': 'Net-zero token balance changes do not establish that a transaction reverted: '
                    'successful transactions can have offsetting transfers. Treat the reported '
                    'status as source-attributed context, not independently verified receipt proof; '
                    'missing receipt data does not establish success or failure.'}

    def _reset_agent_memories(self):
        for name in ('reasoning_agent', 'generation_agent', 'processing_agent', 'organization_agent', 'children_call_filtering_agent'):
            agent = getattr(self, name, None)
            if agent is not None:
                if hasattr(agent, 'reset_memory') and callable(agent.reset_memory):
                    agent.reset_memory()
                elif hasattr(agent, 'memory') and isinstance(agent.memory, list) and agent.memory:
                    agent.memory = [agent.memory[0]]

    def _function_analysis_init(self):
        if self._temp_check():
            return
        self._reset_agent_memories()
        self.function_call_info_summary['transaction_execution'] = self._execution_context(getattr(self, 'txn_info', None))
        self._update_current_understanding(is_init=True)
        prompt = self.function_prompts.function_analysis_init_prompt
        initial_task_tree = self._initial_task_tree()
        prompt = prompt.format(
            task_tree = initial_task_tree,
            current_understanding = self.understanding_result,
            function_call_info_summary = json.dumps(self.function_call_info_summary)
        )
        result = self.reasoning_agent.query(prompt, format='str')
        self.task_tree = result
        logging.info(f"Function call info summary: {json.dumps(self.function_call_info_summary)}")
        logging.info(f"Current understanding: {self.understanding_result}")
        logging.info(f"Task tree: {self.task_tree}")

        # Cloud models need fewer iterations than local; 3 passes is plenty.
        is_cloud = not is_local_model(self.txn_analyzer_model)
        max_iterations = 3 if is_cloud else 8
        MAX_FUNCTION_SECS = 480   # 8-min hard wall-clock cap per function

        import time as _time
        fn_start = _time.time()
        i = 0
        consecutive_timeouts = 0
        while True:
            i += 1
            elapsed = int(_time.time() - fn_start)
            print(f"         [Info] Iteration {i}/{max_iterations}  ({elapsed}s elapsed)", flush=True)
            if _time.time() - fn_start >= MAX_FUNCTION_SECS:
                raise AnalysisIncompleteError('loop_time_limit')
            task = self._select_task()
            if not task or not str(task).strip():
                consecutive_timeouts += 1
                if consecutive_timeouts >= 2:
                    raise AnalysisIncompleteError('empty_task_selection')
                continue
            consecutive_timeouts = 0
            try:
                self._perform_task()
                self._update_current_understanding()
                self._update_task_tree()
                self._update_potentially_vulnerable_function()
                if self._temp_check():
                    break
                if i % 2 == 0:
                    check_prompt = self.function_prompts.check_analysis_adequacy
                    check_prompt += "Current understanding:" + self.understanding_result
                    result = self.organization_agent.query(check_prompt, format='str')
                    if isinstance(result, str) and re.fullmatch(r'\s*yes[\s.!]*', result, flags=re.IGNORECASE):
                        break
            except Exception:
                # A previous candidate does not make a failed task successful.
                # Let the caller label the report partial/failed.
                raise
            if i >= max_iterations:
                break
        
    def _retrieve_source_code(self, address, function_name):
        output = []
        output_memo = []
        address = address.lower()
        contract_info = self.contract_info
        if address not in self.contract_info:
            contract_info = ContractDownloader(self.analysis_result.chain,[address]).run()
        if address in contract_info:
            if function_name in contract_info[address]:
                source_code_list = contract_info[address][function_name]
                for source_code in source_code_list:
                    content = source_code.get('content')
                    if isinstance(content, str) and content.strip() and content not in output_memo:
                        output_memo.append(content)
                        output.append({'path': source_code['path'], 'source_code': content,
                                       'source_binding': 'unverified', 'contract': source_code.get('contract'),
                                       'source_alternatives': len(source_code_list) > 1})
        return output

    def _retrieve_related_info(self, address, function_name):
        output = {}
        related_balance_change = {}
        address = address.lower()
        if address in self.fundflow_analysis['balance_change']:
            related_balance_change = deepcopy(self.fundflow_analysis['balance_change'][address])
        for key,value in self.fundflow_analysis['balance_change'].items():
            if (key!=address) and (address in value):
                related_balance_change[key] = deepcopy(value)
        if related_balance_change:
            output['related_balance_change'] = related_balance_change
        address_calls = []
        if address in self.txn_seq['address_calls']:
            address_calls = self.txn_seq['address_calls'][address]
        if address_calls:
            output['address_calls'] = address_calls
        relations_with_other_addresses = []
        if address in self.address_relation.nodes():
            relations_with_other_addresses.extend(list(self.address_relation.out_edges(address, data=True)))
            relations_with_other_addresses.extend(list(self.address_relation.in_edges(address, data=True)))
        if relations_with_other_addresses:
            output['relations_with_other_addresses(i.e., sender, receiver, function)'] = relations_with_other_addresses
        function_source_code = self._retrieve_source_code(address, function_name)
        if function_source_code:
            output['function_source_code'] = function_source_code
        return output
    
    def _finalize_potentially_vulnerable_functions(self):
        ranking = getattr(self, 'ranked_result', [])
        ranking = ranking if isinstance(ranking, list) else []
        order = {}
        for index, key in enumerate(ranking):
            if isinstance(key, str):
                order.setdefault(key, index)
        keys = sorted(self.potentially_vulnerable_functions,
                      key=lambda key: order.get(key, len(order)))
        finalized = []
        for key in keys:
            function_name, address = key.rsplit('_', 1)
            finding = deepcopy(self.potentially_vulnerable_functions[key])
            finding['function'] = function_name
            finding['address'] = address.lower()
            finalized.append(finding)
        return finalized

    def _process_potentially_vulnerable_functions(self):
        potentially_vulnerable_functions = {}
        for func in self.potentially_vulnerable_functions:
            potentially_vulnerable_functions[func] = {
                'evidence': self.potentially_vulnerable_functions[func]['evidence'],
                'confidence_score': self.potentially_vulnerable_functions[func].get('confidence_score', []),
                'depth': self.potentially_vulnerable_functions[func].get('depth', 0),
            }
        self.potentially_vulnerable_functions = potentially_vulnerable_functions

    def _rank_potentially_vulnerable_functions(self):
        prompt_text = self.vulnerability_prompts.rank_potentially_vulnerable_functions.format(
            current_understanding=json.dumps(self.understanding_result),
            potentially_vulnerable_functions=json.dumps(self.potentially_vulnerable_functions)
        )
        # Normalize only identities already present in validated findings.
        # Never infer a missing selector/address or accept an unknown target.
        known = {}
        for key in self.potentially_vulnerable_functions:
            known.setdefault(key.lower(), []).append(key)
        for attempt in range(2):
            result = self.agent.query(prompt_text)
            if isinstance(result, dict):
                result = result.get('ranked_functions')
            if isinstance(result, list):
                result = [known[key.lower()][0] if isinstance(key, str)
                          and len(known.get(key.lower(), [])) == 1 else key for key in result]
            if isinstance(result, list) and not any(
                    not isinstance(key, str) or key not in self.potentially_vulnerable_functions for key in result):
                if result or not self.potentially_vulnerable_functions:
                    self.ranked_result = list(dict.fromkeys(result))
                    return
            if attempt == 0:
                prompt_text += '\nReturn only {"ranked_functions": [known finding keys]}. Use only exact keys above; include at least one when findings exist.'
        raise ValueError('Invalid ranking response or unobserved ranking target')

    @staticmethod
    def _validate_selection(result, available):
        if (not isinstance(result, (dict, list)) or not result
                or any(not isinstance(key, str) or key not in available for key in result)):
            raise ValueError('Invalid selection response or unobserved selection target')
        return result

    def _review_function_calls(self):
        # A selector/name can occur at several unrelated contracts. Only the
        # same function at the same address is an already examined target.
        self.examined_function_memo = set()
        selected_functions = {k:v['count'] for k,v in self.functions_to_be_inspected.items()}
        count = 0
        while (len(selected_functions) > 5) and (count < 3):
            count += 1
            function_call_to_be_inspected_summary = {}
            for function_call in self.functions_to_be_inspected:
                function_call_to_be_inspected_summary[function_call] = {
                    'count_of_appearance': self.functions_to_be_inspected[function_call]['count'],
                    'example_calls': self.functions_to_be_inspected[function_call]['calls'][:3]
                }
            prompt = self.function_prompts.narrow_down_functions.format(
                function_call_to_be_inspected = json.dumps(function_call_to_be_inspected_summary),
                balance_change = json.dumps(self.fundflow_analysis['balance_change'])
            )
            selected_functions_new = self._validate_selection(self.agent.query(prompt), self.functions_to_be_inspected)
            if len(selected_functions_new) < len(selected_functions):
                selected_functions = selected_functions_new
        selected_functions_with_created_contract_in_params = list(self.address_calls_with_created_contract_in_params.keys())
        count = 0
        while (len(selected_functions_with_created_contract_in_params) > 5) and (count < 3):
            count += 1
            function_call_to_be_inspected_summary = {}
            for function_call in self.address_calls_with_created_contract_in_params:
                function_call_to_be_inspected_summary[function_call] = {
                    'count_of_appearance': self.address_calls_with_created_contract_in_params[function_call]['count'],
                    'example_calls': self.address_calls_with_created_contract_in_params[function_call]['calls'][:3]
                }
            prompt = self.function_prompts.narrow_down_functions_with_created_contracts.format(
                function_call_to_be_inspected = json.dumps(function_call_to_be_inspected_summary),
            )
            selected_functions_new = self._validate_selection(self.agent.query(prompt), self.address_calls_with_created_contract_in_params)
            if len(selected_functions_new) < len(selected_functions_with_created_contract_in_params):
                selected_functions_with_created_contract_in_params = selected_functions_new
        
        self._prepare_children_call_memo(selected_functions)

        total_functions = len(self.repeated_patterns) + len(selected_functions_with_created_contract_in_params) + len(selected_functions)
        current = 0
        print('repeated patterns to be analyzed:', self.repeated_patterns)
        for repeated_pattern in self.repeated_patterns:
            current += 1
            print(f"         [{current}/{total_functions}] Analyzing repeated pattern...")
            self.task_tree = ''
            self.function_call_info_summary = {}
            self.current_task = ''
            self.processing_result = ''
            self.children_call_memo_single = {}
            if 'start_index' in repeated_pattern:
                del repeated_pattern['start_index']
            if 'end_index' in repeated_pattern:
                del repeated_pattern['end_index']
            self.function_call_info_summary = repeated_pattern
            function_call_related_info = {}
            for f in repeated_pattern['pattern']:
                if f['function']:
                    self.examined_function_memo.add((f['function'], f['address'].lower()))
                    related_info = self._retrieve_related_info(f['address'], f['function'])
                    if related_info:
                        current_output = self._resolve_trace_node(
                            f.get('depth'), f['function'], f['address'])['children']
                        self._update_children_call_memo(current_output, f['function'])
                        function_call_related_info[f"{f['function']}::{f['address']}"] = related_info
            self.function_call_info_summary['function_call_related_info'] = function_call_related_info
            self.function_call_info_summary['high_appearance_count_children_calls'] = self.select_high_appearance_count_children_calls()
            self._function_analysis_init()
            repeated_pattern['analysis_result'] = {
                'task_tree': self.task_tree,
                'function_call_info_summary': self.function_call_info_summary,
                'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
                'current_understanding': self.understanding_result
            }
        print('functions with created contract in params to be analyzed:', selected_functions_with_created_contract_in_params)
        for function in selected_functions_with_created_contract_in_params:
            # Ranker keys in this group are function names, not name_address.
            group = self.address_calls_with_created_contract_in_params.get(function)
            if group is None:
                continue
            targets = {(function, address.lower()) for address in group['address']}
            if targets and targets.issubset(self.examined_function_memo):
                continue
            self.examined_function_memo.update(targets)
            if function in self.address_calls_with_created_contract_in_params:
                current += 1
                print(f"         [{current}/{total_functions}] Analyzing {function} (created contract param)...")
                self.task_tree = ''
                self.function_call_info_summary = {}
                self.current_task = ''
                self.processing_result = ''
                # self.understanding_result = ''
                self.children_call_memo_single = {}
                function_name = function
                appearance_count = self.address_calls_with_created_contract_in_params[function]['count']
                function_calls = self.address_calls_with_created_contract_in_params[function]['calls']
                # self._retrieve_children_calls(function_calls,function_name)
                self.function_call_info_summary = {
                    'function': function_name,
                    'appearance_count': appearance_count,
                    'calls': function_calls,
                    'note': 'this function contains a created contract in its params'
                }
                address_related_info = {}
                self.children_call_memo_single = {}
                for address in self.address_calls_with_created_contract_in_params[function].get('address', []):
                    related_info = self._retrieve_related_info(address, function_name)
                    if related_info:
                        matching = [call for call in function_calls if isinstance(call, dict)
                                    and str(call.get('address', '')).lower() == address.lower()]
                        if not matching:
                            raise RetrievalContractError('unobserved_target', {'function': function_name, 'address': address})
                        current_output = self._resolve_trace_node(
                            matching[0].get('depth'), function_name, address)['children']
                        self._update_children_call_memo(current_output, function_name)
                        address_related_info[address] = related_info
                if address_related_info:
                    self.function_call_info_summary['address_related_info'] = address_related_info
                self.function_call_info_summary['high_appearance_count_children_calls'] = self.select_high_appearance_count_children_calls()
                self._function_analysis_init()
                self.address_calls_with_created_contract_in_params[function]['analysis_result'] = {
                    'task_tree': self.task_tree,
                    'function_call_info_summary': self.function_call_info_summary,
                    'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
                    'current_understanding': self.understanding_result
                }
        print('functions to be analyzed:', selected_functions)
        for function in selected_functions:
            if function in self.functions_to_be_inspected:
                self.task_tree = ''
                self.function_call_info_summary = {}
                self.current_task = ''
                self.processing_result = ''
                # self.understanding_result = ''
                function_name, address = function.rsplit('_', 1)
                target = (function_name, address.lower())
                if target in self.examined_function_memo:
                    continue
                self.examined_function_memo.add(target)
                current += 1
                print(f"         [{current}/{total_functions}] Analyzing {function_name}...")
                appearance_count = self.functions_to_be_inspected[function]['count']
                function_calls = self.functions_to_be_inspected[function]['calls']
                # self._retrieve_children_calls(function_calls,function_name)
                related_info = self._retrieve_related_info(address, function_name)
                self.function_call_info_summary = {
                    'function': function_name,
                    'address': address,
                    'appearance_count': appearance_count,
                    'calls': function_calls,
                }
                if related_info:
                    self.function_call_info_summary.update(related_info)
                self._retrieve_chidlren_calls_memo_single(function_name,address)
                self.function_call_info_summary['high_appearance_count_children_calls'] = self.select_high_appearance_count_children_calls()
                self._function_analysis_init()
                self.functions_to_be_inspected[function]['analysis_result'] = {
                    'task_tree': self.task_tree,
                    'function_call_info_summary': self.function_call_info_summary,
                    'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
                    'current_understanding': self.understanding_result
                }
                
    def _txn_analysis_init(self):
        self.function_call_info_summary['transaction_execution'] = self._execution_context(getattr(self, 'txn_info', None))
        self._update_current_understanding(is_init=True)
        prompt = self.function_prompts.function_analysis_init_prompt
        initial_task_tree = self._initial_task_tree()
        prompt = prompt.format(
            task_tree = initial_task_tree,
            current_understanding = self.understanding_result,
            function_call_info_summary = json.dumps(self.function_call_info_summary)
        )
        result = self.reasoning_agent.query(prompt, format='str')
        self.task_tree = result

        logging.info(f"Function call info summary: {json.dumps(self.function_call_info_summary)}")
        logging.info(f"Current understanding: {self.understanding_result}")
        logging.info(f"Task tree: {self.task_tree}")

        import time as _time
        is_cloud = not is_local_model(self.txn_analyzer_model)
        txn_iters = 2 if is_cloud else 3
        fn_start = _time.time()
        MAX_FUNCTION_SECS = 480

        consecutive_timeouts = 0
        for i in range(txn_iters):
            elapsed = int(_time.time() - fn_start)
            print(f"         [Info] Sub-iteration {i+1}/{txn_iters}  ({elapsed}s elapsed)", flush=True)
            if _time.time() - fn_start >= MAX_FUNCTION_SECS:
                raise AnalysisIncompleteError('loop_time_limit')
            task = self._select_task()
            if not task or not str(task).strip():
                consecutive_timeouts += 1
                if consecutive_timeouts >= 2:
                    raise AnalysisIncompleteError('empty_task_selection')
                continue
            consecutive_timeouts = 0
            try:
                self._perform_task()
                self._update_current_understanding()
                self._update_task_tree()
                self._update_potentially_vulnerable_function()
                if i > 0:
                    check_prompt = self.function_prompts.check_analysis_adequacy_alt
                    check_prompt += "Current understanding:" + self.understanding_result
                    result = self.organization_agent.query(check_prompt, format='str')
                    if isinstance(result, str) and re.fullmatch(r'\s*yes[\s.!]*', result, flags=re.IGNORECASE):
                        break
            except Exception:
                # A previous candidate does not make a failed task successful.
                # Let the caller label the report partial/failed.
                raise
    
    def run(self, forensics_result, txn_seq: dict, txn_info: dict, ranking_result: RankingResult) -> dict:
        """
        Run function analysis using forensics results from Stage 1 and ranking results.

        Args:
            forensics_result: ForensicsResult object from Stage 1
            txn_seq: Transaction sequence data
            txn_info: Transaction info data
            ranking_result: RankingResult from FunctionRanker

        Returns:
            Dictionary containing function analysis results
        """
        # Initialize state
        self.task_tree = ''
        self.txn_hash = forensics_result.transaction_hash
        self.cheatsheet = []

        # Store Stage 1 outputs
        self.analysis_result = forensics_result
        self.txn_seq = txn_seq
        self.txn_info = txn_info

        # ── Inject pre-computed signals as LLM context ──────────────────
        self.rule_verdict    = getattr(forensics_result, 'rule_verdict', 'UNKNOWN')
        self.rule_confidence = getattr(forensics_result, 'rule_confidence', 0.0)
        self.vuln_type_hint  = getattr(forensics_result, 'vuln_type_hint', '')
        self.signals_raw     = getattr(forensics_result, 'signals', {})
        # Rule outputs are hypotheses, never confirmed function findings.

        # Store ranking results
        self.repeated_patterns = ranking_result.repeated_patterns
        self.address_calls_with_created_contract_in_params = ranking_result.address_calls_with_created_contract_in_params
        self.functions_to_be_inspected = ranking_result.functions_to_be_inspected
        self.address_list = ranking_result.address_list
        self.retrieval_diagnostics = []
        self.retrieval_unavailable_count = 0
        self.rejected_finding_observations = []
        self.finding_rejection_count = 0
        self.rejected_finding_observations_omitted = 0

        if not (self.txn_seq and self.txn_info and self.analysis_result):
            return None

        if not self.txn_info.get('transaction_hash'):
            return None

        start_time = time.time()

        # Prepare trace data from forensics result
        self.tx_analysis = {
            'transaction_hash': forensics_result.transaction_hash,
            'chain': forensics_result.chain,
            'trace': forensics_result.trace,
            'address_relation': self.txn_seq['address_relation'],
            'address_calls': self.txn_seq['address_calls'],
            'created_address': self.txn_seq['created_address'],
            'repeated_patterns': forensics_result.repeated_patterns,
            'function_calls_to_expand_loc': forensics_result.function_calls_to_expand_loc,
            'address_calls_with_created_contract_in_params': forensics_result.address_calls_with_created_contract,
            'flatten_trace': forensics_result.flatten_trace,
            'function_call_loc_memo': forensics_result.function_call_loc_memo
        }

        # Prepare fund flow analysis from forensics result
        self.fundflow_analysis = {
            'balance_change': forensics_result.balance_change,
            'address_memo': forensics_result.address_memo,
            'potential_attacker': forensics_result.potential_attacker,
            'potential_victim': forensics_result.potential_victim
        }

        self.trace = [forensics_result.trace]
        self.address_relation = nx.node_link_graph(self.txn_seq['address_relation'], directed=True, edges='edges')

        print("      [+] Downloading contract source code...")
        self.contract_info = ContractDownloader(self.analysis_result.chain, self.address_list).run()

        with self._stage('stage2_llm_analysis'):
            print("      [+] Reviewing function calls...")
            self._review_function_calls()

            self._process_potentially_vulnerable_functions()
            self._rank_potentially_vulnerable_functions()

        # Finalize vulnerable functions with confidence scores preserved
        finalized_functions = self._finalize_potentially_vulnerable_functions()
        priority = compute_priority_breakdown(
            self.signals_raw,
            exploitability_score=self.rule_confidence,
        )

        # Build result — include signal layer outputs for downstream / eval
        result = {
            'duration': time.time() - start_time,
            'ranked_result': self.ranked_result,
            'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
            'finalized_vulnerable_functions': finalized_functions,
            'transaction_understanding': self.understanding_result,
            'functions_to_be_inspected': self.functions_to_be_inspected,
            'retrieval_diagnostics': deepcopy(self.retrieval_diagnostics),
            'retrieval_unavailable_count': self.retrieval_unavailable_count,
            'rejected_finding_observations': deepcopy(self.rejected_finding_observations),
            'rejected_finding_observations_omitted': self.rejected_finding_observations_omitted,
            # ── Signal layer (from Stage 1) ───────────────────────────────
            'reentrancy':     extract_reentrancy_analysis(self.signals_raw),
            'priority':       priority,
            'priority_score': priority['total'],
            'rule_verdict':    self.rule_verdict,
            'rule_confidence': self.rule_confidence,
            'vuln_type_hint':  self.vuln_type_hint,
            'signals':         self.signals_raw,
        }

        return result
