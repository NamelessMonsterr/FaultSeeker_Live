import json
import logging
import os
import re
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
from faultseeker.utils.utils import build_agent


class CandidateIncomplete(RuntimeError):
    """A candidate's task loop ended without an explicit completion signal (iteration limit, or stopped by an error)."""


class FunctionAnalysisIncomplete(RuntimeError):
    """Stage 2 attempted candidates it could not analyze. Raised instead of returning a result that would look complete."""


_URL = re.compile(r'(https?|wss?)://([^/\s]+)\S*')
_SECRET_SHAPES = (
    re.compile(r'sk-[A-Za-z0-9_\-]{8,}'),
    re.compile(r'(?i)bearer\s+[A-Za-z0-9._~+/\-]{8,}=*'),
    re.compile(r'(?i)((?:api[_-]?key|token|secret|password|authorization)["\']?\s*[:=]\s*["\']?)[^\s"\',;)]{6,}'),
)


def scrub_error(text, limit=200):
    """Bounded, secret-free text for an exception message: URLs are cut to their host, key-shaped strings and any
    secret-named environment value are masked."""
    text = _URL.sub(lambda m: f"{m.group(1)}://{m.group(2)}/...", str(text))
    for shape in _SECRET_SHAPES:
        text = shape.sub(lambda m: (m.group(1) if m.groups() else '') + '[redacted]', text)
    for name, value in os.environ.items():
        if len(value) >= 8 and re.search(r'KEY|TOKEN|SECRET|PASSWORD', name, re.I):
            text = text.replace(value, '[redacted]')
    return ' '.join(text.split())[:limit]


class FunctionAnalyzer:

    def __init__(self,
                 model='gpt-4o-mini'):
        self.txn_analyzer_model = model

        # Initialize all prompt classes
        self.session_prompts = OrchestrationSessionPrompts()
        self.task_prompts = TaskCoordinatorPrompts()
        self.function_prompts = WorkerPrompts()
        self.vulnerability_prompts = VulnerabilityAnalysisPrompts()
        self.local_task_prompts = LocalTaskPrompts()

        # Initialize agents with session prompts
        self.reasoning_agent = build_agent(self.session_prompts.function_call_reasoning_init, model)
        self.generation_agent = build_agent(self.session_prompts.function_call_task_generation_init, model)
        self.processing_agent = build_agent(self.session_prompts.function_call_info_processing_init, model)
        self.organization_agent = build_agent(self.session_prompts.function_call_organization_init, model)
        self.children_call_filtering_agent = build_agent(self.session_prompts.function_call_children_call_filtering_init, model)
        self.agent = build_agent("", model)
        
        self.task_tree = ''
        self.function_call_info_summary = {}
        self.current_task = ''
        self.processing_result = ''
        self.understanding_result = ''
        self.potentially_vulnerable_functions = {}
        self.children_call_memo_single = {}
        self.children_call_memo = {}
        self.repeated_patterns = []
        self.examined_function_memo = []      # identities ('function@address', lower-case) analyzed successfully
        self.failed_function_memo = {}        # identity -> number of failed attempts (history; never cleared)
        self.attempted_function_memo = []     # identities whose analysis was attempted at least once
        self.unresolved_failures = {}         # identity -> bounded, redacted error; removed when a retry succeeds

    def _get_function_call_depth(self, function_call):
        temp = function_call.rsplit('_',1)
        function_name = temp[0].lower()
        address = temp[1].lower()
        key = f"{function_name}::{address}"
        current_depth = 0
        if key in self.tx_analysis['function_call_loc_memo']:
            for call in self.tx_analysis['function_call_loc_memo'][key]:
                if len(call['depth']) > current_depth:
                    current_depth = len(call['depth'])
        return current_depth
        
    def _retrieve_function_call_by_depth(self, depth , function_name, get_children=False):
        depth_temp = depth[:-1]
        current = deepcopy(self.trace)
        for d in depth_temp:
            current = current[d]['children']
        if get_children:
            output = []
            for c in current[depth[-1]]['children']:
                if c['function']:
                    if (c['function'] == function_name) and (c['call_type'] == 'delegatecall'):
                        output.extend(deepcopy(c['children']))
                    elif c['type'] not in ['return']:
                        output.append(deepcopy(c))      
            for c in output:                    
                c['children'] = [f"[{child['call_type']}]{child['address']}::{child['function']}({child['params']})" for child in c['children'] if child['function']]
            return output
        if depth[-1] < len(current):
            output = deepcopy(current[depth[-1]])
            output['children'] = [f"[{child['call_type']}]{child['address']}::{child['function']}({child['params']})" for child in output['children'] if child['function']]
            return output
        
    @staticmethod
    def _children_memo_key(function, address):
        """One normalisation for both storing and looking up children context."""
        return f"{function}_{str(address).lower()}"

    @classmethod
    def _canonical_key(cls, key):
        name, address = cls._split_function_key(key)
        return cls._children_memo_key(name, address)

    @staticmethod
    def _split_function_key(key):
        """'safe_transfer_0xabc' -> ('safe_transfer', '0xabc'). The address is whatever follows the LAST underscore."""
        name, sep, address = key.rpartition('_')
        return (name, address) if sep else (key, '')

    def _retrieve_chidlren_calls_memo_single(self, function, address):
        # Per-candidate context is cleared first: a miss must yield an empty context, never the previous function's.
        self.children_call_memo_single = {}
        stored = self.children_call_memo.get(self._children_memo_key(function, address))
        if stored is not None:
            self.children_call_memo_single = deepcopy(stored)      # a copy: later filtering must not edit the memo

    def select_high_appreance_count_children_calls(self):
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
    
    def _retrieve_function_calls(self, function_call):
        function_calls = []
        if isinstance(function_call, dict):
            function_name = function_call['function']
            address = function_call['address']
        else:
            function_name = function_call[1]
            address = function_call[0]
        if ('function' in self.function_call_info_summary) and (function_name == self.function_call_info_summary['function']):
            if 'calls' not in self.current_task:
                param_memo = []
                for call in self.function_call_info_summary['calls']:
                    if call['params'] not in param_memo:
                        param_memo.append(call['params'])
                        call_copy = deepcopy(call)
                        call_copy['function'] = function_name
                        function_calls.append(call_copy)
        else:
            key = f"{function_name}::{address}".lower()
            memo = []
            if key in self.tx_analysis['function_call_loc_memo']:
                for call in self.tx_analysis['function_call_loc_memo'][key]:
                    if call['params'] not in memo:
                        memo.append(call['params'])
                        function_calls.append(self._retrieve_function_call_by_depth(call['depth'],function_name=function_name))
        return function_calls
    
    def _retrieve_children_calls(self, function_name, address):
        calls = []
        function_calls = []
        if ('function' in self.function_call_info_summary) and (function_name == self.function_call_info_summary['function']):
            calls = self.function_call_info_summary['calls']
        else:
            key = f"{function_name}::{address}".lower()
            if key in self.tx_analysis['function_call_loc_memo']:
                calls = self.tx_analysis['function_call_loc_memo'][key]
        if calls:
                memo = []
                for call in calls:
                    if call['params'] not in memo:
                        memo.append(call['params'])
                        function_calls.extend(self._retrieve_function_call_by_depth(call['depth'],function_name=function_name,get_children=True))
        return function_calls

    def _retrieve_additional_info(self, additional_info):
        prompt = self.function_prompts.retrieve_additional_info
        prompt += f"Current available information:{self.function_call_info_summary}\n"
        prompt += f"Additional information to be reorganized:{additional_info}"
        formatted_additional_info = self.generation_agent.query(prompt)
        output = {}
        if 'function_call' in formatted_additional_info:
            function_call = []
            for f in formatted_additional_info['function_call']:
                function_call.extend(self._retrieve_function_calls(f))
            if function_call:
                output['function_call'] = function_call
        if 'children_calls' in formatted_additional_info:
            children_call = {}
            for function_call in formatted_additional_info['children_calls']:
                if isinstance(function_call, dict):
                    function_name = function_call['function']
                    address = function_call['address']
                else:
                    function_name = function_call[0]
                    address = function_call[1]
                children_call[f'{function_name}::{address}'] = self._retrieve_children_calls(function_name, address)
            if children_call:
                output['children_calls (i.e., for {k:v}, v is the children calls of k)'] = children_call
        if 'source_code' in formatted_additional_info:
            source_code = {}
            if isinstance(formatted_additional_info['source_code'], dict):
                function_name = formatted_additional_info['source_code']['function_name']
                address = formatted_additional_info['source_code']['address']
                if f'{function_name}::{address}' in self.function_call_info_summary['high_appreance_count_children_calls']:
                    key_list = list(self.function_call_info_summary['high_appreance_count_children_calls'].keys())
                    index = key_list.index(f'{function_name}::{address}')
                    if index + 1 < len(key_list):
                        next_key = key_list[index + 1]
                        next_function_name = next_key.split('::')[0]
                        next_address = next_key.split('::')[1]
                        if next_function_name == function_name:
                            address = next_address
                retrieved_source_code = self._retrieve_source_code(address, function_name)
                source_code[f'{function_name}_{address}'] = retrieved_source_code if retrieved_source_code else 'no source code found, proceed to other analysis for other functions'
            else:
                for temp in formatted_additional_info['source_code']:
                    if isinstance(temp, dict):
                        function_name = temp['function']
                        address = temp['address']
                    else:
                        function_name = temp[1]
                        address = temp[0]
                    if f'{function_name}::{address}' in self.function_call_info_summary['high_appreance_count_children_calls']:
                        key_list = list(self.function_call_info_summary['high_appreance_count_children_calls'].keys())
                        index = key_list.index(f'{function_name}::{address}')
                        if index + 1 < len(key_list):
                            next_key = key_list[index + 1]
                            next_function_name = next_key.split('::')[0]
                            next_address = next_key.split('::')[1]
                            if next_function_name == function_name:
                                address = next_address
                    retrieved_source_code = self._retrieve_source_code(address, function_name)
                    source_code[f'{function_name}_{address}'] = retrieved_source_code if retrieved_source_code else 'no source code found, proceed to other analysis'
            if source_code:
                output['source_code'] = source_code
        if 'balance_change' in formatted_additional_info:
            balance_change = {}
            for address in formatted_additional_info['balance_change']:
                address = address.lower()
                if address in self.fundflow_analysis['balance_change']:
                    balance_change[address] = deepcopy(self.fundflow_analysis['balance_change'][address])
                for addr in self.fundflow_analysis['balance_change']:
                    if addr != address:
                        if address in self.fundflow_analysis['balance_change'][addr]:
                            balance_change[addr] = deepcopy(self.fundflow_analysis['balance_change'][addr])
            if balance_change:
                output['balance_change'] = balance_change
        return output

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
        if is_init:
            understanding_prompt = self.function_prompts.function_call_organization_function_call.format(function_call_info_summary=json.dumps(self.function_call_info_summary))
            self.understanding_result = self.organization_agent.query(understanding_prompt, format='str')
        else:
            understanding_prompt = self.function_prompts.function_call_organization_function_call.format(function_call_info_summary=json.dumps(self.function_call_info_summary))
            self.understanding_result = self.organization_agent.query(understanding_prompt, format='str')
        logging.info(f"Current understanding: {self.understanding_result}")

    def _update_potentially_vulnerable_function(self):
        prompt = self.vulnerability_prompts.update_potentially_vulnerable_function
        prompt += "Current understanding:" + self.understanding_result
        prompt += "Current task:" + json.dumps(self.current_task)
        prompt += 'Analysis result of current task:' + json.dumps(self.processing_result)
        prompt += 'The following function calls have been confirmed to be vulnerable, if it is in the provided information, please add it to the returned JSON with the predefined format: ' + str(self.cheatsheet)
        result = self.organization_agent.query(prompt)
        logging.info(f"Vulnerable function: {result}")
        for key in result:
            try:
                evidence = ''
                confidence_score = ''
                if isinstance(result[key],list) or isinstance(result[key],tuple):
                    evidence = result[key][0]
                    confidence_score = result[key][1]
                elif isinstance(result[key],dict):
                    evidence = result[key]['evidence']
                    confidence_score = result[key]['confidence_score']
                if evidence and confidence_score:
                    if key not in self.potentially_vulnerable_functions:
                        self.potentially_vulnerable_functions[key] = {
                            'confidence_score': [confidence_score],
                            'evidence': [evidence],
                            'depth': self._get_function_call_depth(key),
                        }
                    else:
                        self.potentially_vulnerable_functions[key]['confidence_score'].append(confidence_score)
                        self.potentially_vulnerable_functions[key]['evidence'].append(evidence)
            except Exception:
                pass
    
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

    def _prepare_children_call_memo(self, function_calls):
        for function in function_calls:
            if function not in self.functions_to_be_inspected:
                # Only the address part of a key is case-insensitive; Solidity function names are case-sensitive.
                by_canonical = {self._canonical_key(k): k for k in self.functions_to_be_inspected}
                if self._canonical_key(function) not in by_canonical:
                    continue
                function = by_canonical[self._canonical_key(function)]
            self.children_call_memo_single = {}
            for function_call in self.functions_to_be_inspected[function]['calls']:
                current_output = deepcopy(self.trace)
                for d in function_call['depth']:
                    current_output = current_output[d]['children']
                    self._update_children_call_memo(current_output, self._split_function_key(function)[0])
            self.children_call_memo[self._canonical_key(function)] = self.children_call_memo_single
            self.children_call_memo_single = {}
    
    def _temp_check(self):
        return False
    
    def _function_analysis_init(self):
        if self._temp_check():
            return
        self._update_current_understanding(is_init=True)
        prompt = self.function_prompts.function_analysis_init_prompt
        initial_task_tree = '''1. Basic Function Call Info Gathering - [completed]
   1.1 Summary of appreance in the transaction - (completed)
   1.2 Summary of the relation with other addresses - (completed)
   1.3 Retrieve the source code of the function call - (completed)
'''
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

        # Why the loop ended decides whether the candidate is done. Only an explicit completion signal counts:
        #   - the adequacy check answering yes (the model confirms the analysis is sufficient), or
        #   - _temp_check() returning True (the hook's own "finished" signal; it is a constant False today).
        # Running out of iterations, or being stopped by an error, is NOT completion, however many steps succeeded or
        # whatever was found on the way.
        i = 0
        completed_steps, last_error, completed, stopped = 0, None, False, 'iteration limit'
        while True:
            i += 1
            self._select_task()
            try:
                self._perform_task()
                self._update_current_understanding()
                self._update_task_tree()
                self._update_potentially_vulnerable_function()
                completed_steps += 1
                if self._temp_check():
                    completed = True
                    break
                if i%3 == 0:
                    check_prompt = self.function_prompts.check_analysis_adequacy
                    check_prompt += "Current understanding:" + self.understanding_result
                    result = self.organization_agent.query(check_prompt, format='str')
                    if 'yes' in result.lower():
                        completed = True
                        break
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if self.potentially_vulnerable_functions:
                    stopped = 'error'          # the pre-existing early exit once something was found: still not complete
                    break
            if i > 30:
                break
        if not completed:
            reason = (f"iteration limit ({i}) reached without an adequacy confirmation" if stopped == 'iteration limit'
                      else "stopped by an error without an adequacy confirmation")
            detail = f"{reason} after {completed_steps} completed step(s)"
            if last_error is not None:
                detail += f"; last error {type(last_error).__name__}: {last_error}"
            raise CandidateIncomplete(detail) from None         # no chaining: the raw provider text stays out of tracebacks

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
                    if source_code['start_line'] != source_code['end_line']:
                        if source_code['content'] not in output_memo:
                            output_memo.append(source_code['content'])
                            output.append({'path':source_code['path'],'source_code':source_code['content']})
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
        current_depth = 0
        finalized_potentially_vulnerable_functions = []
        for key in self.potentially_vulnerable_functions:
            if self.potentially_vulnerable_functions[key]['depth'] > current_depth:
                current_depth = self.potentially_vulnerable_functions[key]['depth']
                potentially_vulnerable_functions = deepcopy(self.potentially_vulnerable_functions[key])
                temp = key.rsplit('_',1)
                function_name = temp[0]
                address = temp[1].lower()
                potentially_vulnerable_functions['function'] = function_name
                potentially_vulnerable_functions['address'] = address
                del potentially_vulnerable_functions['confidence_score']
                finalized_potentially_vulnerable_functions = [potentially_vulnerable_functions]
            elif self.potentially_vulnerable_functions[key]['depth'] == current_depth:
                potentially_vulnerable_functions = deepcopy(self.potentially_vulnerable_functions[key])
                temp = key.rsplit('_',1)
                function_name = temp[0]
                address = temp[1].lower()
                potentially_vulnerable_functions['function'] = function_name
                potentially_vulnerable_functions['address'] = address
                del potentially_vulnerable_functions['confidence_score']
                finalized_potentially_vulnerable_functions.append(potentially_vulnerable_functions)
        return finalized_potentially_vulnerable_functions
        
    def _process_potentially_vulnerable_functions(self):
        potentially_vulnerable_functions = {}
        for func in self.potentially_vulnerable_functions:
            potentially_vulnerable_functions[func] = self.potentially_vulnerable_functions[func]['evidence']
        self.potentially_vulnerable_functions = potentially_vulnerable_functions

    def _rank_potentially_vulnerable_functions(self):
        prompt_text = self.vulnerability_prompts.rank_potentially_vulnerable_functions.format(
            current_understanding=json.dumps(self.understanding_result),
            potentially_vulnerable_functions=json.dumps(self.potentially_vulnerable_functions)
        )
        self.ranked_result = self.agent.query(prompt_text)

    def _review_function_calls(self):
        self.examined_function_memo = []
        self.failed_function_memo = {}
        self.attempted_function_memo = []
        self.unresolved_failures = {}
        selected_functions = {k:v['count'] for k,v in self.functions_to_be_inspected.items()}
        count = 0
        while (len(selected_functions) > 5) and (count < 3):
            count += 1
            function_call_to_be_inspected_summary = {}
            for function_call in self.functions_to_be_inspected:
                function_call_to_be_inspected_summary[function_call] = {
                    'count_of_appreance': self.functions_to_be_inspected[function_call]['count'],
                    'example_calls': self.functions_to_be_inspected[function_call]['calls'][:3]
                }
            prompt = self.function_prompts.narrow_down_functions.format(
                function_call_to_be_inspected = json.dumps(function_call_to_be_inspected_summary),
                balance_change = json.dumps(self.fundflow_analysis['balance_change'])
            )
            selected_functions_new = self.agent.query(prompt)
            if len(selected_functions_new) < len(selected_functions):
                selected_functions = selected_functions_new
        selected_functions_with_created_contract_in_params = list(self.address_calls_with_created_contract_in_params.keys())
        count = 0
        while (len(selected_functions_with_created_contract_in_params) > 5) and (count < 3):
            count += 1
            function_call_to_be_inspected_summary = {}
            for function_call in self.address_calls_with_created_contract_in_params:
                function_call_to_be_inspected_summary[function_call] = {
                    'count_of_appreance': self.address_calls_with_created_contract_in_params[function_call]['count'],
                    'example_calls': self.address_calls_with_created_contract_in_params[function_call]['calls'][:3]
                }
            prompt = self.function_prompts.narrow_down_functions_with_created_contracts.format(
                function_call_to_be_inspected = json.dumps(function_call_to_be_inspected_summary),
            )
            selected_functions_new = self.agent.query(prompt)
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
            identities = []
            for f in repeated_pattern['pattern']:
                if f['function']:
                    identities.append(self._identity(f['function'], f['address']))
                    related_info = self._retrieve_related_info(f['address'], f['function'])
                    if related_info:
                        current_output = deepcopy(self.trace)
                        for d in f['depth']:
                            current_output = current_output[d]['children']
                        self._update_children_call_memo(current_output, f['function'])
                        function_call_related_info[f"{f['function']}::{f['address']}"] = related_info
            self.function_call_info_summary['function_call_related_info'] = function_call_related_info
            self.function_call_info_summary['high_appreance_count_children_calls'] = self.select_high_appreance_count_children_calls()
            if self._run_candidate(identities, 'repeated pattern'):
                continue
            repeated_pattern['analysis_result'] = {
                'task_tree': self.task_tree,
                'function_call_info_summary': self.function_call_info_summary,
                'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
                'current_understanding': self.understanding_result
            }
        print('functions with created contract in params to be analyzed:', selected_functions_with_created_contract_in_params)
        for function in selected_functions_with_created_contract_in_params:
            # Keys of this mapping are bare function names; an underscore is part of the name, never a separator.
            if function not in self.address_calls_with_created_contract_in_params:
                bare = self._split_function_key(function)[0]
                if bare not in self.address_calls_with_created_contract_in_params:
                    continue
                function = bare
            addresses = [a for a in self.address_calls_with_created_contract_in_params[function]['address']
                         if self._candidate_pending(self._identity(function, a))]
            if not addresses:
                continue
            current += 1
            print(f"         [{current}/{total_functions}] Analyzing {function} (created contract param)...")
            self.task_tree = ''
            self.function_call_info_summary = {}
            self.current_task = ''
            self.processing_result = ''
            # self.understanding_result = ''
            self.children_call_memo_single = {}
            function_name = function
            appreance_count = self.address_calls_with_created_contract_in_params[function]['count']
            function_calls = self.address_calls_with_created_contract_in_params[function]['calls']
            # self._retrieve_children_calls(function_calls,function_name)
            self.function_call_info_summary = {
                'function': function_name,
                'appreance_count': appreance_count,
                'calls': function_calls,
                'note': 'this function contains a created contract in its params'
            }
            address_related_info = {}
            self.children_call_memo_single = {}
            for address in addresses:
                related_info = self._retrieve_related_info(address, function_name)
                if related_info:
                    current_output = deepcopy(self.trace)
                    for d in function_calls[0]['depth']:
                        current_output = current_output[d]['children']
                    self._update_children_call_memo(current_output, function_name)
                    address_related_info[address] = related_info
            if address_related_info:
                self.function_call_info_summary['address_related_info'] = address_related_info
            self.function_call_info_summary['high_appreance_count_children_calls'] = self.select_high_appreance_count_children_calls()
            if self._run_candidate([self._identity(function, a) for a in addresses], function_name):
                continue
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
                function_name, address = self._split_function_key(function)
                if not self._candidate_pending(self._identity(function_name, address)):
                    continue
                current += 1
                print(f"         [{current}/{total_functions}] Analyzing {function_name}...")
                appreance_count = self.functions_to_be_inspected[function]['count']
                function_calls = self.functions_to_be_inspected[function]['calls']
                # self._retrieve_children_calls(function_calls,function_name)
                related_info = self._retrieve_related_info(address, function_name)
                self.function_call_info_summary = {
                    'function': function_name,
                    'address': address,
                    'appreance_count': appreance_count,
                    'calls': function_calls,
                }
                if related_info:
                    self.function_call_info_summary.update(related_info)
                self._retrieve_chidlren_calls_memo_single(function_name,address)
                self.function_call_info_summary['high_appreance_count_children_calls'] = self.select_high_appreance_count_children_calls()
                if self._run_candidate([self._identity(function_name, address)], function_name):
                    continue
                self.functions_to_be_inspected[function]['analysis_result'] = {
                    'task_tree': self.task_tree,
                    'function_call_info_summary': self.function_call_info_summary,
                    'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
                    'current_understanding': self.understanding_result
                }

    # -- candidate identity and outcomes -----------------------------------------------------------------------
    MAX_CANDIDATE_ATTEMPTS = 2

    @staticmethod
    def _identity(function, address):
        """A candidate is a function ON A CONTRACT: 'function@address'. The address is normalized (lower-case); the function
        name is not, because Solidity names are case-sensitive (`Foo` and `foo` are different functions)."""
        return f"{function}@{str(address or '').lower()}"

    def _candidate_pending(self, identity):
        """True unless it was already analyzed successfully or has used up its attempts."""
        return (identity not in self.examined_function_memo
                and self.failed_function_memo.get(identity, 0) < self.MAX_CANDIDATE_ATTEMPTS)

    def _run_candidate(self, identities, label):
        """Runs the analysis of the current candidate and records the outcome per identity.

        Success is recorded only after the analysis returned, and clears any earlier unresolved failure of that identity.
        A failure is recorded with an attempt count and a bounded, redacted detail, and is returned as text so the caller
        can move on; it is NOT forgotten: run() fails Stage 2 if any attempted identity is still unresolved at the end.
        """
        for identity in identities:
            if identity not in self.attempted_function_memo:
                self.attempted_function_memo.append(identity)
        try:
            self._function_analysis_init()
        except Exception as exc:  # noqa: BLE001 - model/tool failures are per-candidate
            detail = scrub_error(f"{type(exc).__name__}: {exc}")
            for identity in identities:
                self.failed_function_memo[identity] = self.failed_function_memo.get(identity, 0) + 1
                self.unresolved_failures[identity] = detail
            print(f"         ✗ Analysis of {label} failed ({detail}); it will not be retried more than "
                  f"{self.MAX_CANDIDATE_ATTEMPTS} times in total.")
            return detail
        for identity in identities:
            self.unresolved_failures.pop(identity, None)
            if identity not in self.examined_function_memo:
                self.examined_function_memo.append(identity)
        return None

    def _raise_if_unresolved_failures(self):
        """Fail closed: attempted candidates that never recovered mean the analysis is incomplete, whatever else succeeded."""
        if not self.unresolved_failures:
            return
        total, failed = len(self.attempted_function_memo), list(self.unresolved_failures.items())
        head = (f"Stage 2 (Function Analysis) incomplete: {len(failed)} of {total} attempted candidate(s) failed "
                f"and were not recovered: ")
        parts, used = [], len(head)
        for n, (identity, detail) in enumerate(failed):
            piece = f"{identity} ({detail[:70]})"
            if parts and used + len(piece) + 2 > 440:
                parts.append(f"and {len(failed) - n} more")
                break
            parts.append(piece)
            used += len(piece) + 2
        raise FunctionAnalysisIncomplete(head + "; ".join(parts))

    def _txn_analysis_init(self):
        self._update_current_understanding(is_init=True)
        prompt = self.function_prompts.function_analysis_init_prompt
        initial_task_tree = '''1. Basic Function Call Info Gathering - [completed]
   1.1 Summary of appreance in the transaction - (completed)
   1.2 Summary of the relation with other addresses - (completed)
   1.3 Retrieve the source code of the function call - (completed)
'''
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

        for i in range(5):
            self._select_task()
            try:
                self._perform_task()
                self._update_current_understanding()
                self._update_task_tree()
                self._update_potentially_vulnerable_function()
                if i > 0:
                    check_prompt = self.function_prompts.check_analysis_adequacy_alt
                    check_prompt += "Current understanding:" + self.understanding_result
                    result = self.organization_agent.query(check_prompt, format='str')
                    if 'yes' in result.lower():
                        break
            except Exception:
                if self.potentially_vulnerable_functions:
                    break
    
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

        # Store ranking results
        self.repeated_patterns = ranking_result.repeated_patterns
        self.address_calls_with_created_contract_in_params = ranking_result.address_calls_with_created_contract_in_params
        self.functions_to_be_inspected = ranking_result.functions_to_be_inspected
        self.address_list = ranking_result.address_list

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

        print("      → Downloading contract source code...")
        self.contract_info = ContractDownloader(self.analysis_result.chain, self.address_list).run()

        print("      → Reviewing function calls...")
        self._review_function_calls()
        self._raise_if_unresolved_failures()

        self._process_potentially_vulnerable_functions()
        self._rank_potentially_vulnerable_functions()

        # Build result
        result = {
            'duration': time.time() - start_time,
            "ranked_result": self.ranked_result,
            'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
            "transaction_understanding": self.understanding_result,
            'functions_to_be_inspected': self.functions_to_be_inspected,
        }

        return result
