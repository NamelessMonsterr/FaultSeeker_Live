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
from faultseeker.utils.agent import ModelResponseError, ProviderFailure
from faultseeker.utils.utils import build_agent


# Maximum number of model requests permitted for one task-selection operation.
# Includes the initial request and all formatting/structured-response retries.
MAX_TASK_SELECTION_ATTEMPTS = 4


_CANDIDATE_ATTEMPT_STATE_FIELDS = (
    "task_tree",
    "function_call_info_summary",
    "current_task",
    "processing_result",
    "understanding_result",
    "potentially_vulnerable_functions",
    "children_call_memo_single",
    "children_call_memo",
    "repeated_patterns",
)


class CandidateIncomplete(RuntimeError):
    """A candidate's task loop ended without an explicit completion signal (iteration limit, or stopped by an error)."""

    def __init__(self, message, retryable=False):
        super().__init__(message)
        self.retryable = bool(retryable)


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
        self.ranking_problem = ''             # why the ranking reply was unusable ('' when it was fine)
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

    # -- model-supplied structures: validate before use ----------------------------------------------------------
    _ADDRESS = re.compile(r'^0x[0-9a-fA-F]{40}$')

    @classmethod
    def _is_address(cls, value):
        """0x followed by exactly 40 hex digits. Required before any model-influenced contract lookup."""
        return isinstance(value, str) and bool(cls._ADDRESS.match(value.strip()))

    @classmethod
    def _call_ref(cls, entry, legacy_order):
        """(function, address) from one model-supplied reference, or None when it is malformed.

        Supported forms: {"function": f, "address": a} (also "function_name"), and a 2-item list/tuple of strings. In a
        pair the address is the element that looks like one; if neither (or both) does, `legacy_order` decides
        ('address_first' or 'function_first'). Plain strings, numbers and other shapes are rejected, never indexed.
        """
        if isinstance(entry, dict):
            function, address = entry.get('function', entry.get('function_name')), entry.get('address')
        elif isinstance(entry, (list, tuple)) and len(entry) == 2:
            first, second = entry
            if cls._is_address(first) and not cls._is_address(second):
                address, function = first, second
            elif cls._is_address(second) and not cls._is_address(first):
                function, address = first, second
            elif legacy_order == 'address_first':
                address, function = first, second
            else:
                function, address = first, second
        else:
            return None
        if isinstance(function, str) and function.strip() and isinstance(address, str) and address.strip():
            return function.strip(), address.strip()
        return None

    @staticmethod
    def _entries(value):
        """The list of entries in a model-supplied section: a list/tuple as is, a lone dict as one entry, else none
        (in particular a string is never iterated character by character)."""
        if isinstance(value, (list, tuple)):
            return list(value)
        if isinstance(value, dict):
            return [value]
        return []

    def _same_function_next_address(self, function_name, address):
        """Existing rule: if the next high-count child entry is the same function on another contract, use that one."""
        children = self.function_call_info_summary.get('high_appreance_count_children_calls') or {}
        key = f'{function_name}::{address}'
        if key in children:
            key_list = list(children.keys())
            index = key_list.index(key)
            if index + 1 < len(key_list):
                next_function_name, _, next_address = key_list[index + 1].partition('::')
                if next_function_name == function_name and self._is_address(next_address):
                    return next_address
        return address

    def _retrieve_additional_info(self, additional_info):
        prompt = self.function_prompts.retrieve_additional_info
        prompt += f"Current available information:{self.function_call_info_summary}\n"
        prompt += f"Additional information to be reorganized:{additional_info}"
        # The reply as a whole must be a JSON object (else ModelResponseError: the step fails and the loop handles it);
        # individual malformed entries inside it are optional pieces and are skipped.
        formatted_additional_info = self.generation_agent.query_json(prompt, expect=dict)
        output = {}
        function_call = []
        for entry in self._entries(formatted_additional_info.get('function_call')):
            ref = self._call_ref(entry, 'address_first')
            if ref:
                function_call.extend(self._retrieve_function_calls({'function': ref[0], 'address': ref[1]}))
        if function_call:
            output['function_call'] = function_call
        children_call = {}
        for entry in self._entries(formatted_additional_info.get('children_calls')):
            ref = self._call_ref(entry, 'function_first')
            if ref:
                children_call[f'{ref[0]}::{ref[1]}'] = self._retrieve_children_calls(ref[0], ref[1])
        if children_call:
            output['children_calls (i.e., for {k:v}, v is the children calls of k)'] = children_call
        raw_source = formatted_additional_info.get('source_code')
        source_code = {}
        for entry in self._entries(raw_source):
            ref = self._call_ref(entry, 'address_first')
            if not ref or not self._is_address(ref[1]):
                continue                                   # malformed entry or not a real address: never look it up
            function_name, address = ref[0], self._same_function_next_address(ref[0], ref[1])
            retrieved_source_code = self._retrieve_source_code(address, function_name)
            fallback = ('no source code found, proceed to other analysis for other functions'
                        if isinstance(raw_source, dict) else 'no source code found, proceed to other analysis')
            source_code[f'{function_name}_{address}'] = retrieved_source_code if retrieved_source_code else fallback
        if source_code:
            output['source_code'] = source_code
        raw_balance = formatted_additional_info.get('balance_change')
        balance_change = {}
        for address in ([raw_balance] if isinstance(raw_balance, str) else self._entries(raw_balance) if not isinstance(raw_balance, dict) else []):
            if not isinstance(address, str):
                continue
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

    @staticmethod
    def _normalize_task(task):
        """Validates a model-selected task in place and returns it; raises ModelResponseError when a REQUIRED part is
        wrong. Required: a JSON object with a non-empty string task_description (or description). Optional and skipped
        when malformed: additional_information (anything but text, a list or an object becomes empty)."""
        if not isinstance(task, dict):
            raise ModelResponseError(
                f"the selected task is not a JSON object (got {type(task).__name__})"
            )

        description = task.get('description')
        if not (isinstance(description, str) and description.strip()):
            description = task.get('task_description')

        if not (isinstance(description, str) and description.strip()):
            raise ModelResponseError(
                "the selected task has no usable task_description: "
                "it must be a non-empty string "
                f"(got {type(task.get('task_description', task.get('description'))).__name__})"
            )

        task['task_description'] = description

        if not isinstance(task.get('additional_information'), (str, list, dict)):
            task['additional_information'] = ''

        return task


    def _perform_task(self):
        self._normalize_task(self.current_task)
        self.current_task['additional_information'] = self._retrieve_additional_info(str(self.current_task['additional_information'])+ self.current_task['task_description'])
        processing_prompt = self.function_prompts.function_call_info_processing.format(
            selected_task = json.dumps(self.current_task)
        )
        self.processing_result = self.processing_agent.query_text(processing_prompt)
        logging.info(f"Processing result: {self.processing_result}")

    def _select_task(self):
        task_selection_prompt = self.function_prompts.function_call_task_selection.format(
            task_tree=self.task_tree,
            function_call_info_summary=self.function_call_info_summary,
            current_understanding=self.understanding_result
        )

        problem = ''
        for attempt in range(MAX_TASK_SELECTION_ATTEMPTS):
            message = (
                task_selection_prompt
                if attempt == 0
                else (
                    "The previous task selection was unusable. "
                    "Please reformat the task into a standard JSON object "
                    "with a non-empty task_description. Preserve the original "
                    "requested task and do not invent missing information."
                )
            )

            try:
                # One model request per iteration; no nested query_json retries.
                task = self.generation_agent.query_json_once(
                    message,
                    expect=dict
                )

                # Validate each reply before accepting it. Invalid required fields
                # consume one selection attempt just like malformed structured data.
                task = self._normalize_task(task)

            except ProviderFailure:
                # Transport/provider failures are not formatting failures.
                raise

            except ModelResponseError as exc:
                problem = str(exc)
                continue

            self.current_task = task
            logging.info(f"Selected task: {self.current_task}")
            return

        raise CandidateIncomplete(
            f"no usable task after {MAX_TASK_SELECTION_ATTEMPTS} model requests: {problem}",
            retryable=True
        ) from None

    def _update_task_tree(self):
        prompt = self.task_prompts.update_task_tree.format(
            task_tree = self.task_tree,
            current_understanding = self.understanding_result,
            task_completed = self.processing_result
        )
        result = self.reasoning_agent.query_text(prompt)
        self.task_tree = result
        logging.info(f"Task tree: {self.task_tree}")

    def _update_current_understanding(self, is_init=False):
        if is_init:
            understanding_prompt = self.function_prompts.function_call_organization_function_call.format(function_call_info_summary=json.dumps(self.function_call_info_summary))
            self.understanding_result = self.organization_agent.query_text(understanding_prompt)
        else:
            understanding_prompt = self.function_prompts.function_call_organization_function_call.format(function_call_info_summary=json.dumps(self.function_call_info_summary))
            self.understanding_result = self.organization_agent.query_text(understanding_prompt)
        logging.info(f"Current understanding: {self.understanding_result}")

    def _update_potentially_vulnerable_function(self):
        prompt = self.vulnerability_prompts.update_potentially_vulnerable_function
        prompt += "Current understanding:" + self.understanding_result
        prompt += "Current task:" + json.dumps(self.current_task)
        prompt += 'Analysis result of current task:' + json.dumps(self.processing_result)
        prompt += 'The following function calls have been confirmed to be vulnerable, if it is in the provided information, please add it to the returned JSON with the predefined format: ' + str(self.cheatsheet)
        result = self.organization_agent.query_json(prompt, expect=(dict, list))
        if isinstance(result, list):
            if result:
                raise ModelResponseError("expected a JSON object of potentially vulnerable functions, got a non-empty list")
            result = {}
        logging.info(f"Vulnerable function: {result}")
        for key in result:
            try:
                value = result[key]

                if isinstance(value, (list, tuple)):
                    if len(value) != 2:
                        raise ValueError("expected two evidence fields")
                    evidence, confidence_score = value
                elif isinstance(value, dict):
                    evidence = value['evidence']
                    confidence_score = value['confidence_score']
                else:
                    raise TypeError("unsupported evidence value shape")

                if not evidence or not confidence_score:
                    raise ValueError("evidence or confidence score is missing")

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
                logging.warning(
                    "Skipping malformed potentially-vulnerable-function entry; "
                    "evidence or confidence data could not be processed."
                )
    
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
        result = self.reasoning_agent.query_text(prompt)
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
            try:
                self._select_task()
                self._perform_task()
                self._update_current_understanding()
                self._update_task_tree()
                self._update_potentially_vulnerable_function()
                completed_steps += 1

                if self._temp_check():
                    completed = True
                    break

                if i % 3 == 0:
                    check_prompt = self.function_prompts.check_analysis_adequacy
                    check_prompt += "Current understanding:" + self.understanding_result
                    result = self.organization_agent.query_text(check_prompt)
                    if 'yes' in result.lower():
                        completed = True
                        break

            except ProviderFailure as exc:
                # The provider gave no usable text (already re-asked by the agent). That is neither "adequate" nor "not
                # adequate": the candidate stops here, as a provider failure, instead of burning the iteration cap.
                last_error, stopped = exc, 'provider'
                break

            except CandidateIncomplete as exc:
                last_error, stopped = exc, 'error'
                break

            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if self.potentially_vulnerable_functions:
                    stopped = 'error'          # the pre-existing early exit once something was found: still not complete
                    break

            if i > 30:
                break

        if not completed:
            reason = {
                'iteration limit': f"iteration limit ({i}) reached without an adequacy confirmation",
                'provider': "stopped by a provider failure without an adequacy confirmation",
            }.get(stopped, "stopped by an error without an adequacy confirmation")

            detail = f"{reason} after {completed_steps} completed step(s)"
            if last_error is not None:
                detail += f"; last error {type(last_error).__name__}: {last_error}"

            # ProviderFailure subclasses ModelResponseError, but provider outages
            # are terminal and must never make a candidate retryable.
            if isinstance(last_error, ProviderFailure):
                retryable = False
            elif isinstance(last_error, CandidateIncomplete):
                retryable = last_error.retryable
            elif isinstance(last_error, ModelResponseError):
                retryable = True
            else:
                retryable = False

            raise CandidateIncomplete(
                detail,
                retryable=retryable
            ) from None  # no chaining: the raw provider text stays out of tracebacks

    def _retrieve_source_code(self, address, function_name):
        output = []
        output_memo = []
        if not self._is_address(address) or not isinstance(function_name, str):
            return output                                  # garbage never reaches the downloader
        address = address.strip().lower()
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
        self.ranking_problem = ''
        try:
            self.ranked_result = self.agent.query_json(prompt_text, expect=(list, dict))
        except ModelResponseError as exc:
            # No usable ranking is not a failed analysis: the analyzed candidates still go into the report, unranked, and
            # the report says why (results.normalize shows ranking_problem).
            self.ranked_result = []
            self.ranking_problem = scrub_error(f"{type(exc).__name__}: {exc}", 160)

    def _narrowing_reply(self, prompt, current_count):
        """Names from a narrowing reply, or None when the reply is unusable. Narrowing is an optimisation: an unusable
        reply (text, wrong type, empty) is ignored and the larger candidate list is kept, so nothing is dropped by a
        garbled answer and an unparsed string is never iterated as if it were a list of functions."""
        try:
            reply = self.agent.query_json(prompt, expect=(list, dict))
        except ModelResponseError as exc:
            print(f"         narrowing reply ignored ({exc}); keeping all {current_count} candidates")
            return None
        names = [n for n in (list(reply) if isinstance(reply, dict) else reply) if isinstance(n, str) and n.strip()]
        return names or None

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
            selected_functions_new = self._narrowing_reply(prompt, len(selected_functions))
            if selected_functions_new is not None and len(selected_functions_new) < len(selected_functions):
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
            selected_functions_new = self._narrowing_reply(prompt, len(selected_functions_with_created_contract_in_params))
            if selected_functions_new is not None and len(selected_functions_new) < len(selected_functions_with_created_contract_in_params):
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

    def _capture_candidate_attempt_state(self):
        """Capture an isolated baseline of mutable per-candidate analysis state."""
        return {
            field: deepcopy(getattr(self, field))
            for field in _CANDIDATE_ATTEMPT_STATE_FIELDS
        }


    def _restore_candidate_attempt_state(self, state):
        """Restore mutable per-candidate state without changing failure/success history."""
        for field, value in state.items():
            setattr(self, field, deepcopy(value))


    def _run_candidate(self, identities, label):
        """Run a candidate with bounded real attempts and isolated per-attempt state.

        Retry only explicitly retryable CandidateIncomplete failures. ProviderFailure
        remains terminal. Failed attempts leave no partial findings or other mutable
        candidate state behind. Attempt/history memos persist across attempts.
        A failure is recorded with a bounded, redacted detail and is NOT forgotten:
        run() fails Stage 2 if any attempted identity is still unresolved at the end.
        """
        for identity in identities:
            if identity not in self.attempted_function_memo:
                self.attempted_function_memo.append(identity)

        baseline = self._capture_candidate_attempt_state()
        last_detail = "candidate analysis did not complete"
        attempts_used = 0

        for attempt in range(self.MAX_CANDIDATE_ATTEMPTS):
            attempts_used += 1

            # Every attempt starts from the same pre-attempt baseline, not from
            # partial state left by a previous failed attempt.
            self._restore_candidate_attempt_state(baseline)

            try:
                self._function_analysis_init()

            except ProviderFailure as exc:
                # Provider failures are terminal and must never trigger another attempt.
                last_detail = scrub_error(f"{type(exc).__name__}: {exc}")
                break

            except Exception as exc:  # noqa: BLE001 - model/tool failures are per-candidate
                last_detail = scrub_error(f"{type(exc).__name__}: {exc}")

                retryable = (
                    isinstance(exc, CandidateIncomplete)
                    and exc.retryable
                )

                if retryable and attempt + 1 < self.MAX_CANDIDATE_ATTEMPTS:
                    continue

                break

            else:
                # Success: retain this attempt's state and clear earlier unresolved failures.
                for identity in identities:
                    self.unresolved_failures.pop(identity, None)
                    if identity not in self.examined_function_memo:
                        self.examined_function_memo.append(identity)
                return None

        # Restore the original state after total failure. In particular, findings
        # produced during an unsuccessful attempt must not leak into later candidates.
        self._restore_candidate_attempt_state(baseline)

        for identity in identities:
            self.failed_function_memo[identity] = (
                self.failed_function_memo.get(identity, 0) + attempts_used
            )
            self.unresolved_failures[identity] = last_detail

        print(
            f"         ✗ Analysis of {label} failed ({last_detail}); "
            f"{attempts_used} attempt(s) used "
            f"(maximum {self.MAX_CANDIDATE_ATTEMPTS})."
        )
        return last_detail

    def _raise_if_unresolved_failures(self):
        """Fail closed: attempted candidates that never recovered mean the analysis is incomplete, whatever else succeeded."""
        if not self.unresolved_failures:
            return
        total, failed = len(self.attempted_function_memo), list(self.unresolved_failures.items())
        head = (f"Stage 2 (Function Analysis) incomplete: {len(failed)} of {total} attempted candidate(s) failed "
                f"and were not recovered: ")
        parts, used = [], len(head)
        # Few failures get more room for the real reason; many get a short one each. Total stays within the worker's 500.
        room = max(70, min(200, (430 - len(head)) // len(failed) - len(failed[0][0]) - 4))
        for n, (identity, detail) in enumerate(failed):
            piece = f"{identity} ({detail[:room]})"
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
        result = self.reasoning_agent.query_text(prompt)
        self.task_tree = result

        logging.info(f"Function call info summary: {json.dumps(self.function_call_info_summary)}")
        logging.info(f"Current understanding: {self.understanding_result}")
        logging.info(f"Task tree: {self.task_tree}")

        for i in range(5):
            try:
                self._select_task()
                self._perform_task()
                self._update_current_understanding()
                self._update_task_tree()
                self._update_potentially_vulnerable_function()
                if i > 0:
                    check_prompt = self.function_prompts.check_analysis_adequacy_alt
                    check_prompt += "Current understanding:" + self.understanding_result
                    result = self.organization_agent.query_text(check_prompt)
                    if 'yes' in result.lower():
                        break
            except ProviderFailure:
                raise                      # never swallowed: it would leave the transaction understanding silently short
            except CandidateIncomplete:
                raise                      # candidate-level failure must propagate
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
            'ranking_problem': self.ranking_problem,
            'potentially_vulnerable_functions': self.potentially_vulnerable_functions,
            "transaction_understanding": self.understanding_result,
            'functions_to_be_inspected': self.functions_to_be_inspected,
        }

        return result
