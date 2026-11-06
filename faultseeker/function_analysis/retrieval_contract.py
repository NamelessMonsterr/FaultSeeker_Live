"""Model-to-trace retrieval contracts. Missing evidence never means an empty trace."""
from copy import deepcopy
import hashlib
import json
import re


def shape(value):
    result = {'type': type(value).__name__}
    if isinstance(value, (str, list, tuple, dict)):
        result['length'] = len(value)
    if isinstance(value, dict):
        known = {'function', 'function_name', 'address', 'function_call', 'children_calls', 'source_code', 'balance_change'}
        result['known_fields'] = sorted(key for key in value if key in known)
        result['unknown_field_count'] = len(value) - len(result['known_fields'])
    if isinstance(value, (list, tuple)):
        result['item_types'] = [type(item).__name__ for item in value[:8]]
    return result


class RetrievalContractError(ValueError):
    kind = 'retrieval_contract'

    def __init__(self, reason, request=None, path=None):
        self.diagnostics = {'reason': reason, 'request_shape': shape(request)}
        if isinstance(path, (list, tuple)):
            self.diagnostics['path_length'] = len(path)
            if len(path) <= 4096 and all(type(i) is int and abs(i) <= 2**31 for i in path):
                self.diagnostics['path'] = list(path)
        # No raw model text, exception values, source bodies or credentials.
        super().__init__('Retrieval contract: ' + reason)


def target(spec):
    if isinstance(spec, dict):
        function = spec.get('function', spec.get('function_name'))
        address = spec.get('address')
        if 'function' in spec and 'function_name' in spec and spec['function'] != spec['function_name']:
            raise RetrievalContractError('ambiguous_target', spec)
    elif isinstance(spec, (list, tuple)) and len(spec) == 2:
        address, function = spec
    elif isinstance(spec, str) and ('::' in spec or '_' in spec):
        function, address = spec.rsplit('::' if '::' in spec else '_', 1)
    else:
        raise RetrievalContractError('invalid_target_shape', spec)
    if (not isinstance(address, str) or not re.fullmatch(r'0x[0-9a-fA-F]{40}', address, re.I)
            or not isinstance(function, str) or not function.strip() or len(function) > 256):
        raise RetrievalContractError('invalid_target_shape', spec)
    return function, address.lower()


def requests(value):
    if isinstance(value, (dict, str)):
        return [value]
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and isinstance(value[0], str) and re.fullmatch(r'0x[0-9a-fA-F]{40}', value[0], re.I):
            return [value]
        return value
    raise RetrievalContractError('invalid_request_shape', value)


class RetrievalContractMixin:
    def _recover_finding_update(self, update):
        """Repair an unobserved finding once; never fabricate trace bindings.

        Other contract errors and provider failures still propagate. Rejected
        replies are represented by safe shapes and content digests, not raw
        model text or credentials. Unresolved replies remain explicitly partial.
        """
        agent = self.organization_agent
        original_query = agent.query
        stored_query = vars(agent).get('query')
        had_query = 'query' in vars(agent)
        before = deepcopy(self.potentially_vulnerable_functions)
        captured = {}
        repair = False
        record = None

        def query(prompt, *args, **kwargs):
            if repair:
                keys, size = [], 0
                memo = getattr(self, 'tx_analysis', {}).get('function_call_loc_memo', {})
                for key in memo:
                    if not isinstance(key, str) or '::' not in key:
                        continue
                    candidate = key.replace('::', '_', 1)
                    if size + len(candidate) > 4000:
                        break
                    keys.append(candidate)
                    size += len(candidate)
                prompt += ('\nA previous reply contained a target absent from the observed trace. '
                    'Recheck the original task using observed function/address identities; '
                    'do not guess names or substitute addresses. Return findings only when '
                    'supported; {} means no supported findings, not a statement of safety. '
                    'Observed target examples (not an exhaustive list): ' + json.dumps(keys))
            result = original_query(prompt, *args, **kwargs)
            captured['reply'] = result
            return result

        agent.query = query
        try:
            for attempt in range(2):
                captured.clear()
                try:
                    value = update()
                except RetrievalContractError as error:
                    if error.diagnostics.get('reason') != 'unobserved_target':
                        raise
                    self.potentially_vulnerable_functions = deepcopy(before)
                    digest = hashlib.sha256(json.dumps(captured.get('reply'), sort_keys=True,
                        default=lambda value: type(value).__name__).encode('utf-8')).hexdigest()
                    record = {'operation': 'function_call', 'reason': 'unobserved_target',
                              'status': 'rejected', 'attempt': attempt+1,
                              'reply_sha256': digest, 'request_shape': error.diagnostics['request_shape']}
                    observations = getattr(self, 'rejected_finding_observations', [])
                    self.finding_rejection_count = getattr(self, 'finding_rejection_count', 0) + 1
                    self.rejected_finding_observations_omitted = getattr(self, 'rejected_finding_observations_omitted', 0) + max(0, len(observations)+1-100)
                    self.rejected_finding_observations = (observations + [record])[-100:]
                    reserve = getattr(self, '_reserve_finding_repair', lambda: True)
                    if attempt == 0 and reserve():
                        repair = True
                        continue
                    record['status'] = 'unresolved'
                    self._retrieval_unavailable('function_call', error)
                    return None
                else:
                    if record is not None:
                        record['status'] = 'recovered'
                    return value
        except Exception:
            if record is not None and record['status'] == 'rejected':
                record['status'] = 'repair_failed'
            raise
        finally:
            if had_query:
                agent.query = stored_query
            else:
                del agent.query

    def _resolve_trace_node(self, depth, function_name, address=None):
        if (not isinstance(depth, (list, tuple)) or not depth or len(depth) > 4096
                or any(type(i) is not int for i in depth)):
            raise RetrievalContractError('invalid_trace_path', depth, depth)
        current = getattr(self, 'trace', None)
        for position, index in enumerate(depth):
            if not isinstance(current, list) or index < 0 or index >= len(current):
                raise RetrievalContractError('trace_path_out_of_bounds', depth, depth)
            node = current[index]
            if not isinstance(node, dict) or not isinstance(node.get('children'), list):
                raise RetrievalContractError('malformed_trace_node', depth, depth)
            current = node['children']
        if (not isinstance(function_name, str) or not isinstance(node.get('function'), str)
                or node['function'].lower() != function_name.lower()
                or (address is not None and (not isinstance(node.get('address'), str)
                    or node['address'].lower() != address.lower()))):
            raise RetrievalContractError('trace_identity_mismatch', {'function': function_name, 'address': address}, depth)
        return node

    def _get_function_call_depth(self, function_call):
        function, address = target(function_call)
        calls = self._observed_calls(function, address)
        for call in calls:
            self._resolve_trace_node(call.get('depth'), function, address)
        return max(len(call['depth']) for call in calls)

    def _retrieve_function_call_by_depth(self, depth, function_name, get_children=False, address=None):
        node = self._resolve_trace_node(depth, function_name, address)
        def summarized(value):
            result = deepcopy(value)
            children = result['children']
            if any(not isinstance(child, dict) or not isinstance(child.get('children'), list) for child in children):
                raise RetrievalContractError('malformed_trace_node', depth, depth)
            result['children'] = [f"[{child.get('call_type')}]{child.get('address')}::{child.get('function')}({child.get('params')})"
                                  for child in children if child.get('function')]
            return result
        if not get_children:
            return summarized(node)
        output = []
        for child in node['children']:
            if not isinstance(child, dict) or not isinstance(child.get('children'), list):
                raise RetrievalContractError('malformed_trace_node', depth, depth)
            if child.get('function'):
                if child['function'] == function_name and child.get('call_type') == 'delegatecall':
                    output.extend(summarized(c) for c in child['children'])
                elif child.get('type') != 'return':
                    output.append(summarized(child))
        return output

    def _observed_calls(self, function, address):
        info = getattr(self, 'tx_analysis', {})
        memo = info.get('function_call_loc_memo', {}) if isinstance(info, dict) else {}
        if not isinstance(memo, dict):
            raise RetrievalContractError('invalid_request_shape', memo)
        key = f'{function}::{address}'.lower()
        calls = memo.get(key)
        if calls is None:
            summary = getattr(self, 'function_call_info_summary', {})
            if (isinstance(summary, dict) and str(summary.get('function', '')).lower() == function.lower()
                    and str(summary.get('address', '')).lower() == address.lower()):
                calls = summary.get('calls')
        if not isinstance(calls, list) or not calls or any(not isinstance(c, dict) for c in calls):
            raise RetrievalContractError('unobserved_target', {'function': function, 'address': address})
        return calls

    def _retrieve_function_calls(self, function_call):
        function, address = target(function_call)
        # Every occurrence is bound to its actual trace frame, including summary
        # cache hits. An occurrence's path, not its params, establishes identity.
        return [self._retrieve_function_call_by_depth(call.get('depth'), function, address=address)
                for call in self._observed_calls(function, address)]

    def _retrieve_children_calls(self, function_name, address):
        function, address = target({'function': function_name, 'address': address})
        result = []
        for call in self._observed_calls(function, address):
            result.extend(self._retrieve_function_call_by_depth(call.get('depth'), function,
                          get_children=True, address=address))
        return result

    def _prepare_children_call_memo(self, function_calls):
        for key in function_calls:
            function, address = target(key)
            group = self.functions_to_be_inspected.get(key)
            if not isinstance(group, dict):
                raise RetrievalContractError('unobserved_target', key)
            for call in group.get('calls', []):
                node = self._resolve_trace_node(call.get('depth'), function, address)
                self._update_children_call_memo(node['children'], function)
            self.children_call_memo[key] = self.children_call_memo_single
            self.children_call_memo_single = {}

    def _retrieval_unavailable(self, operation, error):
        record = {'operation': operation, 'status': 'unavailable', **error.diagnostics}
        self.retrieval_unavailable_count = getattr(self, 'retrieval_unavailable_count', 0) + 1
        issues = getattr(self, 'retrieval_diagnostics', [])
        self.retrieval_diagnostics = (issues + [record])[-100:]
        return record

    def _retrieve_additional_info(self, additional_info):
        prompt = self.function_prompts.retrieve_additional_info
        prompt += ('\nReturn only a JSON object using the exact observed function/address identifiers. '
                   'Use this schema, omitting unneeded fields: '
                   '{"function_call": [{"address": "observed address", "function": "observed function"}], '
                   '"children_calls": [{"address": "observed address", "function": "observed function"}], '
                   '"source_code": [{"address": "observed address", "function": "observed function"}], '
                   '"balance_change": ["observed address"]}. '
                   'Return {} if no additional information is requested. Do not return acknowledgements or status metadata. '
                   'An unavailable retrieval is missing evidence, not proof of absence or safety.\n')
        prompt += f'Current available information:{self.function_call_info_summary}\n'
        prompt += f'Additional information to be reorganized:{additional_info}'
        generated = self.generation_agent.query(prompt)
        output = {'retrieval_status': []}
        allowed = ('function_call', 'children_calls', 'source_code', 'balance_change')
        if not isinstance(generated, dict) or (generated and not any(k in generated for k in allowed)):
            error = RetrievalContractError('invalid_request_shape', generated)
            output['retrieval_status'].append(self._retrieval_unavailable('request', error))
            return output
        if any(key not in allowed for key in generated):
            output['retrieval_status'].append(self._retrieval_unavailable('request',
                RetrievalContractError('unsupported_request_kind', generated)))
        for operation in allowed:
            if operation not in generated:
                continue
            try:
                specs = requests(generated[operation]) if operation != 'balance_change' else generated[operation]
                if not isinstance(specs, (list, tuple)):
                    raise RetrievalContractError('invalid_request_shape', specs)
            except RetrievalContractError as error:
                output['retrieval_status'].append(self._retrieval_unavailable(operation, error))
                continue
            for spec in specs:
                try:
                    if operation == 'balance_change':
                        if not isinstance(spec, str) or not re.fullmatch(r'0x[0-9a-fA-F]{40}', spec):
                            raise RetrievalContractError('invalid_request_shape', spec)
                        changes = self.fundflow_analysis.get('balance_change', {})
                        value = {a: deepcopy(v) for a, v in changes.items()
                                 if a.lower() == spec.lower() or (isinstance(v, dict) and spec.lower() in v)}
                        if not value:
                            raise RetrievalContractError('balance_not_recorded', spec)
                        output.setdefault(operation, {}).update(value)
                    else:
                        function, address = target(spec)
                        if operation == 'function_call':
                            value = self._retrieve_function_calls(spec)
                            output.setdefault(operation, []).extend(value)
                        elif operation == 'children_calls':
                            value = self._retrieve_children_calls(function, address)
                            output.setdefault('children_calls (i.e., for {k:v}, v is the children calls of k)', {})[f'{function}::{address}'] = value
                        else:
                            value = self._retrieve_source_code(address, function)
                            if not value:
                                raise RetrievalContractError('source_unavailable', spec)
                            output.setdefault(operation, {})[f'{function}_{address}'] = value
                    output['retrieval_status'].append({'operation': operation,
                        'status': 'available' if value else 'available_empty'})
                except RetrievalContractError as error:
                    output['retrieval_status'].append(self._retrieval_unavailable(operation, error))
        return output
