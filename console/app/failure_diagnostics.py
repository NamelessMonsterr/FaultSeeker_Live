"""Safe failure locations and retrieval shapes, excluding messages, locals and bodies."""
import os

OPERATIONS = {'request', 'function_call', 'children_calls', 'source_code', 'balance_change', 'trace_path'}
REASONS = {'ambiguous_target', 'invalid_target_shape', 'invalid_request_shape',
           'invalid_trace_path', 'trace_path_out_of_bounds', 'malformed_trace_node',
           'trace_identity_mismatch', 'unobserved_target', 'source_unavailable',
           'balance_not_recorded', 'unexpected_exception', 'unsupported_request_kind'}
TYPES = {'str', 'list', 'tuple', 'dict', 'int', 'float', 'bool', 'NoneType'}
FIELDS = {'function', 'function_name', 'address', 'function_call', 'children_calls', 'source_code', 'balance_change'}


def safe_retrieval_record(record):
    if not isinstance(record, dict):
        return None
    result = {'operation': record.get('operation') if isinstance(record.get('operation'), str) and record['operation'] in OPERATIONS else 'request',
              'status': 'unavailable',
              'reason': record.get('reason') if isinstance(record.get('reason'), str) and record['reason'] in REASONS else 'unexpected_exception'}
    raw = record.get('request_shape')
    if isinstance(raw, dict):
        value = {'type': raw.get('type') if isinstance(raw.get('type'), str) and raw['type'] in TYPES else 'other'}
        for key in ('length', 'unknown_field_count'):
            if type(raw.get(key)) is int and 0 <= raw[key] <= 10**9:
                value[key] = raw[key]
        if isinstance(raw.get('known_fields'), list):
            value['known_fields'] = [key for key in raw['known_fields'] if isinstance(key, str) and key in FIELDS]
        if isinstance(raw.get('item_types'), list):
            value['item_types'] = [kind if kind in TYPES else 'other' for kind in raw['item_types'][:8] if isinstance(kind, str)]
        result['request_shape'] = value
    path = record.get('path')
    if isinstance(path, list) and len(path) <= 4096 and all(type(i) is int and abs(i) <= 2**31 for i in path):
        result['path'] = list(path)
    if type(record.get('path_length')) is int and 0 <= record['path_length'] <= 10**9:
        result['path_length'] = record['path_length']
    return result


def failure_diagnostics(error):
    frames = []
    tb = error.__traceback__
    while tb is not None:
        code = tb.tb_frame.f_code
        frames.append({'file': os.path.basename(code.co_filename), 'function': code.co_name, 'line': tb.tb_lineno})
        tb = tb.tb_next
    result = {'exception_type': type(error).__name__, 'frames': frames[-24:]}
    retrieval = getattr(error, 'diagnostics', None)
    if isinstance(retrieval, dict):
        result['retrieval'] = safe_retrieval_record(retrieval)
    return result
