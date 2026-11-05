"""Run-local ABI context bound to verified bytecode at the transaction block.

No selector renaming, proxy inference, raw errors or persisted cross-run cache.
Only the operator chooses the public RPC used for historical identity checks.
"""
import hashlib
from contextlib import contextmanager
import json
import re
import time
import threading
import httpx
from eth_utils import keccak
try:
    from .rpc_transport import public_post, RPCDestinationError
except ImportError:
    from rpc_transport import public_post, RPCDestinationError

ADDRESS = re.compile(r"0x[0-9a-f]{40}")
SELECTOR = re.compile(r"0x[0-9a-f]{8}")
HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})+")
MAX_BYTES = 2 * 1024 * 1024


def canonical_type(value, depth=0):
    if depth > 32 or not isinstance(value, dict):
        raise ValueError('Invalid ABI type')
    kind = value.get('type')
    if not isinstance(kind, str) or len(kind) > 256:
        raise ValueError('Invalid ABI type')
    if kind.startswith('tuple'):
        return '(' + ','.join(canonical_type(item, depth + 1) for item in value['components']) + ')' + kind[5:]
    return kind


class VerifiedABIContext:
    def __init__(self, chain_id, block_number, endpoint, *, transport=None, post=public_post,
                 clock=time.monotonic, time_budget=30, max_contracts=8):
        self.chain_id, self.block_number, self.endpoint = chain_id, block_number, endpoint
        self.transport, self.post, self.clock = transport, post, clock
        self.time_budget, self.max_contracts = time_budget, max_contracts
        self.source_cache = {}
        self.cache = {}
        self.lock = threading.RLock()
        self.limited = False
        self._budgets = {kind: {'spent': 0.0, 'started': None, 'depth': 0}
                         for kind in ('lookup', 'source')}

    @contextmanager
    def _charge(self, kind):
        # Callers hold the run-local lock. Nested work is charged once, while
        # time between provider operations (including model calls) is excluded.
        state = self._budgets[kind]
        if state['depth'] == 0:
            state['started'] = self.clock()
        state['depth'] += 1
        try:
            yield
        finally:
            state['depth'] -= 1
            if state['depth'] == 0:
                state['spent'] += max(0.0, self.clock() - state['started'])
                state['started'] = None

    def _budget_remaining(self, kind):
        state = self._budgets[kind]
        active = max(0.0, self.clock() - state['started']) if state['started'] is not None else 0.0
        remaining = self.time_budget - state['spent'] - active
        if remaining <= 0:
            raise TimeoutError()
        return min(5.0, remaining)

    def _remaining(self):
        return self._budget_remaining('lookup')

    def _contract(self, address):
        source_url = ('https://sourcify.dev/server/v2/contract/' + str(self.chain_id) + '/' + address
                      + '?fields=abi,runtimeBytecode.onchainBytecode')
        with httpx.Client(transport=self.transport, trust_env=False, follow_redirects=False) as client:
            with client.stream('GET', source_url, timeout=self._remaining()) as response:
                if response.status_code == 429:
                    self.limited = True
                    return {'status': 'provider_limited'}
                if response.status_code != 200:
                    return {'status': 'source_unavailable'}
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    self._remaining()
                    size += len(chunk)
                    if size > MAX_BYTES:
                        return {'status': 'source_too_large'}
                    chunks.append(chunk)
                source = json.loads(b''.join(chunks))
        if (not isinstance(source, dict) or str(source.get('chainId')) != str(self.chain_id)
                or str(source.get('address', '')).lower() != address
                or source.get('runtimeMatch') != 'exact_match'):
            return {'status': 'source_unverified'}
        code = (source.get('runtimeBytecode') or {}).get('onchainBytecode')
        abi = source.get('abi')
        if (not isinstance(code, str) or not HEX.fullmatch(code) or not isinstance(abi, list)
                or len(abi) > 2048):
            return {'status': 'source_unverified'}
        request = [{'jsonrpc': '2.0', 'id': 1, 'method': 'eth_chainId', 'params': []},
                   {'jsonrpc': '2.0', 'id': 2, 'method': 'eth_getCode', 'params': [address, self.block_number]}]
        raw = self.post(self.endpoint, json.dumps(request).encode(), timeout=self._remaining())
        self._remaining()
        replies = json.loads(raw)
        if not isinstance(replies, list) or len(replies) != 2:
            return {'status': 'rpc_unverified'}
        by_id = {item.get('id'): item for item in replies if isinstance(item, dict)}
        if set(by_id) != {1, 2} or any(item.get('error') for item in by_id.values()):
            return {'status': 'rpc_unverified'}
        network = by_id[1].get('result')
        historical = by_id[2].get('result')
        if (not isinstance(network, str) or int(network, 16) != self.chain_id
                or not isinstance(historical, str) or code.lower() != historical.lower()):
            return {'status': 'bytecode_mismatch'}
        signatures = {}
        for entry in abi:
            if not isinstance(entry, dict) or entry.get('type') != 'function':
                continue
            name = entry.get('name')
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*', name):
                continue
            signature = name + '(' + ','.join(canonical_type(v) for v in entry['inputs']) + ')'
            selector = '0x' + keccak(text=signature).hex()[:8]
            signatures.setdefault(selector, []).append((signature, entry))
        return {'status': 'verified', 'signatures': signatures, 'address': address,
                'chain_id': self.chain_id, 'block_number': self.block_number,
                'scope': 'block_end_state', 'source': 'sourcify_exact_runtime_match',
                'source_url': source_url,
                'runtime_sha256': hashlib.sha256(bytes.fromhex(code[2:])).hexdigest(),
                'abi_sha256': hashlib.sha256(json.dumps(abi, sort_keys=True).encode()).hexdigest()}

    def _source_remaining(self):
        return self._budget_remaining('source')

    def source_for(self, address, selector):
        """Return a verified main compilation unit, never a guessed function body."""
        with self.lock:
            identity = self.lookup(address, selector)
            if identity.get("status") != "verified":
                return {"status": identity.get("status", "source_unavailable")}
            address = address.lower()
            if address in self.source_cache:
                return self.source_cache[address]
            if self.limited:
                return {"status": "provider_limited"}
            try:
                with self._charge('source'):
                    result = self._source_document(address, identity)
            except TimeoutError:
                result = {"status": "source_budget_exhausted"}
            except Exception:
                result = {"status": "source_unavailable"}
            self.source_cache[address] = result
            return result

    def _source_document(self, address, identity):
        url = ('https://sourcify.dev/server/v2/contract/' + str(self.chain_id) + '/' + address
               + '?fields=sources,compilation,abi,runtimeBytecode.onchainBytecode')
        with httpx.Client(transport=self.transport, trust_env=False, follow_redirects=False) as client:
            with client.stream('GET', url, timeout=self._source_remaining()) as response:
                if response.status_code == 429:
                    self.limited = True
                    return {"status": "provider_limited"}
                if response.status_code != 200:
                    return {"status": "source_unavailable"}
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    self._source_remaining()
                    size += len(chunk)
                    if size > MAX_BYTES:
                        return {"status": "source_size_limit"}
                    chunks.append(chunk)
                source = json.loads(b''.join(chunks))
        code = (source.get('runtimeBytecode') or {}).get('onchainBytecode')
        if (str(source.get('chainId')) != str(self.chain_id)
                or str(source.get('address', '')).lower() != address
                or source.get('runtimeMatch') != 'exact_match'
                or not isinstance(code, str) or not HEX.fullmatch(code)
                or hashlib.sha256(bytes.fromhex(code[2:])).hexdigest() != identity['runtime_sha256']
                or hashlib.sha256(json.dumps(source.get('abi'), sort_keys=True).encode()).hexdigest() != identity['abi_sha256']):
            return {'status': 'source_binding_mismatch'}
        qualified = (source.get('compilation') or {}).get('fullyQualifiedName')
        if not isinstance(qualified, str) or ':' not in qualified:
            return {'status': 'source_main_unavailable'}
        path = qualified.rsplit(':', 1)[0]
        content = ((source.get('sources') or {}).get(path) or {}).get('content')
        if not isinstance(content, str) or not content.strip():
            return {'status': 'source_main_unavailable'}
        encoded = content.encode('utf-8')
        if len(encoded) > 65536:
            return {'status': 'source_size_limit'}
        digest = hashlib.sha256(encoded).hexdigest()
        return {'status': 'verified', 'source_url': url, 'source_sha256': digest,
                'scope': 'verified_main_compilation_unit', 'block_number': self.block_number,
                'runtime_sha256': identity['runtime_sha256'],
                'limitations': ['Imported dependencies are not included; this is not transaction prestate replay.'],
                'sources': [{'path': path, 'source_code': content, 'source_sha256': digest,
                             'scope': 'verified_main_compilation_unit'}]}

    def lookup(self, address, selector):
        with self.lock:
            with self._charge('lookup'):
                return self._lookup(address, selector)

    def _lookup(self, address, selector):
        address = address.lower() if isinstance(address, str) else ''
        if not ADDRESS.fullmatch(address) or not isinstance(selector, str) or not SELECTOR.fullmatch(selector):
            return {'status': 'invalid_target'}
        if not self.endpoint:
            return {'status': 'disabled'}
        if not isinstance(self.block_number, str) or not re.fullmatch(r'0x[0-9a-fA-F]+', self.block_number):
            return {'status': 'block_unverified'}
        if address not in self.cache:
            if self.limited:
                return {'status': 'provider_limited'}
            if len(self.cache) >= self.max_contracts:
                return {'status': 'budget_exhausted'}
            try:
                self._remaining()
                self.cache[address] = self._contract(address)
            except RPCDestinationError as error:
                if error.status_code == 429:
                    self.limited = True
                self.cache[address] = {"status": "provider_limited" if self.limited else "rpc_unavailable"}
            except TimeoutError:
                self.cache[address] = {'status': 'budget_exhausted'}
            except Exception:
                # No endpoint URLs, credential strings or provider body escapes.
                self.cache[address] = {'status': 'lookup_unavailable'}
        result = self.cache[address]
        if result['status'] != 'verified':
            return dict(result)
        matches = result['signatures'].get(selector, [])
        if len(matches) != 1:
            return {'status': 'selector_not_found' if not matches else 'ambiguous_selector'}
        signature, abi = matches[0]
        output = {**{k: v for k, v in result.items() if k != 'signatures'},
                  'selector': selector, 'signature': signature, 'abi': abi}
        if address in self.source_cache:
            output['source_binding'] = {key: value for key, value in self.source_cache[address].items() if key != 'sources'}
        return output
