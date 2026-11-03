"""Run-local ABI context bound to verified bytecode at the transaction block.

No selector renaming, proxy inference, raw errors or persisted cross-run cache.
Only the operator chooses the public RPC used for historical identity checks.
"""
import hashlib
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
        self.deadline = None
        self.time_budget, self.max_contracts = time_budget, max_contracts
        self.cache = {}
        self.lock = threading.RLock()
        self.limited = False

    def _remaining(self):
        if self.deadline is None:
            self.deadline = self.clock() + self.time_budget
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise TimeoutError()
        return min(5.0, remaining)

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

    def lookup(self, address, selector):
        with self.lock:
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
        return {**{k: v for k, v in result.items() if k != 'signatures'},
                'selector': selector, 'signature': signature, 'abi': abi}
