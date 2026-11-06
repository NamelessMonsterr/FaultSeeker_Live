"""
SignalExtractor — Deterministic pre-LLM signal layer.

Parses the execution trace and token flow data to extract structured,
numeric signals for the five most common exploit categories in the dataset:

  1. Reentrancy
  2. Flash Loan Attack
  3. Price Manipulation
  4. Access Control Bypass
  5. Profit Extraction / Arbitrary External Call

Zero LLM calls. All logic is pure Python.
"""

from __future__ import annotations
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

# Absolute path to the replay cache — anchored to this file so it's CWD-independent.
# signal_extractor.py is at faultseeker/forensics/signal_extractor.py
# Project root is two directories up.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_REPLAY_CACHE_DIR = os.path.join(_PROJECT_ROOT, 'data', 'cache', 'replay')

# ── Keyword tables ─────────────────────────────────────────────────────────────
_FLASH_BORROW = {
    'flashloan', 'flashloan2', 'flash_loan', 'flashswap', 'flash_swap',
    'borrowflashloan', 'executeoperation', 'receiveloan', 'onflashloan',
    'maxflashloan', 'flashfee',
}
_FLASH_CALLBACK = {
    'uniswapv2call', 'uniswapv3swapcallback', 'pancakecall',
    'balancerflashloanreceived', 'oncredit', 'onflashloan',
    'executeflashloan', 'callbackfunction', 'receiveloan', 'executeoperation',
}
_PRICE_READ = {
    'getreserves', 'slot0', 'getamountout', 'getamountsin',
    'latesttickandliquidity', 'consult', 'observe', 'quote',
    'latesttickinfo', 'getpool',
}
_STATE_WRITE = {
    'transfer', 'transferfrom', 'mint', 'burn', 'swap',
    'setbalance', 'updatebalance', 'setreserves',
}
_PRIVILEGED = {
    'transferownership', 'setowner', 'initialize', 'upgradeto',
    'upgradetoandcall', 'setimplementation', 'setproxy',
    'addminter', 'setadmin', 'setgov', 'setrole', 'grantadmin',
    'selfdestruct', 'suicide', 'emergencywithdraw', 'withdraw',
    'setoperator', 'setminter', 'setburner', 'setfee',
    'pause', 'unpause', 'setreward', 'setvault', 'setallowance',
    'claimreward', 'settreasury', 'setstrategist', 'setkeeper',
}
_ACCESS_FNS = {
    'owner', 'admin', 'isgov', 'isowner', 'hasrole',
    'onlyowner', 'onlyadmin',
}

# hex-encoded 4-byte selector pattern allowing trailing args: 0xa9059cbb or 0xa9059cbb()
_HASH_FN_RE = re.compile(r'^0x[0-9a-fA-F]{8}(?:$|\()')

# Canonical 4-byte selector -> lowercase name hint. 4-byte selectors are not
# unique across contracts (collisions exist), so these aliases are UNVERIFIED
# naming hints only: they let the name-based detectors below look at
# selector-only calls instead of going blind, and at worst a collision adds
# analysis scrutiny. Aliases never filter, rank, or drop any call, and the
# raw undecoded-selector evidence path (_check_hashed_functions) is unchanged.
_SELECTOR_ALIASES = {
    '0x0902f1ac': 'getreserves',   # UniswapV2Pair.getReserves
    '0x3850c7bd': 'slot0',         # UniswapV3Pool.slot0
    '0xa9059cbb': 'transfer',      # ERC20.transfer
    '0x23b872dd': 'transferfrom',  # ERC20.transferFrom
    '0x095ea7b3': 'approve',       # ERC20.approve
    '0x022c0d9f': 'swap',          # UniswapV2Pair.swap
    '0x6a627842': 'mint',          # UniswapV2Pair.mint
    '0x89afcb44': 'burn',          # UniswapV2Pair.burn
    '0x70a08231': 'balanceof',     # ERC20.balanceOf
}


# ── Output dataclass ───────────────────────────────────────────────────────────
@dataclass
class SignalBundle:
    txn_hash: str = ''
    chain: str = ''

    # Reentrancy
    reentrancy_score: float = 0.0          # 0.0–1.0; ≥ 0.45 = actionable signal
    reentrancy_paths: list = field(default_factory=list)
    reentrancy_fallback_mode: bool = False
    reentrancy_detection_threshold: float = 0.45
    reentrancy_confidence_tier: str = 'NOT_REENTRANCY'

    # Flash Loan
    flash_loan_detected: bool = False
    flash_callback_detected: bool = False
    flash_profit_eth: float | None = None  # unavailable without measured net native flow

    # Price Manipulation
    price_read_before_write: bool = False  # getReserves before swap in same subtree
    price_delta_ratio: float | None = None # unavailable without reserve/price measurements
    price_read_write_sequences: int = 0

    # Access Control
    access_control_bypass: bool = False
    access_control_review_required: bool = False
    delegatecall_observed: bool = False
    delegatecall_to_created_contract: bool = False
    undecoded_call_followed_by_state_write: bool = False
    privileged_calls: list = field(default_factory=list)
    created_contract_in_privileged_call: bool = False

    # Undecoded selectors do not establish whether source is available.
    hashed_fn_calls: list = field(default_factory=list)   # 0xABCD1234-style calls
    hashed_fn_count: int = 0                               # total count
    closed_source_state_change: bool = False               # hashed fn + token transfer

    # Profit Extraction / Arbitrary External Call
    profit_extraction_eth: float | None = None  # never inferred from gross/token transfers
    largest_call_value_eth: float = 0.0   # observed gross call value, not profit
    large_transfer_to_eoa: bool = False    # big Transfer to plain wallet at end of tx
    arbitrary_external_call: bool = False  # delegatecall into newly created contract

    # Arithmetic / Inflation
    inflation_pattern_observed: bool = False
    inflation_attack: bool = False  # requires evidence beyond function-name co-occurrence

    # Multi-transaction context flags
    single_transfer_only: bool = False  # ONLY a bare transfer() — likely donation step in multi-tx exploit

    # Selector alias hints applied while extracting (unverified canonical guesses)
    selector_alias_hints_applied: int = 0

    # Convenience
    top_vuln_hints: list = field(default_factory=list)   # ordered list of suspected types
    raw: dict = field(default_factory=dict)              # full evidence for LLM context


# ── Extractor ──────────────────────────────────────────────────────────────────
class SignalExtractor:
    """
    Walk txn_seq + tx_analysis structures and populate a SignalBundle.

    Usage:
        signals = SignalExtractor(txn_seq, tx_analysis, txn_hash, chain).run()
    """

    def __init__(self, txn_seq: dict, tx_analysis: dict,
                 txn_hash: str = '', chain: str = '') -> None:
        self.txn_seq = txn_seq or {}
        self.tx_analysis = tx_analysis or {}
        self.txn_hash = txn_hash
        self.chain = chain
        self.signals = SignalBundle(txn_hash=txn_hash, chain=chain)

        # Flat trace list (list of dicts, each with depth, function, call_type, …)
        self.observed_flat: list[dict] = tx_analysis.get('flatten_trace', [])
        # A successful child of a reverted parent has no committed effects.
        # Retain the original observations, but exclude explicitly failed
        # subtrees from the ordering/state-change heuristics below.
        def failed(call):
            return (bool(call.get('error')) or call.get('success') is False
                    or call.get('status') in (0, '0', '0x0', 'reverted', 'failed'))
        def path(call):
            value = call.get('depth')
            return tuple(value) if isinstance(value, (list, tuple)) and all(type(i) is int for i in value) else None
        failed_paths = {path(call) for call in self.observed_flat if failed(call)} - {None, ()}
        self.flat = []
        for call in self.observed_flat:
            location = path(call)
            reverted_parent = location is not None and any(
                location[:size] in failed_paths for size in range(1, len(location)+1))
            if not failed(call) and not reverted_parent:
                self.flat.append(call)
        # Root trace tree
        trace_raw = tx_analysis.get('trace', None)
        self.trace: list[dict] = ([trace_raw] if isinstance(trace_raw, dict)
                                   else (trace_raw or []))
        # Structured canonical trace tree (RPC-backed, strict schema)
        canonical_trace_raw = (
            tx_analysis.get('canonical_trace')
            or self.txn_seq.get('canonical_trace')
            or None
        )
        self.canonical_trace: list[dict] = (
            [canonical_trace_raw] if isinstance(canonical_trace_raw, dict)
            else (canonical_trace_raw or [])
        )
        self.storage_events: list[dict] = (
            tx_analysis.get('storage_events')
            or self.txn_seq.get('storage_events')
            or []
        )
        # Repeated patterns list (from TraceAnalyzer)
        rp = tx_analysis.get('repeated_patterns', {})
        if isinstance(rp, dict):
            self.repeated = rp.get('keys', []) + rp.get('keys_function_only', [])
        else:
            self.repeated = list(rp) if rp else []
        # Created addresses in this tx
        self.created = {a.lower() for a in self.txn_seq.get('created_address', [])}
        # Balance changes  {addr: {token_addr: delta_str}}
        self.balance_change: dict = {}
        # Absolute path to the cast replay cache for this transaction
        self._cast_cache_path = os.path.join(_REPLAY_CACHE_DIR, f'{txn_hash.lower()}.txt')
        self._alias_selectors: set = set()

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _fn(call: dict) -> str:
        return (call.get('function') or '').lower()

    def _fn_hint(self, call: dict) -> str:
        """Raw function name, or an explicitly-unverified canonical alias when
        the name is a bare 4-byte selector present in _SELECTOR_ALIASES. The
        raw 'function' value is never mutated, so undecoded-selector evidence
        (hashed-fn checks) is preserved."""
        name = self._fn(call)
        match = _HASH_FN_RE.match(name)
        if match:
            alias = _SELECTOR_ALIASES.get(name[:10])
            if alias:
                self._alias_selectors.add(name[:10])
                return alias
        return name

    @staticmethod
    def _addr(call: dict) -> str:
        return (call.get('address') or '').lower()

    @staticmethod
    def _val(call: dict) -> float:
        """Return ETH value of a call (hex or decimal string → float)."""
        v = call.get('value', '') or ''
        if not v or v in ('0', '0x0', '0x'):
            return 0.0
        try:
            if str(v).startswith('0x'):
                return int(v, 16) / 1e18
            return float(v) / 1e18
        except Exception:
            return 0.0

    def _walk(self, node: dict, cb, depth: int = 0) -> None:
        """DFS walker — calls cb(node, depth) on every node."""
        cb(node, depth)
        for child in node.get('children', []):
            self._walk(child, cb, depth + 1)

    @staticmethod
    def _node_address(node: dict) -> str:
        return (
            node.get('callee')
            or node.get('to')
            or node.get('address')
            or ''
        ).lower()

    @staticmethod
    def _node_caller(node: dict) -> str:
        return (
            node.get('caller')
            or node.get('from')
            or ''
        ).lower()

    @staticmethod
    def _node_call_type(node: dict) -> str:
        raw = node.get('call_type') or node.get('type') or 'CALL'
        return str(raw).upper()

    @staticmethod
    def _node_selector(node: dict) -> str:
        selector = (node.get('function_selector') or '').lower()
        if selector and selector != '0x':
            return selector

        input_data = (node.get('input') or '').lower()
        if len(input_data) >= 10 and input_data.startswith('0x'):
            return input_data[:10]

        fn_name = (node.get('function') or '').lower()
        if not fn_name:
            return '0x'
        if _HASH_FN_RE.match(fn_name):
            return fn_name[:10]
        fn_name = fn_name.split('(')[0].split('{')[0].strip()
        return fn_name or '0x'

    @staticmethod
    def _normalize_storage_value(value: Any) -> str | None:
        if value is None:
            return None
        raw = str(value).strip().lower()
        if not raw:
            return None
        if raw.startswith('0x'):
            raw = raw[2:]
        if not raw:
            raw = '0'
        try:
            int(raw, 16)
        except ValueError:
            return None
        return '0x' + raw[-64:].zfill(64)

    def _canonical_roots(self) -> list[dict]:
        return self.canonical_trace or self.trace

    def _effective_address(self, node: dict, storage_owner: str = '') -> str:
        """Address whose storage/context is actually being mutated."""
        address = self._node_address(node)
        call_type = self._node_call_type(node)
        if call_type in {'DELEGATECALL', 'CALLCODE'}:
            return (storage_owner or self._node_caller(node) or address).lower()
        return address.lower()

    def _normalized_storage_events(self) -> list[dict]:
        """
        Normalize cached SSTORE events and drop compiler-loop duplicates.

        `pc` is preserved so the scorer can distinguish loops from distinct sites.
        """
        normalized: list[dict] = []
        for raw in self.storage_events:
            if not isinstance(raw, dict):
                continue

            address = str(raw.get('address') or '').lower()
            slot = self._normalize_storage_value(raw.get('slot'))
            if not address or not slot:
                continue

            try:
                depth = int(raw.get('depth', 0))
            except (TypeError, ValueError):
                depth = 0

            try:
                event_index = int(raw.get('event_index', len(normalized)))
            except (TypeError, ValueError):
                event_index = len(normalized)

            normalized.append({
                'address': address,
                'slot': slot,
                'value_before': self._normalize_storage_value(raw.get('value_before')),
                'value_after': self._normalize_storage_value(raw.get('value_after')),
                'pc': raw.get('pc'),
                'depth': depth,
                'call_id': raw.get('call_id'),
                'event_index': event_index,
                'after_external_call': bool(raw.get('after_external_call')),
            })

        normalized.sort(key=lambda item: (item['event_index'], item['depth']))

        deduped: list[dict] = []
        seen: set[tuple] = set()
        for item in normalized:
            if item['pc'] is not None:
                key = (
                    item['address'],
                    item['slot'],
                    item['pc'],
                    item.get('call_id') or item['depth'],
                )
            else:
                key = (
                    item['address'],
                    item['slot'],
                    item.get('call_id') or item['depth'],
                    item['event_index'],
                )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    def _is_reentrancy_guard_slot(self, writes: list[dict]) -> bool:
        """
        Filter common OpenZeppelin-style mutex slots:
        entry/exit toggles using tiny sentinel constants with no nested rewrite.
        """
        if len(writes) < 2:
            return False

        one = '0x' + '0' * 63 + '1'
        two = '0x' + '0' * 63 + '2'

        transitions = [
            (w.get('value_before'), w.get('value_after'))
            for w in writes
            if w.get('value_before') is not None and w.get('value_after') is not None
        ]
        if not transitions:
            return False

        depth_span = max((w['depth'] for w in writes), default=0) - min((w['depth'] for w in writes), default=0)
        if depth_span >= 2:
            return False

        saw_lock = any(before == one and after == two for before, after in transitions)
        saw_reset = any(before == two and after == one for before, after in transitions)
        if not (saw_lock and saw_reset):
            return False

        values = {
            value
            for transition in transitions
            for value in transition
            if value is not None
        }
        if not values.issubset({one, two}):
            return False

        pcs = {w.get('pc') for w in writes if w.get('pc') is not None}
        return len(pcs) <= 2

    # ── signal: Reentrancy ────────────────────────────────────────────────────

    def _check_reentrancy(self) -> None:
        """
        State-first reentrancy detector.

        Hard signals:
          1. write_after_external_call  — SSTORE after a mutating external boundary
          2. repeated_slot_nested       — same slot rewritten across nested frames
          3. write_before_and_after     — state write before and after external call

        Supporting signals:
          4. same_function_reentered    — same (callee, selector) reappears on stack
          5. same_slot_rewritten        — same slot rewritten more than once

        Score:
          write_after_external_call +0.35
          repeated_slot_nested      +0.45
          write_before_and_after    +0.20
          same_function_reentered   +0.25
          same_slot_rewritten       +0.25

        Final score is clamped to 1.0.
        """
        max_depth = 0
        external_calls = 0
        same_contract_reentry = 0
        same_selector_reentry = 0
        same_function_reentered = False
        same_contract_different_selector = False
        nested_depth_reentry = False

        noise_selectors = {'0x095ea7b3', '0xa9059cbb', '0x23b872dd'}

        def _walk_local(
            node: dict,
            ancestor_addrs: tuple[str, ...] = (),
            stack_ids: tuple[tuple[str, str, int, str], ...] = (),
            storage_owner: str = '',
            boundary_count: int = 0,
            root_storage_context: str = '',
            ancestors: frozenset = frozenset(),
        ) -> list:
            nonlocal max_depth
            nonlocal external_calls
            nonlocal same_contract_reentry
            nonlocal same_selector_reentry
            nonlocal same_function_reentered
            nonlocal same_contract_different_selector
            nonlocal nested_depth_reentry

            if id(node) in ancestors:
                raise ValueError('Cyclic trace cannot define reentrancy evidence')
            lineage = ancestors | {id(node)}

            node_depth = node.get('depth')
            if not isinstance(node_depth, int):
                node_depth = len(ancestor_addrs)
            max_depth = max(max_depth, node_depth)

            address = self._node_address(node)
            effective_address = self._effective_address(node, storage_owner)
            selector = self._node_selector(node)
            call_type = self._node_call_type(node)
            is_call = call_type in {'CALL', 'DELEGATECALL', 'CALLCODE'}
            parent_effective_address = ancestor_addrs[-1] if ancestor_addrs else ''
            crossed_external_boundary = (
                is_call
                and bool(parent_effective_address)
                and effective_address != parent_effective_address
            )
            node_boundary_count = boundary_count + (1 if crossed_external_boundary else 0)
            current_root_context = (root_storage_context or effective_address or storage_owner or address).lower()

            if node_depth > 0 and is_call:
                external_calls += 1

            new_stack_ids = stack_ids
            if effective_address and is_call:
                prior_same_addr_boundaries = [
                    prior_boundary
                    for frame_addr, _frame_selector, prior_boundary, _frame_root in stack_ids
                    if frame_addr == effective_address
                ]
                addr_reentered = any(node_boundary_count > prior_boundary for prior_boundary in prior_same_addr_boundaries)

                if addr_reentered:
                    same_contract_reentry += 1
                    nested_depth_reentry = True

                if selector != '0x' and selector not in noise_selectors:
                    selector_hits = [frame for frame in stack_ids if frame[1] == selector]
                    if selector_hits:
                        same_selector_reentry += 1
                    same_function_reentered = same_function_reentered or any(
                        frame_addr == effective_address
                        and frame_selector == selector
                        and node_boundary_count > prior_boundary
                        and frame_root == current_root_context
                        for frame_addr, frame_selector, prior_boundary, frame_root in stack_ids
                    )
                    same_contract_different_selector = same_contract_different_selector or any(
                        frame_addr == effective_address
                        and frame_selector != selector
                        and node_boundary_count > prior_boundary
                        and frame_root == current_root_context
                        for frame_addr, frame_selector, prior_boundary, frame_root in stack_ids
                    )
                    new_stack_ids = stack_ids + ((effective_address, selector, node_boundary_count, current_root_context),)

            new_ancestors = ancestor_addrs + ((effective_address,) if effective_address else ())
            next_storage_owner = effective_address or storage_owner or address
            next_root_context = current_root_context
            children = []
            for child in node.get('children', []):
                child_call_type = self._node_call_type(child)
                child_effective = self._effective_address(child, next_storage_owner)
                if child_call_type in {'DELEGATECALL', 'CALLCODE'}:
                    child_root_context = next_root_context
                elif child_effective and child_effective != effective_address:
                    child_root_context = child_effective
                else:
                    child_root_context = next_root_context
                children.append((
                    child,
                    new_ancestors,
                    new_stack_ids,
                    next_storage_owner,
                    node_boundary_count,
                    child_root_context,
                    lineage,
                ))
            return children

        for root in self._canonical_roots():
            root_effective = self._effective_address(root)
            pending = [(root, (), (), root_effective, 0, root_effective, frozenset())]
            while pending:
                # Reverse child insertion preserves the prior preorder DFS.
                # Ancestor identities are path-local: reused sibling frames
                # remain separate observed calls rather than false cycles.
                pending.extend(reversed(_walk_local(*pending.pop())))

        storage_events = self._normalized_storage_events()
        writes_by_slot: dict[tuple[str, str], list[dict]] = defaultdict(list)
        writes_by_frame: dict[tuple[str, int], list[dict]] = defaultdict(list)

        guard_filtered_slots = 0
        valid_storage_event_count = 0
        repeated_slot_nested = False
        same_slot_rewritten = False
        write_after_external_call = False
        write_before_and_after = False
        suspicious_paths: list[dict] = []

        for event in storage_events:
            writes_by_slot[(event['address'], event['slot'])].append(event)

        for (address, slot), writes in writes_by_slot.items():
            writes.sort(key=lambda item: (item['event_index'], item['depth']))
            if self._is_reentrancy_guard_slot(writes):
                guard_filtered_slots += 1
                continue

            valid_storage_event_count += len(writes)
            for write in writes:
                writes_by_frame[(write['address'], write['depth'])].append(write)

            unique_depths = {write['depth'] for write in writes}
            write_after_external_call = write_after_external_call or any(
                write['after_external_call'] for write in writes
            )
            same_slot_rewritten = same_slot_rewritten or len(writes) >= 2

            if len(writes) >= 2 and unique_depths and (max(unique_depths) - min(unique_depths) >= 2):
                repeated_slot_nested = True
                suspicious_paths.append({
                    'address': address,
                    'slot': slot,
                    'depths': sorted(unique_depths),
                    'pcs': sorted({write.get('pc') for write in writes if write.get('pc') is not None})[:4],
                })

        for (_, _depth), writes in writes_by_frame.items():
            if any(not write['after_external_call'] for write in writes) and any(write['after_external_call'] for write in writes):
                write_before_and_after = True
                break

        fallback_active = valid_storage_event_count == 0
        external_call_chain = (
            external_calls >= 2
            and max_depth >= 2
            and (same_function_reentered or same_contract_different_selector or nested_depth_reentry)
        )
        detection_threshold = 0.65 if fallback_active else 0.45

        score = 0.0
        if fallback_active:
            score += 0.45 if same_function_reentered else 0.0
            score += 0.35 if same_contract_different_selector else 0.0
            score += 0.35 if nested_depth_reentry else 0.0
            score += 0.20 if external_call_chain else 0.0
            score *= 0.75
            score = min(score, 0.80)
        else:
            score += 0.55 if repeated_slot_nested else 0.0
            score += 0.25 if write_after_external_call else 0.0
            score += 0.20 if same_function_reentered else 0.0
            score += 0.10 if write_before_and_after else 0.0
            score += 0.10 if same_slot_rewritten else 0.0
        score = round(min(score, 1.0), 4)

        score_components = {
            'same_contract_reentry': same_contract_reentry,
            'ancestor_proximity_reentry': 0,
            'same_selector_reentry': same_selector_reentry,
            'delegatecall_proxy_reentry': 0,
            'call_depth_max': max_depth,
            'external_calls': external_calls,
            'state_changes_after_call': write_after_external_call,
            'state_reentry': repeated_slot_nested,
            'write_before_and_after': write_before_and_after,
            'same_function_reentered': same_function_reentered,
            'same_contract_different_selector': same_contract_different_selector,
            'nested_depth_reentry': nested_depth_reentry,
            'external_call_chain': external_call_chain,
            'same_slot_rewritten': same_slot_rewritten,
            'storage_events_total': len(storage_events),
            'storage_trace_available': not fallback_active,
            'detection_threshold': detection_threshold,
            'guard_slots_filtered': guard_filtered_slots,
            'score': score,
        }

        self.signals.reentrancy_score = float(score)
        self.signals.reentrancy_paths = suspicious_paths[:5]
        self.signals.reentrancy_fallback_mode = fallback_active
        self.signals.reentrancy_detection_threshold = detection_threshold
        setattr(self, '_reentrancy_debug_components', score_components)

    # ── signal: Flash Loan ────────────────────────────────────────────────────

    def _check_flash_loan(self) -> None:
        """Detect borrow + callback pattern in the flat trace."""
        saw_borrow = False
        saw_callback = False
        for item in self.flat:
            fn = self._fn(item)
            if fn in _FLASH_BORROW:
                saw_borrow = True
            if fn in _FLASH_CALLBACK:
                saw_callback = True
        # Also check function_calls_to_expand_loc populated by TraceAnalyzer
        expand = self.tx_analysis.get('function_calls_to_expand_loc', {})
        if expand.get('flashloan'):
            saw_borrow = True
        if expand.get('flashloan_callback'):
            saw_callback = True

        # OR-assign: preserve values set earlier by _analyze_cast_trace_text()
        self.signals.flash_loan_detected  = self.signals.flash_loan_detected  or saw_borrow
        self.signals.flash_callback_detected = self.signals.flash_callback_detected or saw_callback

        # A borrow principal or repayment is not net profit. No native net-flow
        # measurement is supplied at this stage; leave flash_profit_eth unknown.

    # ── signal: Price Manipulation ────────────────────────────────────────────

    def _check_price_manipulation(self) -> None:
        """
        Detect getReserves/slot0 → [swap/transfer] → getReserves pattern.
        Count occurrences; if ≥ 2 read-write-read sequences, flag it.
        """
        sequences = 0
        last_price_read_idx = -1

        for idx, item in enumerate(self.flat):
            fn = self._fn_hint(item)
            if fn in _PRICE_READ:
                if last_price_read_idx >= 0:
                    # Check if there was a state write between then and now
                    between = self.flat[last_price_read_idx + 1:idx]
                    has_write = any(self._fn_hint(b) in _STATE_WRITE for b in between)
                    if has_write:
                        sequences += 1
                last_price_read_idx = idx

        self.signals.price_read_write_sequences = sequences
        self.signals.price_read_before_write = sequences >= 1

        # Call ordering cannot measure reserve/price change. Keep the numeric
        # delta unavailable; sequences remain observations for further analysis.

    # ── signal: Hashed Function (closed-source access control) ──────────────

    def _check_hashed_functions(self) -> None:
        """
        Record undecoded selectors and nearby named writes for further review.
        ABI decoding failure does not prove missing source or a permission bypass.
        """
        hashed_calls = []
        has_transfer_after = False
        saw_hash = False

        for i, item in enumerate(self.flat):
            fn = self._fn(item)
            call_type = (item.get('call_type') or '').lower()
            if call_type == 'staticcall':
                continue

            if _HASH_FN_RE.match(fn):
                saw_hash = True
                hashed_calls.append({'fn': fn, 'addr': self._addr(item)})
                # Check if a transfer follows within next 5 calls
                for j in range(i + 1, min(i + 6, len(self.flat))):
                    next_fn = self._fn_hint(self.flat[j])
                    if next_fn in _STATE_WRITE:
                        has_transfer_after = True
                        break

            # Also catch: privileged call into the tx-from address' contract
            if fn in _PRIVILEGED and self._val(item) > 0:
                hashed_calls.append({'fn': fn, 'addr': self._addr(item), 'value_eth': self._val(item)})

        self.signals.hashed_fn_calls  = hashed_calls[:10]
        self.signals.hashed_fn_count = max(self.signals.hashed_fn_count, len(hashed_calls))
        self.signals.undecoded_call_followed_by_state_write = saw_hash and has_transfer_after

        # Also use TraceAnalyzer's pre-computed list
        expand = self.tx_analysis.get('function_calls_to_expand_loc', {})
        if expand.get('name_in_hash'):
            self.signals.hashed_fn_count = max(
                self.signals.hashed_fn_count, len(expand['name_in_hash'])
            )

    # ── signal: Access Control Bypass ────────────────────────────────────────

    def _check_access_control(self) -> None:
        """
        Detect:
        - delegatecall into a contract created in this tx
        - calls to privileged functions (transferOwnership, initialize, etc.)
        - created-contract address appears as recipient of privileged call
        - hashed function selector calling state-changing operations (closed-source)
        - single caller interacting with 3+ contracts in rapid sequence
        """
        priv_calls = []
        arb_ext = False
        caller_contracts: set = set()

        for item in self.flat:
            fn = self._fn(item)
            addr = self._addr(item)
            call_type = (item.get('call_type') or '').lower()

            # Delegation is an observation, not proof of unauthorized storage use.
            if call_type == 'delegatecall':
                self.signals.delegatecall_observed = True

            # delegatecall into freshly created contract
            if call_type == 'delegatecall' and addr in self.created:
                arb_ext = True
                priv_calls.append({'type': 'delegatecall_into_created', 'fn': fn, 'addr': addr})

            elif call_type == 'delegatecall':
                priv_calls.append({'type': 'delegatecall_into_external', 'fn': fn, 'addr': addr})

            # privileged function call
            if fn in _PRIVILEGED:
                call_detail = {'type': 'privileged_fn', 'fn': fn, 'addr': addr}
                params_str = str(item.get('params', '')).lower()
                for ca in self.created:
                    if ca in params_str:
                        call_detail['created_contract_in_params'] = ca
                        self.signals.created_contract_in_privileged_call = True
                        break
                priv_calls.append(call_detail)
                caller_contracts.add(addr)

            # Track multi-contract state writes from repeated caller
            if self._fn_hint(item) in _STATE_WRITE and call_type not in ('staticcall', ''):
                caller_contracts.add(addr)

        # Multi-contract calls are useful review context, also common in routers.
        # They do not establish a common caller or an access-control violation.
        if len(caller_contracts) >= 3 and not self.signals.flash_loan_detected:
            priv_calls.append({
                'type': 'multi_contract_state_change',
                'contracts': list(caller_contracts)[:5],
            })

        # Also use pre-computed list from TraceAnalyzer
        if self.tx_analysis.get('address_calls_with_created_contract_in_params'):
            self.signals.created_contract_in_privileged_call = True

        self.signals.privileged_calls = priv_calls[:10]
        self.signals.delegatecall_to_created_contract = arb_ext
        self.signals.access_control_review_required = bool(
            priv_calls or self.signals.created_contract_in_privileged_call
            or self.signals.undecoded_call_followed_by_state_write
            or self.signals.delegatecall_observed
        )
        # No caller authorization / expected implementation is checked here.
        # Do not claim access_control_bypass or arbitrary_external_call.

    # ── signal: Profit Extraction ─────────────────────────────────────────────

    def _check_profit_extraction(self) -> None:
        """Record gross value only; token amounts and call values are not net ETH profit."""
        self.signals.largest_call_value_eth = max((self._val(c) for c in self.flat), default=0.0)
        # Neither attacker native net flow nor recipient EOA status is measured.
        # Leave profit_extraction_eth unavailable and large_transfer_to_eoa unset.

    # ── collate hints ─────────────────────────────────────────────────────────

    def _collate_hints(self) -> None:
        """Rank suspected vulnerability types by signal weight."""
        hints: list[tuple[float, str]] = []

        # Reentrancy
        if self.signals.reentrancy_score >= self.signals.reentrancy_detection_threshold:
            hints.append((self.signals.reentrancy_score, 'Reentrancy'))

        # Flash Loan
        fl_weight = 0.0
        if self.signals.flash_loan_detected:
            fl_weight += 5.0
        if self.signals.flash_callback_detected:
            fl_weight += 3.0
        if fl_weight:
            hints.append((fl_weight, 'Flash Loan Attack'))

        # Price Manipulation
        pm_weight = (self.signals.price_delta_ratio or 0.0) * 50 + self.signals.price_read_write_sequences * 3
        if pm_weight >= 3:
            hints.append((pm_weight, 'Price Manipulation'))

        # Access Control
        ac_weight = 0.0
        if self.signals.access_control_bypass or self.signals.access_control_review_required:
            ac_weight += 6.0
        if self.signals.created_contract_in_privileged_call:
            ac_weight += 4.0
        if self.signals.arbitrary_external_call:
            ac_weight += 5.0
        if ac_weight:
            hints.append((ac_weight, 'Access Control'))

        # Arbitrary External Call (subset of AC)
        if self.signals.arbitrary_external_call and not self.signals.access_control_bypass:
            hints.append((5.0, 'Arbitrary External Call'))

        # Sort descending by weight
        hints.sort(key=lambda x: x[0], reverse=True)
        self.signals.top_vuln_hints = [h[1] for h in hints]

    def _reentrancy_confidence_tier(self) -> str:
        """Human-readable confidence tier for downstream reports/UI."""
        score = self.signals.reentrancy_score
        threshold = self.signals.reentrancy_detection_threshold

        if score >= 0.85:
            return 'HIGH_RISK_REENTRANCY' if self.signals.reentrancy_fallback_mode else 'CONFIRMED_REENTRANCY'
        if score >= 0.70:
            return 'HIGH_RISK_REENTRANCY'
        if score >= threshold:
            return 'POSSIBLE_REENTRANCY'
        return 'NOT_REENTRANCY'

    # ── cast trace text fallback ────────────────────────────────────────────────

    def _analyze_cast_trace_text(self) -> None:
        """
        Parse the human-readable cast run output from the replay cache and
        extract signals that the RPC-based structured trace may miss:
          - [delegatecall] markers → delegation observed
          - raw 0xABCD1234 hex selectors → undecoded selector count
          - flash loan keywords in function names
          - inflation-attack pattern: mint + deposit/donate in same trace
        """
        if not os.path.exists(self._cast_cache_path):
            return
        try:
            # Read raw bytes first — lets us detect ASCII-only patterns (like
            # 'delegatecall') without any Unicode decoding risk on Windows.
            raw_bytes = open(self._cast_cache_path, 'rb').read()
        except OSError:
            return

        if not raw_bytes.strip():
            return

        # ── Byte-level detection (immune to encoding/box-drawing issues) ──────
        raw_lower = raw_bytes.lower()
        has_delegatecall = b'delegatecall' in raw_lower
        has_hex_selector = False

        # Regex on decoded text for function name extraction
        try:
            text = raw_bytes.decode('utf-8', errors='replace')
        except Exception:
            text = raw_bytes.decode('latin-1', errors='replace')

        fns_seen = []
        hex_sel_re = re.compile(r'::([0-9a-fA-F]{8})\(')
        hex_0x_re  = re.compile(r'\b0x([0-9a-fA-F]{8})\b')
        fn_name_re = re.compile(r'::([a-zA-Z_]\w*)\(')

        for line in text.splitlines():
            if hex_sel_re.search(line) or hex_0x_re.search(line):
                has_hex_selector = True
                self.signals.hashed_fn_count += 1
            fn_m = fn_name_re.search(line)
            if fn_m:
                fns_seen.append(fn_m.group(1).lower())

        # Text markers establish call observations, not source visibility,
        # permission bypass, or successful state change.
        self.signals.delegatecall_observed = has_delegatecall

        # Flash loan keywords in cast text
        for fn in fns_seen:
            if fn in _FLASH_BORROW:
                self.signals.flash_loan_detected = True
            if fn in _FLASH_CALLBACK:
                self.signals.flash_callback_detected = True

        # Inflation attack in cast text: mint/deposit alongside redeem/borrow
        fn_set = set(fns_seen)
        _DEPOSIT  = {'deposit', 'mint', 'transfer', 'storeconstructor'}
        _BORROW   = {'borrow', 'redeem', 'withdraw', 'liquidate', 'exchangerate'}
        if fn_set & _DEPOSIT and fn_set & _BORROW:
            self.signals.inflation_pattern_observed = True

        # Single-transfer detection: ONLY a bare transfer/transferFrom, nothing else
        # → characteristic of the donation step in a multi-tx Compoundv2 inflation attack
        _TRANSFER_FNS = {'transfer', 'transferfrom', 'safeTransfer', 'sendEther'}
        non_transfer = fn_set - {f.lower() for f in _TRANSFER_FNS}
        if fn_set and not non_transfer and not has_hex_selector and not has_delegatecall:
            self.signals.single_transfer_only = True

    # ── inflation attack ────────────────────────────────────────────────────────

    def _check_inflation_attack(self) -> None:
        """
        Compoundv2-style inflation attack:
          1. Attacker deposits a tiny amount to get cToken shares (mint)
          2. Attacker sends large amount directly to the vault (donate/transfer)
          3. Share price inflates → subsequent borrow drains vault
        Signal: mint/deposit call + direct ETH transfer to vault + borrow/redeem.
        """
        fns = [self._fn(c).lower() for c in self.flat]
        fn_set = set(fns)

        _MINT   = {'mint', 'deposit', 'supply'}
        _DONATE = {'transfer', 'transferfrom', 'sendether'}
        _DRAIN  = {'borrow', 'redeem', 'withdraw', 'redeemunderlying'}

        if fn_set & _MINT and fn_set & _DONATE and fn_set & _DRAIN:
            self.signals.inflation_pattern_observed = True

        # Also check repeated patterns: inflation txs often have
        # mint→transfer→borrow in a tight sequence
        for pat in self.repeated:
            if not isinstance(pat, dict):
                continue
            pattern_fns = {p.lower() for p in pat.get('pattern', []) if isinstance(p, str)}
            if pattern_fns & _MINT and pattern_fns & _DRAIN:
                self.signals.inflation_pattern_observed = True

    # ── public entry point ────────────────────────────────────────────────────

    def run(self) -> SignalBundle:
        self._analyze_cast_trace_text()      # ← cast text fallback (runs first)
        self._check_reentrancy()
        self._check_flash_loan()
        self._check_price_manipulation()
        self._check_hashed_functions()       # ← must run before access control
        self._check_access_control()
        self._check_inflation_attack()       # ← Compoundv2-style inflation
        self._check_profit_extraction()
        self._collate_hints()
        self.signals.reentrancy_confidence_tier = self._reentrancy_confidence_tier()
        self.signals.selector_alias_hints_applied = len(self._alias_selectors)

        # Build compact raw evidence dict for LLM context
        _dbg = getattr(self, '_reentrancy_debug_components', {})
        reentrancy_signals = {
            'same_function_reentry': _dbg.get('same_function_reentered', False),
            'cross_function_reentry': _dbg.get('same_contract_different_selector', False),
            'reentry_before_return': _dbg.get('nested_depth_reentry', False),
            'slot_rewrite': _dbg.get('same_slot_rewritten', False),
            'write_after_call': _dbg.get('state_changes_after_call', False),
            'state_slot_reentry': _dbg.get('state_reentry', False),
        }
        reentrancy_context = {
            'fallback_mode': self.signals.reentrancy_fallback_mode,
            'storage_trace_available': _dbg.get('storage_trace_available', False),
        }
        reentrancy = {
            'score': self.signals.reentrancy_score,
            'detected': self.signals.reentrancy_score >= self.signals.reentrancy_detection_threshold,
            'tier': self.signals.reentrancy_confidence_tier,
            'signals': reentrancy_signals,
            'context': reentrancy_context,
        }
        self.signals.raw = {
            'reentrancy':                  reentrancy,
            'reentrancy_score':             self.signals.reentrancy_score,
            'reentrancy_detected':          self.signals.reentrancy_score >= self.signals.reentrancy_detection_threshold,
            'reentrancy_paths_count':       len(self.signals.reentrancy_paths),
            'reentrancy_fallback_mode':     self.signals.reentrancy_fallback_mode,
            'reentrancy_detection_threshold': self.signals.reentrancy_detection_threshold,
            'reentrancy_confidence_tier':   self.signals.reentrancy_confidence_tier,
            'reentrancy_signals':          reentrancy_signals,
            'reentrancy_context':          reentrancy_context,
            'flash_loan_detected':          self.signals.flash_loan_detected,
            'flash_callback_detected':      self.signals.flash_callback_detected,
            'flash_profit_eth':             (round(self.signals.flash_profit_eth, 4) if self.signals.flash_profit_eth is not None else None),
            'price_read_write_sequences':   self.signals.price_read_write_sequences,
            'selector_alias_hints_applied': self.signals.selector_alias_hints_applied,
            'price_delta_ratio':            (round(self.signals.price_delta_ratio, 4) if self.signals.price_delta_ratio is not None else None),
            'price_manipulation_detected': False,
            'price_read_write_pattern_observed': self.signals.price_read_before_write,
            'hashed_fn_count':              self.signals.hashed_fn_count,
            'closed_source_state_change':   self.signals.closed_source_state_change,
            'access_control_bypass':        self.signals.access_control_bypass,
            'access_control_review_required': self.signals.access_control_review_required,
            'delegatecall_observed': self.signals.delegatecall_observed,
            'delegatecall_to_created_contract': self.signals.delegatecall_to_created_contract,
            'undecoded_call_followed_by_state_write': self.signals.undecoded_call_followed_by_state_write,
            'privileged_calls_count':       len(self.signals.privileged_calls),
            'created_contract_in_privileged': self.signals.created_contract_in_privileged_call,
            'arbitrary_external_call':      self.signals.arbitrary_external_call,
            'inflation_attack':             self.signals.inflation_attack,
            'inflation_pattern_observed': self.signals.inflation_pattern_observed,
            'single_transfer_only':         self.signals.single_transfer_only,
            'profit_extraction_eth':        (round(self.signals.profit_extraction_eth, 4) if self.signals.profit_extraction_eth is not None else None),
            'profit_measurement_status': 'unavailable',
            'price_delta_measurement_status': 'unavailable',
            'largest_call_value_eth': self.signals.largest_call_value_eth,
            'large_transfer_to_eoa':        self.signals.large_transfer_to_eoa,
            'top_vuln_hints':               self.signals.top_vuln_hints,
            'debug': {
                # reentrancy signal breakdown
                'same_contract_reentry':      _dbg.get('same_contract_reentry', 0),
                'ancestor_proximity_reentry': _dbg.get('ancestor_proximity_reentry', 0),
                'same_selector_reentry':      _dbg.get('same_selector_reentry', 0),
                'delegatecall_proxy_reentry': _dbg.get('delegatecall_proxy_reentry', 0),
                'call_depth_max':             _dbg.get('call_depth_max', 0),
                'external_calls':             _dbg.get('external_calls', 0),
                'state_changes_after_call':   _dbg.get('state_changes_after_call', False),
                'state_reentry':              _dbg.get('state_reentry', False),
                'write_before_and_after':     _dbg.get('write_before_and_after', False),
                'same_function_reentered':    _dbg.get('same_function_reentered', False),
                'same_contract_different_selector': _dbg.get('same_contract_different_selector', False),
                'nested_depth_reentry':       _dbg.get('nested_depth_reentry', False),
                'external_call_chain':        _dbg.get('external_call_chain', False),
                'same_slot_rewritten':        _dbg.get('same_slot_rewritten', False),
                'storage_events_total':       _dbg.get('storage_events_total', 0),
                'storage_trace_available':    _dbg.get('storage_trace_available', False),
                'detection_threshold':        _dbg.get('detection_threshold', 0.45),
                'guard_slots_filtered':       _dbg.get('guard_slots_filtered', 0),
                # legacy compatibility
                'reentrant_patterns_found': len(self.tx_analysis.get('repeated_patterns', {})),
                'score_components': _dbg,
            }
        }
        return self.signals
