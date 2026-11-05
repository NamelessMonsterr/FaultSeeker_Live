"""Narrow runtime integration for the external, commit-pinned FaultSeeker pipeline.

Hooks are installed per worker before main() is entered, and removed on exit.
The upstream checkout is not edited. This keeps local and Docker execution on
the same transport/identity policy while retaining the pinned source revision.
"""
import json
import threading
import re
from copy import deepcopy
import os
import sys

try:
    from .model_endpoint import ModelEndpointSession
    from .model_routes import ITERA_DEFAULT_BASE_URL, MERCURY_DEFAULT_BASE_URL, resolve_route
    from .trace_identity import TraceIdentityError, canonical_to_legacy, check_structured, validate_trace_root
except ImportError:  # app/server.py invoked directly
    from model_endpoint import ModelEndpointSession
    from model_routes import ITERA_DEFAULT_BASE_URL, MERCURY_DEFAULT_BASE_URL, resolve_route
    from trace_identity import TraceIdentityError, canonical_to_legacy, check_structured, validate_trace_root


CHAIN_IDS = {"eth": 1, "bsc": 56, "polygon": 137, "arbitrum": 42161,
             "optimism": 10, "avalanche": 43114, "base": 8453, "fantom": 250,
             "zksync": 324, "linea": 59144, "scroll": 534352, "gnosis": 100,
             "celo": 42220, "cronos": 25, "moonbeam": 1284, "aurora": 1313161554}


# Well-known function selectors (verified against openchain signature
# database 2026-11-05). The upstream name-based match sets were written for
# decoded cast-text traces; on canonical traces the function identity is the
# calldata SELECTOR, so name-only sets silently never match. Extending the
# sets with selectors revives the upstream logic for both identity forms.
# Standard read selectors. These are NOT added to the upstream name filter:
# a 4-byte selector is not behavioral proof - arbitrary EVM code can mutate or
# reenter under any selector. They are pruned from ranked patterns only when
# the trace itself shows a staticcall (EVM-enforced read-only); see
# prune_static_readonly_selectors.
SEL_ERC20_READS = {
    "0x70a08231",  # balanceOf(address)
    "0xdd62ed3e",  # allowance(address,address)
    "0x18160ddd",  # totalSupply()
    "0x313ce567",  # decimals()
    "0x06fdde03",  # name()
    "0x95d89b41",  # symbol()
}
SEL_DEX_READS = {
    "0x0dfe1681",  # token0()
    "0xd21220a7",  # token1()
    "0x0902f1ac",  # getReserves()
}
# Full standard token surface (reads + state-changing). Used only for
# DEMOTION of token-like addresses, never for exclusion: an address whose
# observed calls in this transaction are entirely within this surface behaves
# exactly like a standard token in this trace (grounded context). An address
# with ANY custom selector observed, or any tx-created contract, is never
# demoted - a malicious implementation behind a standard selector stays
# discoverable at full rank.
SEL_TOKEN_SURFACE = SEL_ERC20_READS | SEL_DEX_READS | {
    "0xa9059cbb",  # transfer(address,uint256)
    "0x23b872dd",  # transferFrom(address,address,uint256)
    "0x095ea7b3",  # approve(address,uint256),
}
# POSSIBLE signatures for well-known selectors (4byte/openchain, 2026-11-05).
# A 4-byte selector is NOT an ABI identity: collisions exist and the actual
# implementation at an address is unverified from the trace alone (a proxy or
# custom contract can implement anything under a familiar selector). These
# labels are presentation hints only, always emitted alongside
# implementation_unverified=True.
SEL_STANDARD_NAMES = {
    "0xa9059cbb": "transfer", "0x23b872dd": "transferFrom",
    "0x095ea7b3": "approve", "0x70a08231": "balanceOf",
    "0xdd62ed3e": "allowance", "0x18160ddd": "totalSupply",
    "0x313ce567": "decimals", "0x06fdde03": "name", "0x95d89b41": "symbol",
    "0x0dfe1681": "token0", "0xd21220a7": "token1", "0x0902f1ac": "getReserves",
}
SEL_PRICE_READS = {"0x0902f1ac", "0x3850c7bd"}  # getReserves(), slot0()
# Presence of any of these is an OBSERVATION about the trace, never proof of
# a mechanism; mechanism classification belongs to the rule layer, which
# requires its own verified effects before naming an exploit class.
SEL_STATE_WRITES = {
    "0xa9059cbb", "0x23b872dd",  # transfer, transferFrom
    "0x6a627842", "0x89afcb44",  # mint(address), burn(address)
    "0x022c0d9f",  # swap(uint256,uint256,address,bytes)
    "0xfff6cae9",  # sync()
}
SEL_FLASH_BORROW = {
    "0x5c38449e",  # Balancer Vault flashLoan(address,address[],uint256[],bytes)
    "0xab9c4b5d",  # Aave flashLoan(...,uint16)
    "0x490e6cbc",  # UniswapV3 Pool flash(address,uint256,uint256,bytes)
}
SEL_FLASH_CALLBACK = {
    "0x10d1e85c",  # uniswapV2Call(address,uint256,uint256,bytes)
    "0xf04f2707",  # Balancer IFlashLoanRecipient.receiveFlashLoan (4byte-verified)
    "0x920f5c84",  # Aave IFlashLoanReceiver.executeOperation (4byte-verified)
}


def extend_signal_sets(sig_module):
    """Selector identities must satisfy the same name-based detectors; the sets
    are module-level upstream, extended here without editing the pinned checkout."""
    sig_module._FLASH_BORROW |= SEL_FLASH_BORROW
    sig_module._FLASH_CALLBACK |= SEL_FLASH_CALLBACK
    sig_module._PRICE_READ |= SEL_PRICE_READS
    sig_module._STATE_WRITE |= SEL_STATE_WRITES


SEL_STANDARD_READS = SEL_ERC20_READS | SEL_DEX_READS


def prune_static_readonly_selectors(result):
    """Prune standard read selectors from ranked repeated patterns ONLY when
    the trace itself shows the call was a staticcall (EVM-enforced read-only
    context). The same selector invoked via call/delegatecall - e.g. a custom
    or malicious contract implementing the ERC-20 surface with exploit logic -
    stays in the ranked targets. functions_to_be_inspected and
    created-contract calls are never pruned here: the forensics orchestrator
    only admits non-staticcall calls into them, so every entry there is a
    state-capable invocation by construction and must remain discoverable."""
    kept_patterns = []
    for pattern in result.repeated_patterns:
        entries = [
            e for e in pattern["pattern"]
            if not (isinstance(e.get("function"), str)
                    and e["function"].lower() in SEL_STANDARD_READS
                    and str(e.get("call_type") or "").lower() == "staticcall")
        ]
        if entries:
            pattern["pattern"] = entries
            kept_patterns.append(pattern)
    result.repeated_patterns = kept_patterns
    return result


def annotate_standard_selector_names(result):
    """Attach a POSSIBLE-signature hint to each entry/call of a well-known
    selector, in functions_to_be_inspected and created-contract call lists.
    Pure presentation metadata: keys, counts and membership are untouched, so
    every entry remains analyzable; the narrow-down and analysis prompts stop
    being semantics-free hex WITHOUT asserting verified behavior - each hint
    carries implementation_unverified=True because a proxy or custom contract
    can implement anything under a familiar selector, and 4-byte collisions
    exist."""
    def _hint(sel):
        nm = SEL_STANDARD_NAMES.get(str(sel or "").lower())
        return f"{nm}(...) [possible signature; implementation unverified]" if nm else None
    def _annotate(calls):
        for c in calls or []:
            if not isinstance(c, dict):
                continue
            hint = _hint(c.get("function"))
            if hint:
                c["possible_signature"] = hint
                c["implementation_unverified"] = True
    for key, entry in result.functions_to_be_inspected.items():
        # Upstream entries are dicts {"count", "calls"}, but tolerate
        # list-shaped entries (a bare call list) instead of crashing the run.
        if isinstance(entry, dict):
            hint = _hint(key.rsplit("_", 1)[0])
            if hint:
                entry["possible_signature"] = hint
                entry["implementation_unverified"] = True
                # Propagation fix (e2e finding): the REAL upstream narrow-down
                # serializer (_review_function_calls) passes only
                # count_of_appearance + example_calls[:3] into the prompt, and
                # ranked call dicts carry no "function" key, so entry-level
                # annotation never reached the model on selector traces.
                # Stamp the hint onto the serialized call entries themselves;
                # the serializer passes them through verbatim.
                for c in (entry.get("calls") or [])[:3]:
                    if isinstance(c, dict):
                        c["possible_signature"] = hint
                        c["implementation_unverified"] = True
            _annotate(entry.get("calls"))
        elif isinstance(entry, list):
            _annotate(entry)
    for entry in result.address_calls_with_created_contract_in_params.values():
        if isinstance(entry, dict):
            _annotate(entry.get("calls"))
        elif isinstance(entry, list):
            _annotate(entry)
    return result


def order_ranked_targets(result, observed_functions_by_address, created_addresses):
    """Selection ordering with diversity slots. Groups, count-desc within each:
    A: entries at addresses with any custom selector observed, and all
       tx-created contracts (exploit-relevant by construction);
    B: ONE representative (highest count) per token-like address, so a
       malicious ERC-20-only contract keeps a visible slot and cannot be
       silently crowded out;
    C: remaining duplicate token-surface entries.
    Token-likeness is a HEURISTIC (all observed calls at the address are
    standard-token selectors in this one transaction), not verified safe
    behavior; nothing is dropped from the ranked targets."""
    observed_functions_by_address = observed_functions_by_address or {}
    created = {a.lower() for a in (created_addresses or set())}

    def addr_of(key):
        return key.rsplit("_", 1)[1].lower()

    def is_token_like(addr):
        if addr in created:
            return False
        observed = observed_functions_by_address.get(addr)
        return bool(observed) and all(o.lower() in SEL_TOKEN_SURFACE for o in observed)

    group_a, by_token_addr = [], {}
    for key, val in result.functions_to_be_inspected.items():
        addr = addr_of(key)
        if is_token_like(addr) and key.rsplit("_", 1)[0].lower() in SEL_TOKEN_SURFACE:
            by_token_addr.setdefault(addr, []).append((key, val))
        else:
            group_a.append((key, val))
    group_b, group_c = [], []
    for addr, entries in by_token_addr.items():
        entries.sort(key=lambda kv: kv[1].get("count", 0), reverse=True)
        group_b.append(entries[0])
        group_c.extend(entries[1:])
    group_b.sort(key=lambda kv: kv[1].get("count", 0), reverse=True)
    result.functions_to_be_inspected = dict(group_a + group_b + group_c)
    return result


def restore_custom_selector_recall(forensics_result, trace_root):
    """Selector-era recall repair (robustness, classifier-independence).
    The upstream forensics expansion (name_in_hash one-level child admission +
    address-role token filter) was designed for cast-text traces where only
    UNRESOLVED names appear as hashes; on selector traces every call is a
    hash, and admission depends on the LLM address-role classification - when
    the classifier marks the vulnerable contract as already-inspected/common,
    its custom functions never reach the ranker. (Corrected record: ETH
    Mercury run 3's artifact showed a 43-candidate pool; its 6-entry
    functions_to_inspect was the POST-narrow-down selection, not the ranker
    input, so the earlier claim that admission dropped the exploit path in
    that run is withdrawn. This repair exists so custom-selector candidacy
    does not depend on LLM classification variance, not because a specific
    run proved an admission drop.)
    Repair: admit every state-capable (call/delegatecall, non-staticcall) call
    whose selector is OUTSIDE the standard token surface and that is not
    already present, so custom functions are always rankable. Token-surface
    calls follow the normal path (ordering handles their priority); nothing
    here changes mechanism classification."""
    existing = set()
    for calls in (forensics_result.functions_to_be_inspected or {}).values():
        if not isinstance(calls, list):
            continue
        for c in calls or []:
            if isinstance(c, dict) and c.get("function") and c.get("address"):
                existing.add(f"{c['function']}_{c['address']}".lower())
    added = []
    # GPT round 10: fail-closed call-type boundary + inherited static context.
    # Only an explicit allowlist of state-capable EVM ops counts; unknown or
    # missing call types are NOT treated as ordinary calls. A staticcall makes
    # its ENTIRE subtree read-only (EVM-enforced), so the static context is
    # propagated to descendants: a CALL nested under a STATICCALL cannot modify
    # state and must not be admitted as state-capable.
    STATE_CAPABLE = ("call", "delegatecall", "callcode")
    def _visit(node, depth, static_context=False):
        if not isinstance(node, dict):
            return
        fn = node.get("function")
        addr = node.get("address")
        ct = str(node.get("call_type") or "").lower()
        static_here = static_context or ct == "staticcall"
        if (fn and addr and not static_here and ct in STATE_CAPABLE
                and fn.lower() not in SEL_TOKEN_SURFACE):
            key = f"{fn}_{addr}".lower()
            if key not in existing:
                existing.add(key)
                added.append({
                    "function": fn, "address": addr,
                    "gas": node.get("gas"),
                    "params": node.get("input") or node.get("params") or "0x",
                    "depth": str(node.get("depth") or depth),
                    "call_type": ct,
                })
        children = node.get("children") or []
        if isinstance(children, list):
            for child in children:
                _visit(child, depth + 1, static_here)
    _visit(trace_root, 0)
    if added:
        bucket = forensics_result.functions_to_be_inspected
        if not isinstance(bucket, dict):
            bucket = {}
            forensics_result.functions_to_be_inspected = bucket
        bucket.setdefault("selector_recall", []).extend(added)
    return len(added)


def walk(node):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.get("children", [])))


def reconcile_calibrated_confidence(result):
    """Upstream Stage 3 (engine pipeline.py) replaces confidence.overall with
    the logistic-calibrated probability but leaves confidence.level and the
    first explanation line computed from the PRE-calibration 4-factor proxy -
    e.g. overall 0.9975 rendered next to "62.4% (moderate)". Reconcile the
    presentation at the fork layer (engine stays pinned): level classifies the
    FINAL reported score, the explanation's first line matches it, and the
    proxy value remains disclosed as proxy_overall/proxy_level."""
    try:
        from faultseeker.core.confidence_scorer import CONFIDENCE_LEVELS
    except Exception:
        CONFIDENCE_LEVELS = [(0.9, "very_high", "Immediate remediation recommended"),
                             (0.7, "high", "Priority investigation warranted"),
                             (0.5, "moderate", "Further analysis recommended"),
                             (0.3, "low", "Review for false positive"),
                             (0.0, "very_low", "Likely false positive")]
    import re
    for sf in (result.get("scored_functions") or []):
        conf = sf.get("confidence") if isinstance(sf, dict) else None
        if not isinstance(conf, dict) or not conf.get("calibrated"):
            continue
        overall = conf.get("overall")
        if not isinstance(overall, (int, float)) or isinstance(overall, bool):
            continue
        level, desc = next(((lv, d) for t, lv, d in CONFIDENCE_LEVELS if overall >= t),
                           ("very_low", "Likely false positive"))
        expl = list(conf.get("explanation") or [])
        if expl:
            m = re.search(r"Overall confidence: ([0-9.]+)% \((\w+)\)", str(expl[0]))
            if m:
                try:
                    conf.setdefault("proxy_overall", round(float(m.group(1)) / 100.0, 4))
                    conf.setdefault("proxy_level", m.group(2))
                except (TypeError, ValueError):
                    pass  # proxy extraction is diagnostic; reconciliation must not fail
            expl[0] = f"Overall confidence: {overall:.1%} ({level}) - {desc}"
            conf["explanation"] = expl
        conf["level"] = level


class NarrowdownCaptureStop(Exception):
    """Intentional diagnostic stop (FAULTSEEKER_STOP_AFTER_NARROWDOWN=1): the
    narrow-down selection boundary has been captured and the run halts before
    any per-function analysis. This is a requested measurement, not a provider
    or product failure."""


class PipelineRuntime:
    def __init__(self, tx_hash, chain, session=None, emit=lambda event: None):
        self.tx_hash, self.chain = tx_hash.lower(), chain.lower()
        self.session = session
        self.emit = emit
        self.partial = None
        self.sequence = None
        self.ranked_targets = []
        self.narrowdown_capture = []
        self.function_verdicts = []  # per-analyzer deep-analysis proposals + rejections
        self._verdicts_lock = threading.Lock()
        self.restorers = []
        self.source = None
        self.model_keys = {}
        self.function_analysis = {"started": 0, "completed": 0}  # observed FunctionAnalyzer.run, not inferred
        self.selector_bindings = {}        # address -> ABI selector->source-name binding + code-hash evidence
        self.selector_resolution_log = []  # per-lookup resolution records from the analysis path
        self.bound_source_texts = []       # verified bound source bodies handed to the analyzer (retention checks)
        self.source_retention_events = []  # outbound-boundary retention outcomes (preserved / trimmed / oversized)
        self.model_texts = []              # model replies seen at the boundary (regenerable text, the only trimmable class)
        self._frame_index = None           # lazy (address, selector) -> code-context map from the canonical trace
        try:
            from .function_wall_guard import WallCapLedger
        except ImportError:
            from function_wall_guard import WallCapLedger
        self.wall_cap = WallCapLedger()

    def replace(self, owner, name, replacement):
        original = getattr(owner, name)
        self.restorers.append((owner, name, original))
        setattr(owner, name, replacement)
        return original

    def assert_healthy(self):
        if self.session:
            self.session.assert_healthy()

    def _ensure_eth_explorer_fallback(self):
        # Source-acquisition root cause (2026-11-05, verified live): the engine's
        # 'eth' explorer list is Etherscan-V1-only, and api.etherscan.io/api now
        # answers every call with status 0 "deprecated V1 endpoint" - which the
        # engine's explorer_call counts as success, so it never fails over and
        # get_abi/get_source_code return None even for publicly verified
        # contracts. Register keyless Blockscout mainnet AHEAD of the dead V1
        # entries (higher initial score so it is tried first; V1 specs kept
        # untouched as documented-dead config and future V2 swap point).
        # Runtime-only registration with restorer - the pinned engine checkout
        # is never edited. Rebuild the endpoint registry so no cached eth
        # endpoint list from before install() survives.
        try:
            from faultseeker.utils import explorer_provider as _xp
        except ImportError:
            return
        specs = _xp._CHAIN_EXPLORERS.get('eth')
        if not isinstance(specs, list):
            return
        if any('blockscout' in str(url) for url, *_ in specs):
            return
        merged = dict(_xp._CHAIN_EXPLORERS)
        # V1 entries kept for documentation/future V2 swap but demoted below the
        # jitter band (95 vs 10): endpoint scores get +-4 random jitter at
        # construction, which otherwise intermittently re-sorts the dead V1 route
        # ahead and its deprecation NOTOK short-circuits acquisition again.
        merged['eth'] = [('https://eth.blockscout.com/api', '', 95)] + [
            (url, env, 10) for url, env, _score in specs]
        self.replace(_xp, '_CHAIN_EXPLORERS', merged)
        # Rebuild exactly once; the pinned engine always provides _ExplorerRegistry.
        self.replace(_xp, '_registry', _xp._ExplorerRegistry())

    @staticmethod
    def _canonical_abi_type(inp):
        # Canonical ABI type text with recursive tuple expansion: keccak selectors
        # are computed over the expanded component list, never the word "tuple".
        t = str(inp.get("type", ""))
        if t.startswith("tuple"):
            comps = "(" + ",".join(PipelineRuntime._canonical_abi_type(c) for c in inp.get("components", []) or []) + ")"
            return comps + t[len("tuple"):]
        return t

    @staticmethod
    def _build_selector_map(abi):
        """selector -> {'name','signature'}; a same-ABI 4-byte collision between
        distinct signatures is recorded as 'ambiguous' and must fail unresolved."""
        from eth_utils import function_signature_to_4byte_selector
        out = {}
        for entry in abi or []:
            if not isinstance(entry, dict) or entry.get("type") != "function":
                continue
            name = entry.get("name")
            if not name:
                continue
            try:
                sig = name + "(" + ",".join(PipelineRuntime._canonical_abi_type(i) for i in entry.get("inputs", []) or []) + ")"
                selector = "0x" + function_signature_to_4byte_selector(sig).hex()
            except Exception:
                continue
            prior = out.get(selector)
            if prior is None:
                out[selector] = {"name": name, "signature": sig,
                                 "input_count": len(entry.get("inputs", []) or []),
                                 "input_types": [PipelineRuntime._canonical_abi_type(i)
                                                 for i in entry.get("inputs", []) or []],
                                 "input_internal_types": [(i.get("internalType") or "")
                                                          for i in entry.get("inputs", []) or []],
                                 "input_components": [([PipelineRuntime._canonical_abi_type(c)
                                                        for c in i.get("components", []) or []]
                                                       if str(i.get("type", "")).startswith("tuple") else None)
                                                      for i in entry.get("inputs", []) or []]}
            elif prior == "ambiguous" or prior.get("signature") != sig:
                out[selector] = "ambiguous"
        return out

    def _code_hash_evidence(self, address):
        """Bytecode evidence for the CODE address a binding refers to. Every step
        records an explicit state; failures keep a bounded reason instead of
        being swallowed. ABI/source resolution (explorer) and bytecode identity
        are separate evidence: this records code hashes only and never claims
        the downloaded source corresponds to the deployed code."""
        ev = {"code_address": address,
              "latest_code": "not_attempted",
              "tx_lookup": "not_attempted",
              "code_at_tx_block": "not_checked"}
        try:
            from faultseeker.utils.rpc_provider import rpc_call
            from eth_utils import keccak
        except Exception as exc:
            ev["latest_code"] = "unavailable:import:%s" % type(exc).__name__
            return ev
        code = None
        try:
            code = rpc_call(self.chain, "eth_getCode", [address, "latest"], timeout=15)
            if isinstance(code, str) and code.startswith("0x") and len(code) > 2:
                ev["code_hash_latest"] = "0x" + keccak(hexstr=code).hex()
                ev["latest_code"] = "fetched"
            else:
                ev["latest_code"] = "unavailable:empty_or_invalid"
                code = None
        except Exception as exc:
            ev["latest_code"] = "unavailable:%s:%s" % (type(exc).__name__, str(exc)[:100])
            code = None
        try:
            tx = rpc_call(self.chain, "eth_getTransactionByHash", [self.tx_hash], timeout=15)
            block = tx.get("blockNumber") if isinstance(tx, dict) else None
            if block:
                ev["tx_lookup"] = "found"
                ev["tx_block"] = block
            else:
                ev["tx_lookup"] = "unavailable:no_block_number"
        except Exception as exc:
            ev["tx_lookup"] = "unavailable:%s:%s" % (type(exc).__name__, str(exc)[:100])
        if ev.get("tx_block"):
            try:
                historical = rpc_call(self.chain, "eth_getCode", [address, ev["tx_block"]], timeout=15)
                if isinstance(historical, str) and historical.startswith("0x"):
                    if isinstance(code, str):
                        ev["code_at_tx_block"] = ("matches_latest" if historical.lower() == code.lower()
                                                  else "differs_from_latest")
                    else:
                        ev["code_at_tx_block"] = "unverified:no_latest_code"
                else:
                    ev["code_at_tx_block"] = "not_checked:empty_or_invalid_historical"
            except Exception as exc:
                ev["code_at_tx_block"] = "not_checked:%s:%s" % (type(exc).__name__, str(exc)[:100])
        return ev

    def _frame_code_index(self):
        """(address, selector) -> execution context from the observed trace.

        Prefers the canonical trace, whose producer (rpc_provider
        .normalize_trace_node) carries explicit call-frame metadata: callee/to
        is the address whose CODE the frame executes (for DELEGLEGATECALL: the
        target whose code runs) and caller/from is the execution context.
        Falls back to the legacy conversion (same fields after
        canonical_to_legacy). The cache is keyed by the identity of the trace
        object: replacing the sequence/trace rebuilds the index, so bindings
        from a previous trace can never be reused. Frames not observed have no
        entry - lookups for them must fail unresolved, never fall back to a
        guessed code address."""
        trace = (self.sequence or {}).get("canonical_trace") or (self.sequence or {}).get("trace")
        if self._frame_index is not None and self._frame_index[0] is trace:
            return self._frame_index[1]
        index = {}

        def walk(node, parent_addr):
            if not isinstance(node, dict):
                return
            addr = str(node.get("callee") or node.get("to") or node.get("address") or "").lower()
            fn = node.get("function_selector") or node.get("function")
            call_type = str(node.get("call_type") or node.get("type") or "").lower()
            if addr and isinstance(fn, str) and re.fullmatch(r"0x[0-9a-fA-F]{8}", fn):
                index.setdefault((addr, fn.lower()), {
                    "code_address": addr,
                    "call_type": call_type,
                    "execution_context": (parent_addr if call_type in ("delegatecall", "callcode")
                                          and parent_addr else addr),
                })
            for child in node.get("children", []) or []:
                walk(child, addr or parent_addr)

        walk(trace, None)
        self._frame_index = (trace, index)
        return index

    _ELEMENTARY_RE = re.compile(
        r"^(u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?"
        r"|bytes([1-9]|[12][0-9]|3[012])?"
        r"|address|bool|string|byte|ufixed|fixed)(\[\d*\])?$")

    @staticmethod
    def _normalize_source_type(token):
        """Canonical ABI type for an elementary Solidity source type token,
        else None for user-defined types (struct/enum/contract/function) which
        the source parser cannot expand to canonical tuple/uint8 form."""
        token = token.strip()
        suffix = ""
        while token.endswith("]"):
            i = token.rindex("[")
            suffix = token[i:] + suffix
            token = token[:i]
        base = {"uint": "uint256", "int": "int256", "byte": "bytes1"}.get(token, token)
        if not PipelineRuntime._ELEMENTARY_RE.match(base):
            return None
        if base in ("ufixed", "fixed"):
            base += "128x18"
        return base + suffix

    @staticmethod
    def _source_header_params(source_code):
        """Tri-state parse of a candidate function's source header.

        ("ok", [canonical types]) - header isolated, every parameter elementary.
        ("non_elementary", count) - header isolated and parsed, but at least one
            parameter is user-defined (struct/enum/contract/function type):
            parsed, just not parser-comparable to canonical ABI tuples. The
            parsed parameter COUNT is retained so callers can still enforce
            arity agreement with the ABI signature.
        ("unparseable", None)     - header could not be isolated or parsed
            (no function keyword, unbalanced parens, malformed parameter,
            misspelled elementary type). Unparseable is NOT non-elementary.
        """
        m = re.search(r"function\s+\w+\s*\(", source_code or "")
        if not m:
            return "unparseable", None
        depth, params, buf = 0, [], []
        for ch in source_code[m.end() - 1:]:
            if ch == "(":
                depth += 1
                if depth > 1:
                    buf.append(ch)
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    if buf and "".join(buf).strip():
                        params.append("".join(buf))
                    break
                buf.append(ch)
            elif ch == "," and depth == 1:
                params.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
        else:
            return "unparseable", None  # unbalanced parens: header never closed
        out = []
        non_elementary_seen = False
        for raw in params:
            tokens = [t for t in raw.strip().split() if t not in ("memory", "calldata", "storage", "payable")]
            if len(tokens) == 1:
                type_tok = tokens[0]
            elif len(tokens) == 2:
                type_tok = tokens[0]
            else:
                return "unparseable", None  # malformed parameter list
            canon = PipelineRuntime._normalize_source_type(type_tok)
            if canon is None:
                if re.match(r"^(u?int\d*|bytes\d*|ufixed|fixed)", type_tok):
                    return "unparseable", None  # misspelled elementary type
                if re.fullmatch(r"[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)?(\[\d*\])*", type_tok):
                    non_elementary_seen = True  # user-defined type, parsed
                    continue
                return "unparseable", None  # unsupported syntax
            out.append(canon)
        if non_elementary_seen:
            return "non_elementary", len(params)
        return "ok", out

    @staticmethod
    def _source_header_type_tokens(source_code):
        """Raw per-parameter type tokens of a parsed header, or None when the
        header is unparseable (same isolation rules as _source_header_params)."""
        status, _ = PipelineRuntime._source_header_params(source_code)
        if status == "unparseable":
            return None
        m = re.search(r"function\s+\w+\s*\(", source_code or "")
        depth, params, buf = 0, [], []
        for ch in source_code[m.end() - 1:]:
            if ch == "(":
                depth += 1
                if depth > 1:
                    buf.append(ch)
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    if buf and "".join(buf).strip():
                        params.append("".join(buf))
                    break
                buf.append(ch)
            elif ch == "," and depth == 1:
                params.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
        tokens = []
        for raw in params:
            parts = [t for t in raw.strip().split() if t not in ("memory", "calldata", "storage", "payable")]
            tokens.append(parts[0])
        return tokens

    @staticmethod
    def _strip_comments_and_strings(source_text):
        """Blank comments AND string literal contents, preserving EXACT length
        and every newline position, so byte/line offsets computed against the
        result map 1:1 to the original source. One lexical pass with correct
        precedence: comment markers inside strings are string data, quotes
        inside comments are comment data. Escapes inside strings are blanked
        with their escaped char. Unterminated string/comment blanks to EOF
        (fail closed). Declaration keywords or braces inside strings/comments
        are data, never declarations, and cannot disturb scope tracking."""
        text = source_text or ""
        out = []
        i, n = 0, len(text)
        blank = lambda c: "\n" if c == "\n" else " "
        while i < n:
            ch = text[i]
            nxt = text[i + 1] if i + 1 < n else ""
            if ch == "/" and nxt == "/":
                out.append("  ")
                i += 2
                while i < n and text[i] != "\n":
                    out.append(" ")
                    i += 1
            elif ch == "/" and nxt == "*":
                out.append("  ")
                i += 2
                while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                    out.append(blank(text[i]))
                    i += 1
                if i < n:
                    out.append("  ")
                    i += 2
            elif ch in ('"', "'"):
                q = ch
                out.append(" ")
                i += 1
                while i < n and text[i] != q:
                    if text[i] == "\\" and i + 1 < n:
                        out.append(blank(text[i]))
                        out.append(blank(text[i + 1]))
                        i += 2
                    else:
                        out.append(blank(text[i]))
                        i += 1
                if i < n:
                    out.append(" ")
                    i += 1
            else:
                out.append(ch)
                i += 1
        return "".join(out)

    @staticmethod
    def _declaration_index(source_text):
        """Source-context resolution: declarations visible in ONE file, with
        enclosing-scope provenance.

        {"decls": {simple_name: [(qualified_name, scope_or_None), ...]},
         "kinds": {qualified_name: "struct"|"enum"|"contract"},
         "fields": {qualified_name: [canonical field types] | None},
         "scopes": [(contract_name, start_offset, end_offset)]}

        A name resolves for a function ONLY from its own enclosing contract's
        declarations or a UNIQUE file-level declaration; a declaration inside
        a DIFFERENT contract (shadowing/inheritance/import ambiguity) never
        proves it. Enum-typed struct fields resolve to uint8 (the ABI
        canonical form); other non-elementary fields make fields None
        (unsupported depth fails closed)."""
        text = PipelineRuntime._strip_comments_and_strings(source_text)
        decls, kinds, fields, scopes = {}, {}, {}, []
        scope, scope_start, depth = None, 0, 0
        i = 0
        n = len(text)
        while i < n:
            m = re.match(r"(contract|library|interface)\s+(\w+)[^{;]*\{", text[i:])
            if m and scope is None and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_$")):
                scope, scope_start = m.group(2), i
                decls.setdefault(scope, []).append((scope, None))
                kinds[scope] = m.group(1)
                i += m.end()
                depth = 1
                continue
            m = re.match(r"(struct|enum)\s+(\w+)\s*\{", text[i:])
            if m and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_$")):
                kind, name = m.group(1), m.group(2)
                qualified = f"{scope}.{name}" if scope else name
                decls.setdefault(name, []).append((qualified, scope))
                kinds[qualified] = kind
                j = text.find("}", i + m.end())
                if j == -1:
                    scopes.append((scope, scope_start, n)) if scope else None
                    return {"decls": decls, "kinds": kinds, "fields": fields, "scopes": scopes}
                body = text[i + m.end():j]
                if kind == "struct":
                    canon_fields = []
                    for field in body.split(";"):
                        field = field.strip()
                        if not field:
                            continue
                        ftok = field.split()[0] if field.split() else ""
                        canon = PipelineRuntime._normalize_source_type(ftok)
                        if canon is None:
                            fbase = ftok.split("[")[0]
                            # enum-typed field (same scope or file-level): uint8
                            fcands = [q for q, sc in decls.get(fbase, [])
                                      if sc == scope or sc is None]
                            fqual = fcands[0] if len(fcands) == 1 else None
                            if fqual and kinds.get(fqual) == "enum":
                                canon = "uint8" + ftok[len(fbase):]
                            else:
                                canon_fields = None
                                break
                        canon_fields.append(canon)
                    fields[qualified] = canon_fields
                i = j + 1
                continue
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if scope is not None and depth == 0:
                    scopes.append((scope, scope_start, i))
                    scope = None
            i += 1
        if scope is not None:
            scopes.append((scope, scope_start, n))
        return {"decls": decls, "kinds": kinds, "fields": fields, "scopes": scopes}

    @staticmethod
    def _resolve_decl(decl_index, base, fn_scope):
        """Qualified name for an unqualified token, or None when the function's
        own scope and the file level cannot prove it. Enclosing-contract
        declarations win over file-level ones; anything else (other contracts,
        imports, inheritance) is ambiguity and fails closed."""
        if fn_scope is None:
            return None  # unknown enclosing scope: import/inheritance ambiguity
        entries = (decl_index or {}).get("decls", {}).get(base) or []
        scoped = [q for q, sc in entries if sc is not None and sc == fn_scope]
        if len(scoped) == 1:
            return scoped[0]
        if scoped:
            return None
        file_level = [q for q, sc in entries if sc is None]
        if len(file_level) == 1:
            return file_level[0]
        return None

    @staticmethod
    def _header_matches_abi(source_code, input_types, internal_types,
                            components=None, decl_index=None, fn_scope=None):
        """Exact type-identity check: every header parameter must match the ABI
        input at its position. Elementary source tokens canonicalize and must
        equal the canonical ABI type; user-defined tokens (struct/enum/
        contract) must match the ABI internalType's declared type NAME and the
        ABI canonical array shape. Qualified source names need full dotted-path
        equality. Unqualified names are provable ONLY through the source unit's
        own declaration index (a name the file does not declare may come from
        an import and stays unproven). For structs the DECLARED FIELD TYPES
        must also equal the ABI tuple components. A user-defined ABI input vs
        an elementary source token (enum vs uint) or vice versa is a mismatch.
        Same-arity alone never satisfies this. Returns True/False, or None
        when identity cannot be proven (unparseable header, missing
        internalType, undeclared name, non-elementary struct fields)."""
        tokens = PipelineRuntime._source_header_type_tokens(source_code)
        if tokens is None or len(tokens) != len(input_types):
            return None if tokens is None else False
        internal_types = internal_types or [""] * len(input_types)
        components = components or [None] * len(input_types)
        for idx, (tok, canon_abi, internal) in enumerate(zip(tokens, input_types, internal_types)):
            canon_src = PipelineRuntime._normalize_source_type(tok)
            kind, _, it_name = (internal or "").partition(" ")
            while it_name.endswith("]"):
                it_name = it_name[:it_name.rindex("[")]
            it_short = it_name.rsplit(".", 1)[-1] if it_name else ""
            if canon_src is not None:
                if kind in ("struct", "enum", "contract"):
                    return False  # ABI user-defined, source elementary
                if canon_src != canon_abi:
                    return False
                continue
            # user-defined source token: needs ABI internalType to identify it
            if kind not in ("struct", "enum", "contract") or not it_short:
                return None
            base = tok
            suffix = ""
            while base.endswith("]"):
                i = base.rindex("[")
                suffix = base[i:] + suffix
                base = base[:i]
            if "." in base:
                # qualified source name: full dotted path must equal the ABI's
                if base != it_name:
                    return False
                resolved = base
            else:
                # unqualified: provable only via the function's own enclosing
                # contract or a unique file-level declaration (shadowing /
                # import / inheritance ambiguity fails closed)
                resolved = PipelineRuntime._resolve_decl(decl_index, base, fn_scope)
                if resolved is None:
                    return None
                if resolved != it_name:
                    return False
            if decl_index is None:
                # name identity stands, but without source declaration context
                # kind/layout identity of a user-defined type is unprovable
                # (imports stay unresolved): fail closed
                return None
            # Kind identity: a matched NAME is not a matched TYPE when the
            # declaration kinds differ (struct vs enum vs contract).
            kinds_map = decl_index.get("kinds") or {}
            if resolved in kinds_map:
                if kinds_map[resolved] != kind:
                    return False         # proven kind mismatch
            else:
                return None              # declaration not established here: kind unproven
            abi_arr = canon_abi
            while abi_arr.endswith("]"):
                abi_arr = abi_arr[:abi_arr.rindex("[")]
            if suffix != canon_abi[len(abi_arr):]:
                return False
            if kind == "struct":
                # name identity proven; when source context is available,
                # verify the DEFINITION against the ABI tuple components (the
                # selector commits to the exact layout). Without any source
                # context the qualified-path/internalType identity stands.
                comp = components[idx]
                if comp is not None and decl_index is not None:
                    fields_map = decl_index.get("fields") or {}
                    if resolved in fields_map:
                        decl_fields = fields_map[resolved]
                        if decl_fields is None:
                            return None      # non-elementary field: unsupported depth
                        if decl_fields != comp:
                            return False     # same name, different layout
                    elif any(resolved == q for es in (decl_index.get("decls") or {}).values() for q, _ in es):
                        return None          # declared here but layout unparseable
        return True

    PROMPT_CAP = 10000  # pinned engine GPTAgent/UniversalAgent._send_message cap (agent.py: >10000 -> first 8000 + last 2000)
    MODEL_TEXT_KEEP = 200      # minimum chars kept (head+tail) of each trimmed model-written span
    MODEL_TEXT_MARKER = "\n...[model-written text trimmed to keep bound source and evidence intact]...\n"
    SOURCE_KEYS = ("function_source_code", "'source_code'", '"source_code"')  # engine payload keys that carry source

    @staticmethod
    def _source_forms(source):
        """Every serialization a bound source takes inside engine prompts: raw,
        json.dumps (summary payloads) and repr (str(dict) task-selection)."""
        forms = {source, json.dumps(source)[1:-1], repr(source)[1:-1]}
        return [f for f in forms if f]

    @staticmethod
    def _find_spans(message, needles):
        spans = []
        for needle in needles:
            start = 0
            while needle:
                i = message.find(needle, start)
                if i == -1:
                    break
                spans.append((i, i + len(needle)))
                start = i + len(needle)
        spans.sort()
        merged = []
        for a, b in spans:
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        return [tuple(x) for x in merged]

    @staticmethod
    def _preserve_bound_sources(message, sources, model_texts=(), cap=10000):
        """Outbound-boundary retention for bound source. Returns (message, event).
        The pinned engine cuts any message over `cap` to head 8000 + tail 2000,
        which can silently drop a bound source (or any evidence) in the middle.

        Policy: bound source and ALL non-model-written prompt text are
        REQUIRED evidence and are never trimmed. Only text that is verbatim a
        previous MODEL REPLY (understanding, task tree, processing result:
        regenerable model narrative, not evidence) may be shortened, each span
        keeping head+tail with a fixed inline marker, by a deterministic
        proportional budget. If required evidence cannot fit, or a source-
        bearing prompt cannot be positively verified to contain the bound
        source, the message is left unchanged and an explicit event says so
        (fail closed: such a run is never reported as fully analyzed).
        Statuses: preserved_other_text_trimmed, source_oversized_unpreserved,
        required_evidence_unfit, bound_source_unverified_outbound. At/under
        the cap, or when no source-bearing key and no bound source: (message, None)."""
        if not isinstance(message, str) or len(message) <= cap or not sources:
            return message, None
        P = PipelineRuntime
        needles = [f for src in sources for f in P._source_forms(src)]
        src_spans = P._find_spans(message, needles)
        base = {"original_chars": len(message), "cap": cap}
        if not src_spans:
            if any(k in message for k in P.SOURCE_KEYS):
                # a source-bearing prompt whose bound source cannot be located:
                # absence of a match is NOT proof that preservation was unneeded
                return message, {**base, "status": "bound_source_unverified_outbound"}
            return message, None
        src_chars = sum(b - a for a, b in src_spans)
        base["protected_source_chars"] = src_chars
        if src_chars > cap:
            return message, {**base, "status": "source_oversized_unpreserved"}
        cut = len(message) - cap
        # trimmable: verbatim model replies (full text or its [:2000] prefix) outside source spans
        mt_needles = []
        for t in model_texts:
            if isinstance(t, str) and len(t) >= 2 * P.MODEL_TEXT_KEEP + len(P.MODEL_TEXT_MARKER):
                mt_needles.extend({t, t[:2000]})
        cand = [(a, b) for a, b in P._find_spans(message, [n for n in mt_needles if len(n) >= 2 * P.MODEL_TEXT_KEEP + len(P.MODEL_TEXT_MARKER)])
                if not any(a < sb and sa < b for sa, sb in src_spans)]
        M, K = len(P.MODEL_TEXT_MARKER), P.MODEL_TEXT_KEEP
        slack = [(a, b, (b - a) - K - M) for a, b in cand if (b - a) - K - M > 0]
        max_red = sum(x[2] for x in slack)
        if max_red < cut:
            return message, {**base, "status": "required_evidence_unfit", "needed_reduction": cut,
                             "available_reduction": max_red}
        # deterministic proportional allocation, then exact top-up
        reds = [min(sl, -(-cut * sl // max_red)) for _, _, sl in slack]
        short = cut - sum(reds)
        for i in sorted(range(len(slack)), key=lambda j: -(slack[j][2] - reds[j])):
            if short <= 0:
                break
            add = min(short, slack[i][2] - reds[i])
            reds[i] += add
            short -= add
        pieces, pos = [], 0
        for (a, b, _), red in zip(slack, reds):
            if red <= 0:
                continue
            pieces.append(message[pos:a])
            keep = (b - a) - red - M          # chars of the model text retained
            head = int(keep * 0.6)
            pieces.append(message[a:a + head] + P.MODEL_TEXT_MARKER + message[b - (keep - head):b])
            pos = b
        pieces.append(message[pos:])
        new_msg = "".join(pieces)
        if len(new_msg) > cap or not all(message[a:b] in new_msg for a, b in src_spans):
            return message, {**base, "status": "required_evidence_unfit", "needed_reduction": cut,
                             "available_reduction": max_red}
        return new_msg, {**base, "status": "preserved_other_text_trimmed",
                         "removed_chars": len(message) - len(new_msg), "final_chars": len(new_msg),
                         "trimmed_kind": "model_written_text_only"}

    def _install_selector_source_binding(self):
        # Analysis-input root cause #2 (2026-11-05, verified): canonical traces
        # carry calldata-selector function identity, but parse_contract keys
        # downloaded source by function NAME and the pinned engine's
        # FunctionAnalyzer._retrieve_source_code looks up by that key - so even
        # successfully downloaded source never reached analysis for
        # selector-identified units (upstream get_abi existed but was never
        # called on any path). Bind selector -> verified source name via the
        # explorer ABI at the acquisition boundary, keep the canonical
        # selector/address identity intact, and record the binding plus
        # code-hash evidence instead of renaming identity or trusting
        # model-chosen names. Resolution failures stay unresolved (empty
        # source), never guessed; same-ABI selector collisions fail ambiguous.
        from faultseeker.data_collection.contract_downloader import ContractDownloader
        from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
        from faultseeker.utils import rpc_provider as _rp
        runtime = self

        # Producer gap verified on the captured Erigon fixture (hedgey_tx1_parity):
        # normalize_trace_node takes call_type from the item's 'type' ('call') and
        # drops action.callType, so real DELEGATECALL frames are mislabelled CALL
        # in the canonical trace. Preserve the explicit action.callType metadata
        # at the runtime boundary so the frame index sees true delegatecall
        # semantics (code address = target, execution context = caller frame).
        original_tree = _rp.build_parity_tree
        def parity_tree_preserving_delegatecall(trace_list):
            declared = {}
            for item in trace_list or []:
                if isinstance(item, dict):
                    t = str((item.get('action') or {}).get('callType') or '').lower()
                    if t in ('delegatecall', 'callcode'):
                        declared[tuple(item.get('traceAddress', []) or ())] = t
            tree = original_tree(trace_list)

            def restore_flags(node):
                if not isinstance(node, dict):
                    return
                t = declared.get(tuple(node.get('_addr') or ()))
                if t:
                    node['call_type'] = t.upper()
                for child in node.get('children', []) or []:
                    restore_flags(child)

            restore_flags(tree)
            return tree
        self.replace(_rp, 'build_parity_tree', parity_tree_preserving_delegatecall)

        original_normalize = _rp.normalize_trace_node
        def normalize_preserving_delegatecall(node, depth=0, call_id='0'):
            result = original_normalize(node, depth=depth, call_id=call_id)
            declared = ''
            if isinstance(node, dict):
                declared = (str((node.get('action') or {}).get('callType') or '').lower()
                            or str(node.get('call_type') or '').lower())
            if declared in ('delegatecall', 'callcode') and str(result.get('call_type', '')).upper() == 'CALL':
                result['call_type'] = declared.upper()
            return result
        self.replace(_rp, 'normalize_trace_node', normalize_preserving_delegatecall)

        original_run = ContractDownloader.run

        def run_with_binding(downloader):
            info = original_run(downloader)
            for address, functions in (info or {}).items():
                if not functions:
                    continue  # no parsed source -> no binding claim
                try:
                    abi = ContractDownloader.get_abi(downloader.chain, address)
                except Exception:
                    abi = None
                if not abi:
                    continue
                record = {
                    "selectors": runtime._build_selector_map(abi),
                    "abi_provenance": "explorer_registry_after_fallback",
                    "binding_rule": "4-byte selector over canonical ABI signature; collisions unresolved",
                    "code_address": str(address).lower(),
                    "source_bytecode_link": ("explorer reports the source verified against the deployed "
                                             "bytecode at this address; the code-hash evidence below is an "
                                             "independent observation, not a verification of that link"),
                    "source_bytecode_independently_verified": False,
                }
                record.update(runtime._code_hash_evidence(str(address).lower()))
                runtime.selector_bindings[str(address).lower()] = record
            return info
        self.replace(ContractDownloader, "run", run_with_binding)

        original_parse_contract = ContractDownloader.parse_contract

        def parse_contract_with_decl_index(output_dir):
            # Source-context resolution support: attach each source file's
            # declaration index (struct/enum names with their qualified paths
            # and canonical field layouts) so unqualified header tokens can be
            # resolved against the file's OWN declarations instead of guessed.
            parsed = original_parse_contract(output_dir)
            file_index = {}
            file_text = {}
            for entries in parsed.values():
                for e in entries:
                    rel = e.get("path") or ""
                    if rel not in file_index:
                        actual = os.path.join(output_dir, rel.lstrip("./"))
                        try:
                            with open(actual, encoding="utf-8") as fh:
                                file_text[rel] = fh.read()
                        except OSError:
                            file_text[rel] = ""
                        file_index[rel] = PipelineRuntime._declaration_index(file_text[rel])
                    e["decl_index"] = file_index[rel]
                    # The function's actual enclosing contract: a declaration
                    # from another contract in the same file never proves a
                    # name for this function.
                    try:
                        stripped = PipelineRuntime._strip_comments_and_strings(file_text[rel])
                        off = sum(len(l) + 1 for l in stripped.split("\n")[:max(0, (e.get("start_line") or 1) - 1)])
                        e["fn_scope"] = next((name for name, s, en in file_index[rel].get("scopes", [])
                                              if s <= off <= en), None)
                    except Exception:
                        e["fn_scope"] = None
            return parsed
        self.replace(ContractDownloader, "parse_contract", staticmethod(parse_contract_with_decl_index))

        original_retrieve = FunctionAnalyzer._retrieve_source_code
        selector_re = re.compile(r"^0x[0-9a-fA-F]{8}$")

        def retrieve_with_resolution(analyzer, address, function_name):
            if not (isinstance(function_name, str) and selector_re.match(function_name)):
                return original_retrieve(analyzer, address, function_name)  # name identity: unchanged path
            addr = str(address).lower()
            base = {"selector": function_name.lower(), "address": addr}
            frame = runtime._frame_code_index().get((addr, function_name.lower()))
            if frame is None:
                # The frame's code address cannot be established from the observed
                # trace: fail unresolved, never fall back to a guessed address.
                runtime.selector_resolution_log.append(
                    {**base, "status": "unresolved", "reason": "no_observed_frame",
                     "resolved_name": None, "source_entries": 0})
                return []
            code_address = frame["code_address"]
            context = {"code_address": code_address,
                       "execution_context": frame["execution_context"],
                       "call_type": frame["call_type"]}
            mapping = (runtime.selector_bindings.get(code_address) or {}).get("selectors", {})
            entry = mapping.get(function_name.lower())
            if isinstance(entry, dict):
                candidates = original_retrieve(analyzer, code_address, entry["name"])
                # The pinned retriever rebuilds each entry (path+source_code
                # only), dropping the declaration index attached at parse time;
                # reattach it from the analyzer's contract_info by exact
                # (path, content) identity.
                raw_entries = (analyzer.contract_info.get(code_address) or {}).get(entry["name"]) or []
                by_identity = {(r.get("path"), r.get("content")): r for r in raw_entries}
                for c in candidates:
                    raw = by_identity.get((c.get("path"), c.get("source_code")))
                    if raw and raw.get("decl_index"):
                        c["decl_index"] = raw["decl_index"]
                        c["fn_scope"] = raw.get("fn_scope")
                # Exact unit binding: the ABI selector proves the signature; the
                # source parser keys by name only, so multiple candidate bodies
                # (overloads, same-name functions across inherited contracts)
                # must be disambiguated to exactly one unit or fail ambiguous.
                out = candidates
                unit = None
                if len(candidates) > 1:
                    # Exact unit binding: arity alone cannot establish an overload
                    # (foo(uint256) vs foo(address)); require the full canonical
                    # input-type list to match. Any non-elementary (struct/enum)
                    # parameter is not parser-comparable, so such candidates
                    # cannot be distinguished and must fail unresolved.
                    verdicts = [runtime._header_matches_abi(c.get("source_code"),
                                                            entry.get("input_types"),
                                                            entry.get("input_internal_types"),
                                                            entry.get("input_components"),
                                                            c.get("decl_index"),
                                                            c.get("fn_scope"))
                                for c in candidates]
                    # Exactly one proven match AND every other candidate
                    # provably excluded: an undecidable (None) candidate might
                    # be the ABI-matched overload, so it fails the whole
                    # disambiguation closed.
                    matched = [c for c, v in zip(candidates, verdicts) if v is True]
                    if any(v is None for v in verdicts):
                        matched = []
                    if len(matched) == 1:
                        out = matched
                        unit = {"candidates": len(candidates), "selected_path": matched[0].get("path"),
                                "disambiguated_by": "canonical_input_types_vs_source_header"}
                    else:
                        runtime.selector_resolution_log.append(
                            {**base, **context, "status": "ambiguous_overload",
                             "resolved_name": entry["name"], "signature": entry["signature"],
                             "candidates": len(candidates),
                             "matching_signature": len(matched), "source_entries": 0})
                        return []
                elif candidates:
                    verdict = runtime._header_matches_abi(
                        candidates[0].get("source_code"), entry.get("input_types"),
                        entry.get("input_internal_types"), entry.get("input_components"),
                        candidates[0].get("decl_index"), candidates[0].get("fn_scope"))
                    if verdict is not True:
                        # False: a parameter's type identity provably disagrees
                        #   (wrong canonical type, wrong user-defined name, wrong
                        #   array shape, or arity) - source and ABI do not
                        #   describe the same function.
                        # None: cannot prove identity (unparseable header, or a
                        #   user-defined parameter without ABI internalType) -
                        #   unsupported, conservative unresolved.
                        runtime.selector_resolution_log.append(
                            {**base, **context, "status": "unresolved",
                             "reason": ("signature_mismatch" if verdict is False
                                        else "type_identity_unsupported"),
                             "resolved_name": entry["name"],
                             "signature": entry["signature"], "source_entries": 0})
                        return []
                    unit = {"candidates": 1, "selected_path": candidates[0].get("path"),
                            "disambiguated_by": "single_candidate_exact_types",
                            "evidence_basis": "abi_internal_type_and_canonical_match"}
                for _o in out:
                    _sc = _o.get("source_code") if isinstance(_o, dict) else None
                    if _sc and _sc not in runtime.bound_source_texts:
                        runtime.bound_source_texts.append(_sc)
                runtime.selector_resolution_log.append(
                    {**base, **context, "status": "resolved", "resolved_name": entry["name"],
                     "signature": entry["signature"], "source_entries": len(out),
                     **({"unit_binding": unit} if unit else {})})
                return out
            if entry == "ambiguous":
                runtime.selector_resolution_log.append(
                    {**base, **context, "status": "ambiguous_collision",
                     "resolved_name": None, "source_entries": 0})
                return []  # collision: refuse to bind, never guess
            runtime.selector_resolution_log.append(
                {**base, **context, "status": "unresolved", "reason": "no_abi_binding",
                 "resolved_name": None, "source_entries": 0})
            return []
        self.replace(FunctionAnalyzer, "_retrieve_source_code", retrieve_with_resolution)

    def install_model_hooks(self, agent_module):
        if not self.session:
            return
        if self.source is not None:
            self.session.route_policy = self._model_config
        if hasattr(agent_module, "_llm_call_with_retry"):
            self.replace(agent_module, "_llm_call_with_retry", self.session.call)
        config = getattr(agent_module, "PROVIDER_CONFIG", None)
        if isinstance(config, dict):
            # The pinned pipeline sends any unknown model prefix to a local Ollama
            # agent. Register the operator-selected Itera and Mercury routes so
            # they use the OpenAI-compatible agent whose calls the shared
            # transport owns.
            additions = {}
            if "itera/" not in config:
                additions["itera/"] = (ITERA_DEFAULT_BASE_URL, "ITERA_API_KEY")
            if "mercury-" not in config:
                additions["mercury-"] = (MERCURY_DEFAULT_BASE_URL, "INCEPTION_API_KEY")
            if additions:
                self.replace(agent_module, "PROVIDER_CONFIG", {**config, **additions})
            # Prompt-family boundary (parent directive 2026-11-05 18:00): the
            # engine picks prompt complexity via is_local_model() over its
            # static CLOUD_PREFIXES, which predates the fork's routes - so
            # mercury-3 and itera/qwen3.8-27b were silently classed "local"
            # and analyzed with the simplified weak-model prompt family
            # (root cause of the abstention contract never firing in
            # production: it targets the cloud template, which these runs
            # never sent). The "local" family is a capability tier for weak
            # on-box models, not a hosting label; both fork routes are
            # capable hosted models. Register them as cloud at this same
            # authorized hook boundary. Every other model's classification
            # is unchanged; the pinned engine checkout is never edited.
            # Fail CLOSED (R26-F1): a missing prompt module or an unexpected
            # CLOUD_PREFIXES structure must abort installation loudly - never
            # serve runs with provider routing installed but the prompt-family
            # correction silently skipped (the exact silent failure being
            # remediated). Concurrency: this is a process-global mutation;
            # production runs one analysis per child process (server.worker),
            # and install happens before dispatch and restore after completion.
            from faultseeker.prompts import local_model_prompts as _lmp
            _prefixes = getattr(_lmp, "CLOUD_PREFIXES", None)
            if (not isinstance(_prefixes, tuple)
                    or not all(isinstance(pfx, str) and pfx for pfx in _prefixes)):
                raise RuntimeError(
                    "pinned engine prompt boundary unexpected: "
                    "local_model_prompts.CLOUD_PREFIXES is not a tuple of "
                    "non-empty strings - refusing to install model hooks "
                    "against an unverified boundary")
            _add = tuple(pfx for pfx in ("mercury-", "itera/")
                         if not any(pfx.startswith(c) or c.startswith(pfx)
                                    for c in _prefixes))
            if _add:
                self.replace(_lmp, "CLOUD_PREFIXES", tuple(_lmp.CLOUD_PREFIXES) + _add)
            # Post-condition (R28): registration must be EFFECTIVE, not merely
            # attempted - an unmatched boundary (e.g. a shadowing prefix)
            # would otherwise leave both routes silently local.
            for _route in ("mercury-3", "itera/qwen3.8-27b"):
                if _lmp.is_local_model(_route):
                    raise RuntimeError(
                        f"prompt-family registration ineffective: {_route} "
                        "still classified local after CLOUD_PREFIXES extension")
        for agent_class in {agent_module.GPTAgent, agent_module.UniversalAgent}:
            original = agent_class._send_message
            def checked_send(agent, *args, _original=original, **kwargs):
                self.assert_healthy()
                if self.bound_source_texts:
                    if args and isinstance(args[0], str):
                        _msg, _ev = self._preserve_bound_sources(args[0], self.bound_source_texts, self.model_texts, self.PROMPT_CAP)
                        args = (_msg,) + tuple(args[1:])
                    elif isinstance(kwargs.get("user_message"), str):
                        _msg, _ev = self._preserve_bound_sources(kwargs["user_message"], self.bound_source_texts, self.model_texts, self.PROMPT_CAP)
                        kwargs = {**kwargs, "user_message": _msg}
                    else:
                        _ev = None
                    if _ev:
                        self.source_retention_events.append(_ev)
                try:
                    result = _original(agent, *args, **kwargs)
                except Exception:
                    self.assert_healthy()
                    raise
                self.assert_healthy()  # Upstream may have swallowed an APIStatusError.
                if isinstance(result, str) and len(result) >= 450:
                    self.model_texts.append(result)
                    del self.model_texts[:-200]
                return result
            self.replace(agent_class, "_send_message", checked_send)

    def install(self):
        from faultseeker.utils import agent as agents
        from faultseeker.data_collection.txn_sequencer import TransactionSequencer
        from faultseeker.data_collection.trace_parser import TraceNode
        from faultseeker.data_collection.trace_visualizer import TransactionTraceVisualizer
        from faultseeker.data_collection.txn_replayer import TransactionReplayer
        from faultseeker.utils.rpc_provider import rpc_call
        from faultseeker.utils import rpc_provider
        from faultseeker.forensics.orchestrator import ForensicsOrchestrator
        from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
        from faultseeker.function_analysis.function_ranker import FunctionRanker
        self.source = agents
        from faultseeker.forensics import signal_extractor as _sig
        extend_signal_sets(_sig)
        self._ensure_eth_explorer_fallback()
        self._install_selector_source_binding()
        if os.getenv("FAULTSEEKER_VISITOR_RPC_RELAY"):
            # Forked workers may inherit a registry populated by a prior diagnostic.
            # Rebuild it after the visitor URL was replaced with the checked relay.
            if not hasattr(rpc_provider, "_ChainRegistry") or not hasattr(rpc_provider, "_registry"):
                raise RuntimeError("Pipeline cannot isolate the visitor RPC registry.")
            self.replace(rpc_provider, "_registry", rpc_provider._ChainRegistry())
        self.install_model_hooks(agents)

        original_structured = TransactionReplayer.get_structured_trace
        def checked_structured(replayer, tx_hash, chain):
            payload = check_structured(original_structured(replayer, tx_hash, chain), tx_hash, chain)
            tx = rpc_call(chain, "eth_getTransactionByHash", [tx_hash], timeout=15)
            network = rpc_call(chain, "eth_chainId", [], timeout=15)
            try:
                actual_chain = int(network, 16) if isinstance(network, str) else int(network)
            except (ValueError, TypeError):
                raise TraceIdentityError("RPC chain identity could not be established.") from None
            if actual_chain != CHAIN_IDS.get(chain):
                raise TraceIdentityError("RPC network does not match the selected chain.")
            root = payload["trace"]
            receipt = None
            if isinstance(tx, dict) and tx.get("to") is None:
                receipt = rpc_call(chain, "eth_getTransactionReceipt", [tx_hash], timeout=15)
            validate_trace_root(tx, root, tx_hash, receipt)
            payload = deepcopy(payload)
            payload["trace_provenance"] = {
                "source": "structured_rpc_or_cache", "identity_cross_check": "eth_getTransactionByHash + eth_chainId",
                "transaction_hash": tx_hash.lower(), "chain": chain,
                "block_hash": tx.get("blockHash"), "block_number": tx.get("blockNumber"),
                "function_identity": "calldata_selector", "abi_verified": False}
            return payload
        self.replace(TransactionReplayer, "get_structured_trace", checked_structured)

        original_sequence = TransactionSequencer.run
        def canonical_sequence(sequencer, tx_hash, chain):
            # Capture the checked canonical payload even if the upstream sequencer
            # subsequently chooses decoded cast text as its legacy trace.
            checked = None
            original_get = sequencer.replayer.get_structured_trace
            def remember(*args, **kwargs):
                nonlocal checked
                checked = original_get(*args, **kwargs)
                return checked
            sequencer.replayer.get_structured_trace = remember
            try:
                value = original_sequence(sequencer, tx_hash, chain)
            finally:
                sequencer.replayer.get_structured_trace = original_get
            check_structured(checked, tx_hash, chain)
            if not isinstance(value, dict):
                raise TraceIdentityError("Transaction sequence is unavailable.")
            value["trace"] = canonical_to_legacy(checked["trace"])
            value["canonical_trace"] = checked["trace"]
            value["trace_provenance"] = checked.get("trace_provenance", {})
            memo, created = {}, []
            for node in walk(value["trace"]):
                address = str(node.get("address") or "").lower()
                memo.setdefault(address, [])
                if node["function"] not in memo[address]:
                    memo[address].append(node["function"])
                if node["call_type"] in ("create", "create2"):
                    created.append(address)
            value["address_calls"], value["created_address"] = memo, created
            sequencer.parser.address_call_memo, sequencer.parser.created_address = memo, created
            sequencer.visualizer = TransactionTraceVisualizer()
            sequencer.visualizer.build_graph_from_tree(TraceNode.from_dict(value["trace"]))
            value["address_relation"] = sequencer.visualize_address_relation()
            self.sequence = value
            return value
        self.replace(TransactionSequencer, "run", canonical_sequence)

        original_forensics = ForensicsOrchestrator.run
        def checked_forensics(orchestrator, *args, **kwargs):
            try:
                value = original_forensics(orchestrator, *args, **kwargs)
                if value and value[0]:
                    self.partial = value[0].to_dict()
                    self.partial["sections"] = {"deterministic_checks": "completed", "address_classification": "completed"}
                self.assert_healthy()
                return value
            except Exception:
                if hasattr(orchestrator, "rule_verdict"):
                    self.partial = {"transaction": {"hash": self.tx_hash, "chain": self.chain},
                                    "classification": {"rule_verdict": orchestrator.rule_verdict,
                                        "rule_confidence": getattr(orchestrator, "rule_confidence", None),
                                        "matched_rule": getattr(orchestrator, "matched_rule", None)},
                                    "sections": {"deterministic_checks": "completed", "address_classification": "failed"}}
                self.assert_healthy()
                raise
        self.replace(ForensicsOrchestrator, "run", checked_forensics)

        original_rank = FunctionRanker.rank
        def checked_rank(ranker, *args, **kwargs):
            if not self.sequence:
                raise TraceIdentityError("Cannot rank targets without a checked canonical trace.")
            if args and hasattr(args[0], "functions_to_be_inspected"):
                restore_custom_selector_recall(args[0], self.sequence["trace"])
            result = original_rank(ranker, *args, **kwargs)
            result = prune_static_readonly_selectors(result)
            observed_by_addr = {}
            created_addrs = set()
            for n in walk(self.sequence["trace"]):
                fn = n.get("function")
                addr = (n.get("address") or "").lower()
                if fn and addr:
                    observed_by_addr.setdefault(addr, set()).add(fn)
                if str(n.get("call_type") or n.get("type") or "").lower() in ("create", "create2"):
                    created_addrs.add(addr)
            result = order_ranked_targets(result, observed_by_addr, created_addrs)
            result = annotate_standard_selector_names(result)
            allowed = {f"{n['function']}_{n['address']}".lower() for n in walk(self.sequence["trace"])}
            if any(key.lower() not in allowed for key in result.functions_to_be_inspected):
                raise TraceIdentityError("Ranked target is not an observed canonical selector/address pair.")
            self.ranked_targets = list(result.functions_to_be_inspected)
            return result
        self.replace(FunctionRanker, "rank", checked_rank)

        original_analyze = FunctionAnalyzer.run
        def checked_analysis(analyzer, *args, **kwargs):
            self.assert_healthy()
            self.function_analysis["started"] += 1
            try:
                result = original_analyze(analyzer, *args, **kwargs)
            except Exception:
                self.assert_healthy()
                raise
            self.assert_healthy()  # ThreadPoolExecutor may catch individual failures.
            self.function_analysis["completed"] += 1
            self._capture_function_verdicts(analyzer)
            return result
        self.replace(FunctionAnalyzer, "run", checked_analysis)
        for _name, _kind in (("_function_analysis_init", "function"), ("_txn_analysis_init", "transaction")):
            if hasattr(FunctionAnalyzer, _name):
                self.replace(FunctionAnalyzer, _name, self.wall_cap.wrap(getattr(FunctionAnalyzer, _name), _kind))
        self.replace(FunctionAnalyzer, "_update_potentially_vulnerable_function",
                     self.wall_cap.wrap_update(FunctionAnalyzer._update_potentially_vulnerable_function))

        # Instrumented selection boundary (parent directive 2026-11-05 13:13):
        # capture the EXACT narrow-down payload and the model's raw reply in
        # production so selection quality is evaluated on evidence, not on
        # reconstructed stage guesses. The artifact records pre-selection
        # candidates (ranked_targets) and each serializer prompt + reply.
        original_rfc = FunctionAnalyzer._review_function_calls
        def capturing_rfc(analyzer, *args, **kwargs):
            real_agent = analyzer.agent
            captures = self.narrowdown_capture
            runtime = self
            class _CapturingAgent:
                def query(self, prompt, *a, **k):
                    reply = real_agent.query(prompt, *a, **k)
                    captures.append({"kind": "narrowdown",
                                     "candidate_count": len(getattr(analyzer, "functions_to_be_inspected", {}) or {}),
                                     "prompt": str(prompt),
                                     "reply": reply})
                    return reply
                def __getattr__(self, name):
                    return getattr(real_agent, name)
            analyzer.agent = _CapturingAgent()
            try:
                return original_rfc(analyzer, *args, **kwargs)
            finally:
                analyzer.agent = real_agent
        self.replace(FunctionAnalyzer, "_review_function_calls", capturing_rfc)

        # Post-selection boundary: _prepare_children_call_memo is called exactly
        # once, immediately after BOTH narrow-down loops finish and before any
        # per-function analysis. Record the pre/post selection state so the
        # captured payload can be compared against the model's final choice.
        # FAULTSEEKER_STOP_AFTER_NARROWDOWN=1 then stops the run here
        # (diagnostic, bounded: no per-function model calls are made).
        original_pccm = FunctionAnalyzer._prepare_children_call_memo
        stop_env = os.getenv("FAULTSEEKER_STOP_AFTER_NARROWDOWN") == "1"
        # Environment snapshot only - NOT proof of the dispatched request
        # config (defaults, normalization and adapter rewrites live downstream).
        env_snapshot = {"model": os.getenv("FAULTSEEKER_MODEL", ""),
                        "reasoning_effort": os.getenv("FAULTSEEKER_MERCURY_REASONING_EFFORT", ""),
                        "retry_limit": os.getenv("FAULTSEEKER_MODEL_RETRY_LIMIT", ""),
                        "max_functions": os.getenv("FAULTSEEKER_MAX_FUNCTIONS", "")}
        def capturing_pccm(analyzer, selected_functions, *args, **kwargs):
            post_keys = (list(selected_functions.keys()) if isinstance(selected_functions, dict)
                         else list(selected_functions or []))
            self.narrowdown_capture.append({"kind": "narrowdown_selection",
                             "env_snapshot": dict(env_snapshot),
                             "dispatched_configs": self._dispatched_configs(),
                             "pre_candidate_count": len(getattr(analyzer, "functions_to_be_inspected", {}) or {}),
                             "pre_created_contract_candidates": list(getattr(analyzer, "address_calls_with_created_contract_in_params", {}) or {}),
                             "post_selection_count": len(post_keys),
                             "post_selection_keys": post_keys,
                             "repeated_patterns_count": len(getattr(analyzer, "repeated_patterns", []) or [])})
            if stop_env:
                raise NarrowdownCaptureStop(
                    f"Intentional diagnostic stop after the narrow-down selection boundary "
                    f"({len(post_keys)} functions selected). Payload and raw replies retained in "
                    "_debug.narrowdown_capture. Not a provider or product failure.")
            return original_pccm(analyzer, selected_functions, *args, **kwargs)
        self.replace(FunctionAnalyzer, "_prepare_children_call_memo", capturing_pccm)
        return self

    def _capture_function_verdicts(self, analyzer):
        # Minimal per-function verdict capture (parent directive 2026-11-05
        # 17:38; no engine edit - the run() wrap already holds the analyzer
        # instance). Records what each analyzer's deep analysis PROPOSED and
        # REJECTED, so the micro-loss point between deep analysis and final
        # scoring is evidence, not hypothesis. Observability must never
        # break the run.
        try:
            buckets = getattr(analyzer, "functions_to_be_inspected", None) or {}
            proposals = {}
            for bucket, value in buckets.items():
                res = (value or {}).get("analysis_result") or {}
                pvf = res.get("potentially_vulnerable_functions") or {}
                if isinstance(pvf, dict) and pvf:
                    proposals[bucket] = list(pvf.keys())
            # Sanitized rejection capture (R24 data classification): ids and
            # reasons only; model-generated evidence strings are capped so
            # the artifact never persists large copied fragments.
            rejected = []
            for _r in (getattr(analyzer, "rejected_findings", None) or []):
                if isinstance(_r, dict):
                    rejected.append({k: (str(v)[:200] if isinstance(v, str) else v)
                                     for k, v in _r.items()})
                else:
                    rejected.append(str(_r)[:200])
            with self._verdicts_lock:
                self.function_verdicts.append({
                    "known_buckets": list(buckets.keys()),
                    "proposals": proposals,
                    "rejected_findings": rejected,
                })
        except Exception:
            pass

    def _dispatched_configs(self):
        # Effective configs live on the run's model-endpoint session, recorded
        # at the provider send boundary (ModelEndpointSession.call). Offline
        # runs without a session legitimately have none.
        return deepcopy(list(getattr(self.session, "dispatched_configs", None) or []))

    def _model_config(self, model):
        base_url, env_name = self.source.UniversalAgent._detect_provider(model)
        base_url, env_name = resolve_route(model, base_url, env_name)
        keys = self.model_keys.get(model) or self.source._parse_api_keys(os.getenv(env_name, ""))
        if not keys:
            raise ValueError("The configured model requires an API key.")
        return base_url, keys

    def preflight(self, models, timeout=20):
        if not self.session:
            return
        self.session.route_policy = self._model_config
        # One overall preflight deadline, including any explicitly split stages.
        deadline = self.session.clock() + timeout
        configured = [(model, *self._model_config(model)) for model in dict.fromkeys(models)]
        for model, base_url, keys in configured:
            self.session.model_routes[model] = base_url
            self.session.register_keys(base_url, keys, model=model)
            self.session.preflight(lambda: self.source.OpenAI(api_key=keys[0], base_url=base_url,
                                      max_retries=0, timeout=min(timeout, self.session.call_timeout)),
                                   model, timeout=timeout, deadline=deadline)

    def _trace_call_paths(self):
        # Canonical selector_address -> all child-index paths at which that
        # call appears in THIS run's trace. Trace-identity bound: identity is
        # (address, selector) within this trace only; nothing carries across
        # runs. Used to state structural relations between a citing analysis
        # unit and a cited call - never to infer a causal parent.
        paths = {}
        root = (self.sequence or {}).get("trace")
        if not isinstance(root, dict):
            return paths
        def rec(node, path):
            sel = str(node.get("function") or "").lower()
            addr = str(node.get("address") or "").lower()
            if sel and addr:
                paths.setdefault(f"{sel}_{addr}", []).append(path)
            for i, child in enumerate(node.get("children", []) or []):
                if isinstance(child, dict):
                    rec(child, path + [i])
        rec(root, [])
        return paths

    @staticmethod
    def _trace_relation(paths, cited_key, unit_key):
        # Strongest established structural relation wins; absence of a shared
        # subtree means "referenced" (the trace establishes no parent/child
        # relation - cross-contract and sibling citations land here and stay
        # legitimate unknown suspects, never discarded).
        cited_paths = paths.get(str(cited_key).lower()) or []
        unit_paths = paths.get(str(unit_key).lower()) or []
        best = None
        for unit_path in unit_paths:
            for cited_path in cited_paths:
                if len(cited_path) == len(unit_path) + 1 and cited_path[:-1] == unit_path:
                    return "direct_child"
                if len(cited_path) > len(unit_path) + 1 and cited_path[:len(unit_path)] == unit_path:
                    best = "transitive_descendant"
        return best or "referenced"

    def _annotate_finding_provenance(self, result):
        # Representation repair (2026-11-05): the findings consumer binds a
        # proposed key by identity only (canonical observed call id), so a
        # call cited DURING the analysis of another function is presented as
        # if it were the analyzed target. Bind each finding to its actual
        # per-unit analysis context instead: which analyzed unit cited it,
        # and the trace-established structural relation. A cited call keeps
        # its proposal with role "unknown_suspect" - never promoted to
        # analyzed/vulnerable, never silently excluded. This changes
        # representation only, not any mechanism or causal judgment.
        verdicts = list(self.function_verdicts or [])
        analyzed, cited_by = set(), {}
        for entry in verdicts:
            if not isinstance(entry, dict):
                continue
            for unit, proposed in (entry.get("proposals") or {}).items():
                analyzed.add(str(unit).lower())
                for key in proposed or []:
                    cited_by.setdefault(str(key).lower(), []).append(str(unit).lower())
        if not analyzed and not cited_by:
            return
        paths = self._trace_call_paths()

        def context_for(key):
            # PR1-F1: a function can be BOTH independently analyzed AND cited
            # by another unit. Citation provenance is never overwritten by an
            # analysis record: unknown_suspect + citations are preserved, with
            # independent analysis recorded as a separate fact (also_analyzed).
            # PR1-F2: trace_relation is computed PER citing unit - units can
            # relate to the same call differently (direct child of one,
            # cross-contract reference of another) and must not be collapsed.
            key = str(key).lower()
            units = cited_by.get(key) or []
            if units:
                ctx = {"analysis_role": "unknown_suspect",
                       "citations": [{"unit": unit,
                                      "trace_relation": self._trace_relation(paths, key, unit)}
                                     for unit in units]}
                if key in analyzed:
                    ctx["also_analyzed"] = True
                return ctx
            if key in analyzed:
                return {"analysis_role": "analyzed_target"}
            return {"analysis_role": "unknown_suspect", "citations": [],
                    "trace_relation": "undetermined"}

        pvf = result.get("potentially_vulnerable_functions")
        if isinstance(pvf, dict):
            for key, record in pvf.items():
                if isinstance(record, dict):
                    record["analysis_context"] = context_for(key)
        elif isinstance(pvf, list):
            for record in pvf:
                if isinstance(record, dict):
                    sig = record.get("function_signature") if isinstance(record.get("function_signature"), dict) else record
                    key = f"{sig.get('function', '')}_{sig.get('address', '')}"
                    record["analysis_context"] = context_for(key)
        for coll in ("evidence_cards", "scored_functions"):
            for record in (result.get(coll) or []):
                if isinstance(record, dict):
                    sig = record.get("function_signature") if isinstance(record.get("function_signature"), dict) else record
                    key = f"{sig.get('function', '')}_{sig.get('address', '')}"
                    record["analysis_context"] = context_for(key)
        result["finding_provenance"] = {
            "analyzed_units": sorted(analyzed),
            "note": ("Findings with analysis_role unknown_suspect are retained proposals whose "
                     "vulnerable status is not established: they are neither confirmed vulnerable "
                     "nor dismissed. citations, when present, name each analysis unit that cited "
                     "the finding with its own structural relation in this run's trace only; a "
                     "finding without citations has undetermined provenance - it was neither "
                     "analyzed nor recorded as cited. also_analyzed marks a cited function that "
                     "was additionally analyzed on its own. analyzed_target marks functions the "
                     "analysis unit itself analyzed.")}

    def annotate_result(self, value):
        self.assert_healthy()
        result = deepcopy(value)
        reconcile_calibrated_confidence(result)
        if self.narrowdown_capture or self.ranked_targets or self.function_verdicts:
            dbg = result.setdefault("_debug", {})
            if isinstance(dbg, dict):
                dbg["ranked_targets"] = list(self.ranked_targets)
                dbg["narrowdown_capture"] = deepcopy(self.narrowdown_capture)
                with self._verdicts_lock:
                    dbg["function_verdicts"] = deepcopy(self.function_verdicts)
                dbg["dispatched_configs"] = self._dispatched_configs()
        self._annotate_finding_provenance(result)
        # Score provenance: the priority "exploitability" component IS the
        # deterministic rule's confidence (engine pipeline.py passes
        # rule_confidence as exploitability_score); no function-level model
        # evidence feeds the priority total. Keep the original numbers;
        # label what they are. total = 1 - product(1 - component).
        obs = (self.partial or {}).get("classification") if isinstance(self.partial, dict) else None
        result["score_provenance"] = {
            "formula": "total = 1 - product(1 - component) over the listed components",
            "component_sources": {
                "exploitability": {
                    "source": "deterministic_rule_confidence",
                    "matched_rule": (obs or {}).get("matched_rule"),
                    "meaning": ("Deterministic pre-analysis rule confidence, not an "
                                "exploitability assessment. No function-level model "
                                "evidence feeds the priority score.")}}}
        allowed = {(str(n.get("address", "")).lower(), n["function"].lower()) for n in walk(self.sequence["trace"])} if self.sequence else set()
        unsupported = []
        for item in (result.get("scored_functions") or []) + (result.get("evidence_cards") or []):
            if not isinstance(item, dict):
                continue
            sig = item.get("function_signature") if isinstance(item.get("function_signature"), dict) else item
            pair = (str(sig.get("address") or "").lower(), str(sig.get("function") or "").lower())
            if pair not in allowed:
                unsupported.append(f"{sig.get('function', '?')}@{sig.get('address', '?')}")
        result["analysis_integrity"] = {"function_identity": "calldata_selector", "abi_verified": False,
                                        "ranked_targets": self.ranked_targets, "unverified_targets": unsupported}
        result["trace_provenance"] = deepcopy((self.sequence or {}).get("trace_provenance", {}))
        if self.selector_bindings:
            result["selector_bindings"] = deepcopy(self.selector_bindings)
        if self.selector_resolution_log:
            result["selector_resolutions"] = deepcopy(self.selector_resolution_log)
        # Carry the deterministic forensics observation into completed results
        # the same way failure_report does for partial ones: it is a
        # pre-analysis rule observation, not a verified vulnerability verdict.
        obs = (self.partial or {}).get("classification") if isinstance(self.partial, dict) else None
        if isinstance(obs, dict) and obs.get("rule_verdict"):
            result["deterministic_rule_observation"] = deepcopy(obs)
        result.setdefault("limitations", []).append("Function identities use observed calldata selectors. Human-readable names require verified ABI/source at the execution context; selector-database labels are not proof.")
        if unsupported:
            result["analysis_status"] = "partial"
            result["classification"] = {"rule_verdict": "INCONCLUSIVE"}
            result["limitations"].append("Model output contained function labels that could not be linked to the observed canonical targets. Localization is unverified.")
        rejected = [r for r in (result.get("rejected_findings") or []) if isinstance(r, dict)]
        if rejected:
            # Upstream refused to score model findings whose target could not be
            # bound to an observed call id. Their existence means the model made
            # claims this run could not verify - the run is never "complete".
            result["analysis_status"] = "partial"
            result["classification"] = {"rule_verdict": "INCONCLUSIVE"}
            shown = ", ".join(str(r.get("key", "?"))[:80] for r in rejected[:5])
            result["limitations"].append(
                f"{len(rejected)} model finding(s) had no bindable observed target and were excluded from scoring: {shown}"
                + (" ..." if len(rejected) > 5 else ""))
        # Narrative function names are model-generated labels bound to no ABI;
        # only selectors/addresses are verified identities. Annotate every scored
        # entry, and flag when prose claims a canonical ERC-20 name whose
        # well-known selector contradicts the observed selector.
        CANONICAL = {"approve": "0x095ea7b3", "transferfrom": "0x23b872dd",
                     "transfer": "0xa9059cbb", "balanceof": "0x70a08231",
                     "allowance": "0xdd62ed3e"}
        import re as _re
        name_claim = _re.compile(r"\b(approve|transferFrom|transfer|balanceOf|allowance)\b", _re.I)
        selector_shape = _re.compile(r"^0x[0-9a-f]{8}$")
        contradictions = []
        entries = []
        for e in (result.get("scored_functions") or []) + (result.get("evidence_cards") or []):
            if not isinstance(e, dict):
                continue
            sig = e.get("function_signature") if isinstance(e.get("function_signature"), dict) else e
            entries.append((e, str(sig.get("address") or "").lower(),
                            str(sig.get("function") or "").lower()))
        for entry, address, selector in entries:
            texts = [str(t) for t in (entry.get("evidence") or [])]
            claimed = {m.group(1).lower() for t in texts for m in name_claim.finditer(t)}
            # Contradiction requires a TRACE-VERIFIED identity: the entry's own
            # selector counts only when that exact (address, selector) pair was
            # observed in calldata. Anything else - a bare prose name, or a
            # selector-shaped claim the trace never observed - carries no proof
            # the entry describes a particular invocation, so it stays an
            # unverified label and never produces a contradiction.
            if selector_shape.match(selector or "") and (address, selector) in allowed:
                observed = selector
            else:
                observed = None
            bad = (sorted(n for n in claimed if n in CANONICAL and CANONICAL[n] != observed)
                   if observed else [])
            entry["name_verification"] = ("contradiction: prose claims " + ", ".join(bad)
                                          if bad else "unverified_model_label")
            if bad:
                contradictions.append(f"{selector}: prose claims {', '.join(bad)}")
        result["analysis_integrity"]["function_name_verification"] = (
            "narrative names are unverified model labels; selectors and addresses are the verified identities")
        if contradictions:
            shown = "; ".join(contradictions[:5])
            result.setdefault("limitations", []).append(
                f"Name/selector contradiction(s): {shown}. Narrative names are unverified; selector identity stands."
                + (" ..." if len(contradictions) > 5 else ""))
        if self.session:
            result["model_endpoint"] = self.session.summary()
            calls = result["model_endpoint"].get("calls", {})
            analysis = calls.get("analysis", {"ok": 0, "failed": 0})
            scored = len(result.get("scored_functions") or [])
            cards = len(result.get("evidence_cards") or [])
            result["analysis_integrity"]["model_analysis"] = {
                "analysis_calls_ok": analysis.get("ok", 0), "analysis_calls_failed": analysis.get("failed", 0),
                "preflight_calls_ok": calls.get("preflight", {}).get("ok", 0),
                "scored_functions": scored, "evidence_cards": cards,
                "function_analysis_runs_observed": dict(self.function_analysis)}
            wall = self.wall_cap.summary()
            result["analysis_integrity"]["function_wall_cap"] = wall
            if analysis.get("ok", 0) == 0:
                # No model completion was received for analysis: nothing was analysed,
                # so scores come from deterministic pre-analysis heuristics only.
                result["analysis_status"] = "partial"
                result["stage_completed"] = "deterministic-checks"  # server.py only setdefaults this to stage-3
                result["sections"] = {**(result.get("sections") or {}), "function_analysis": "no_model_analysis", "scoring": "skipped"}
                result["priority_basis"] = "heuristic_preanalysis_estimate"
                result["limitations"].append(
                    "No model analysis completion was received, so priority and exploitability scores are heuristic pre-analysis estimates, not validated findings.")
            elif self.function_analysis["completed"] == 0:
                # Model calls succeeded (e.g. forensics) but the per-function analysis stage
                # was never observed to complete: do not let the server default claim stage-3.
                result["analysis_status"] = "partial"
                result["stage_completed"] = "forensics-only"
                result["sections"] = {**(result.get("sections") or {}), "function_analysis": "not_observed", "scoring": "not_observed"}
                result["priority_basis"] = "heuristic_preanalysis_estimate"
                result["limitations"].append(
                    "Function-level analysis was not observed to complete, so stage coverage beyond forensics is unknown and scores are heuristic pre-analysis estimates.")
            elif scored == 0 and cards == 0:
                result["stage_completed"] = "stage-3"
                # The model ran and legitimately reported no scored function: keep status, label the scores.
                result["priority_basis"] = "heuristic_preanalysis_estimate"
                result["limitations"].append(
                    "The model analysed the run but produced no scored function or evidence card; priority and exploitability are heuristic estimates.")
            else:
                result["stage_completed"] = "stage-3"
                result["priority_basis"] = "model_scored_functions"
            bad = wall["likely_forced"] + wall["unknown_exit"] + wall["error"]
            if bad:
                # The fork returns partial candidates at its wall cap with no flag; a completion
                # marker alone does not prove the function analysis finished.
                result["analysis_status"] = "partial"
                result["stage_completed"] = "function-analysis-partial"  # never leave the stage-3 default on a truncated analysis
                result["sections"] = {**(result.get("sections") or {}), "function_analysis": "partial_wall_cap" if wall["likely_forced"] else ("partial_errors" if wall["error"] else "partial_unverified_exit"), "scoring": "not_validated"}
                result["priority_basis"] = "heuristic_preanalysis_estimate"
                adequate = sum(1 for r in wall["functions"] if r.get("outcome") == "normal" and r.get("detail") == "adequate")
                ceiling = sum(1 for r in wall["functions"] if r.get("outcome") == "normal" and r.get("detail") == "iteration_ceiling")
                capped = ", ".join(f"{r.get('function', '?')} ({r.get('completed_cycles', 0)}/{r.get('ceiling', '?')} cycles)"
                                   for r in wall["functions"] if r.get("outcome") != "normal") or "none"
                result.setdefault("limitations", []).append(
                    f"Function analysis: {wall['normal']} ended normally ({adequate} adequacy-confirmed, {ceiling} iteration-ceiling), "
                    f"{wall['likely_forced']} likely stopped by the {wall['cap_secs']}s per-function wall cap, "
                    f"{wall['unknown_exit']} ended without an observed normal exit, {wall['error']} errored. "
                    f"Non-normal functions: {capped}. Candidates from those functions are partial; scoring is not validated. "
                    "An iteration-ceiling exit is the fork's completion rule, not substantive verification of that function's analysis.")
        if self.source_retention_events:
            _ev = self.source_retention_events
            _bad = [e for e in _ev if e.get("status") in ("source_oversized_unpreserved", "required_evidence_unfit", "bound_source_unverified_outbound")]
            _trim = [e for e in _ev if e.get("status") == "preserved_other_text_trimmed"]
            result["source_retention"] = {
                "prompt_cap": self.PROMPT_CAP, "preserved_with_other_text_trimmed": len(_trim),
                "source_unpreserved": len(_bad), "events": deepcopy(_ev[:20])}
            if _bad:
                result["analysis_status"] = "partial"
                result["stage_completed"] = "function-analysis-partial"
                result["sections"] = {**(result.get("sections") or {}), "function_analysis": "partial_bound_source_unpreserved", "scoring": "not_validated"}
                result.setdefault("limitations", []).append(
                    f"{len(_bad)} model request(s) could not keep the bound source and required evidence intact within the {self.PROMPT_CAP}-character request cap "
                    "(source too large, required evidence did not fit, or the bound source could not be verified in the outbound request); "
                    "the engine cut the request. Those analyses are incomplete and the run is not fully analyzed.")
            if _trim:
                result.setdefault("limitations", []).append(
                    f"{len(_trim)} model request(s) exceeded the {self.PROMPT_CAP}-character cap; only earlier model-written text was shortened (marked inline) to keep the bound source and all evidence intact.")
        return result

    def failure_report(self, error=None):
        result = deepcopy(self.partial or {"transaction": {"hash": self.tx_hash, "chain": self.chain}})
        result["analysis_status"] = "partial" if self.partial else "failed"
        result["analysis_mode"] = "live-pipeline"
        result["stage_completed"] = "deterministic-checks" if self.partial else "none"
        observation = result.pop("classification", {})
        result["deterministic_rule_observation"] = observation
        result["classification"] = {"rule_verdict": "INCONCLUSIVE"}
        failed_during_classification = result.get("sections", {}).get("address_classification") == "failed"
        result["sections"] = {**result.get("sections", {}),
                              "deterministic_checks": "completed" if self.partial else "skipped",
                              "function_analysis": "failed" if self.partial and not failed_during_classification else "skipped", "scoring": "skipped"}
        result["limitations"] = list(result.get("limitations") or []) + [
            "Model-dependent analysis did not complete. Deterministic observations are not a verified vulnerability report."]
        if self.session:
            result["model_endpoint"] = self.session.summary()
        # Preserve the instrumented selection boundary on failure too: a run
        # that dies AFTER the narrow-down still yields the exact payload+reply
        # needed for offline stage evaluation.
        if self.narrowdown_capture or self.ranked_targets:
            result["_debug"] = {"ranked_targets": list(self.ranked_targets),
                                "narrowdown_capture": deepcopy(self.narrowdown_capture),
                                "dispatched_configs": self._dispatched_configs()}
        if isinstance(error, TraceIdentityError):
            result["failure"] = {"kind": "trace_identity", "message": str(error)}
        if isinstance(error, NarrowdownCaptureStop):
            result["failure"] = {"kind": "diagnostic_stop", "message": str(error)}
            result["limitations"].append(
                "Run halted intentionally at the narrow-down selection boundary for payload capture "
                "(FAULTSEEKER_STOP_AFTER_NARROWDOWN=1). No per-function analysis was attempted; "
                "this is a diagnostic measurement, not an analysis failure.")
        result["trace_provenance"] = deepcopy((self.sequence or {}).get("trace_provenance", {}))
        return result

    def close(self):
        for owner, name, original in reversed(self.restorers):
            setattr(owner, name, original)
        self.restorers.clear()


ITERA_DEFAULT_TIME_BUDGET_SECS = 6000.0   # forecast full flow exceeds 1h; stays under the cap below
ITERA_MAX_TIME_BUDGET_SECS = 6600.0       # must stay under the 7200s DEMO_RUN_TIMEOUT_SECS wall cap


def model_time_budget(models=()):
    """Shared model budget. Itera-only runs get a bounded route-specific budget;
    every other model keeps FAULTSEEKER_MODEL_TIME_BUDGET_SECS (default 600)."""
    base = float(os.getenv("FAULTSEEKER_MODEL_TIME_BUDGET_SECS", "600"))
    selected = [str(m) for m in models if m]
    if not selected or not any(m.startswith("itera/") for m in selected):
        return base
    wall = float(os.getenv("DEMO_RUN_TIMEOUT_SECS", "7200"))
    cap = min(ITERA_MAX_TIME_BUDGET_SECS, max(base, wall - 600.0))
    want = float(os.getenv("FAULTSEEKER_ITERA_TIME_BUDGET_SECS", str(ITERA_DEFAULT_TIME_BUDGET_SECS)))
    return max(base, min(want, cap))


def make_runtime(tx_hash, chain, use_model, emit, models=()):
    session = ModelEndpointSession(emit=emit,
        retry_limit=int(os.getenv("FAULTSEEKER_MODEL_RETRY_LIMIT", "3")),
        time_budget=model_time_budget(models),
        call_timeout=float(os.getenv("FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS", os.getenv("FAULTSEEKER_LLM_TIMEOUT_SECS", "60")))) if use_model else None
    runtime = PipelineRuntime(tx_hash, chain, session=session, emit=emit)
    try:
        return runtime.install()
    except Exception:
        runtime.close()
        raise
