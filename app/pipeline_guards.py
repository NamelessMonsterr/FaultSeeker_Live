"""Narrow runtime integration for the external, commit-pinned FaultSeeker pipeline.

Hooks are installed per worker before main() is entered, and removed on exit.
The upstream checkout is not edited. This keeps local and Docker execution on
the same transport/identity policy while retaining the pinned source revision.
"""
from copy import deepcopy
import os

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


class PipelineRuntime:
    def __init__(self, tx_hash, chain, session=None, emit=lambda event: None):
        self.tx_hash, self.chain = tx_hash.lower(), chain.lower()
        self.session = session
        self.emit = emit
        self.partial = None
        self.sequence = None
        self.ranked_targets = []
        self.narrowdown_capture = []
        self.restorers = []
        self.source = None
        self.model_keys = {}
        self.function_analysis = {"started": 0, "completed": 0}  # observed FunctionAnalyzer.run, not inferred
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
        for agent_class in {agent_module.GPTAgent, agent_module.UniversalAgent}:
            original = agent_class._send_message
            def checked_send(agent, *args, _original=original, **kwargs):
                self.assert_healthy()
                try:
                    result = _original(agent, *args, **kwargs)
                except Exception:
                    self.assert_healthy()
                    raise
                self.assert_healthy()  # Upstream may have swallowed an APIStatusError.
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
        return self

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

    def annotate_result(self, value):
        self.assert_healthy()
        result = deepcopy(value)
        if self.narrowdown_capture or self.ranked_targets:
            dbg = result.setdefault("_debug", {})
            if isinstance(dbg, dict):
                dbg["ranked_targets"] = list(self.ranked_targets)
                dbg["narrowdown_capture"] = deepcopy(self.narrowdown_capture)
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
        if isinstance(error, TraceIdentityError):
            result["failure"] = {"kind": "trace_identity", "message": str(error)}
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
