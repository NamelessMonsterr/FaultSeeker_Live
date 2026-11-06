"""Narrow runtime integration for the external, commit-pinned FaultSeeker pipeline.

Hooks are installed per worker before main() is entered, and removed on exit.
The upstream checkout is not edited. This keeps local and Docker execution on
the same transport/identity policy while retaining the pinned source revision.
"""
from copy import deepcopy, copy
import os
import json
import re
import time
import threading
import inspect

try:
    from .failure_diagnostics import failure_diagnostics, safe_retrieval_record
    from .retrieval_contract import RetrievalContractMixin, shape as retrieval_shape
except ImportError:
    from failure_diagnostics import failure_diagnostics, safe_retrieval_record
    from retrieval_contract import RetrievalContractMixin, shape as retrieval_shape

_MISSING = object()

try:
    from .model_endpoint import ModelEndpointSession, ModelEndpointFailure
    from .model_routes import ITERA_DEFAULT_BASE_URL, INCEPTION_DEFAULT_BASE_URL, resolve_route, model_call_timeout
    from .trace_identity import TraceIdentityError, canonical_to_legacy, check_structured, validate_trace_root
except ImportError:  # app/server.py invoked directly
    from model_endpoint import ModelEndpointSession, ModelEndpointFailure
    from model_routes import ITERA_DEFAULT_BASE_URL, INCEPTION_DEFAULT_BASE_URL, resolve_route, model_call_timeout
    from trace_identity import TraceIdentityError, canonical_to_legacy, check_structured, validate_trace_root


try:
    from .explorer_trace import payload_from_explorer, pro_rpc, PRO_CHAINS, EXPLORER_TRACE_INSTANCES as EXPLORER_CHAINS
except ImportError:
    from explorer_trace import payload_from_explorer, pro_rpc, PRO_CHAINS, EXPLORER_TRACE_INSTANCES as EXPLORER_CHAINS
CHAIN_IDS = {"eth": 1, "bsc": 56, "polygon": 137, "arbitrum": 42161,
             "optimism": 10, "avalanche": 43114, "base": 8453, "fantom": 250,
             "zksync": 324, "linea": 59144, "scroll": 534352, "gnosis": 100,
             "celo": 42220, "cronos": 25, "moonbeam": 1284, "aurora": 1313161554}


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
        self.selection_coverage = []
        self.completed_analysis_units = []
        self.checkpoint_sink = None
        self.checkpoint_lock = threading.RLock()
        self.retrieval_diagnostics = []
        self.retrieval_incomplete = False
        self.retrieval_diagnostics_omitted = 0
        self.rejected_finding_observations = []
        self.rejected_finding_observations_omitted = 0
        self.abi_context = None
        self.abi_lock = threading.RLock()
        self.abi_observations = {}
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
        original = getattr(owner, name, _MISSING)
        stored = vars(owner).get(name, _MISSING)
        self.restorers.append((owner, name, stored))
        setattr(owner, name, replacement)
        return original

    def record_retrieval_issues(self, records):
        with self.checkpoint_lock:
            for record in records:
                if not isinstance(record, dict) or record.get('status') not in ('unavailable', 'failed'):
                    continue
                safe = safe_retrieval_record(record)
                self.retrieval_incomplete = True
                if not self.retrieval_diagnostics or self.retrieval_diagnostics[-1] != safe:
                    self.retrieval_diagnostics.append(safe)
            self.retrieval_diagnostics_omitted += max(0, len(self.retrieval_diagnostics) - 200)
            self.retrieval_diagnostics = self.retrieval_diagnostics[-200:]
            if self.retrieval_incomplete and self.partial is not None and self.checkpoint_sink is not None:
                self.checkpoint_sink(self.failure_report())

    def retrieval_report_fields(self, result):
        integrity = result.setdefault('analysis_integrity', {})
        integrity['rejected_finding_observations'] = deepcopy(self.rejected_finding_observations)
        integrity['rejected_finding_observations_omitted'] = self.rejected_finding_observations_omitted
        integrity['retrieval_diagnostics'] = deepcopy(self.retrieval_diagnostics)
        integrity['retrieval_incomplete'] = self.retrieval_incomplete
        integrity['retrieval_diagnostics_omitted'] = self.retrieval_diagnostics_omitted
        if self.retrieval_incomplete:
            result['analysis_status'] = 'partial'
            result['stage_completed'] = 'function-analysis-partial'
            result['classification'] = {'rule_verdict': 'INCONCLUSIVE'}
            sections = result.setdefault('sections', {})
            sections['function_analysis'] = 'partial_missing_evidence'
            if sections.get('scoring') != 'skipped':
                sections['scoring'] = 'not_validated'
            result.setdefault('limitations', []).append(
                'Requested evidence was unavailable or invalid. This is not evidence of no calls or safety; model findings and scores remain unverified.')
        return result

    def assert_healthy(self):
        if self.session:
            self.session.assert_healthy()

    def reserve_finding_repair(self):
        if self.session is None:
            return True
        with self.session.state_lock:
            if self.session.failure is not None:
                raise self.session.failure
            if self.session.retries_left <= 0 or self.session.spent >= self.session.time_budget:
                return False
            self.session.retries_left -= 1
            remaining = self.session.retries_left
        self.emit({'state': 'waiting_on_model_endpoint', 'phase': 'analysis',
                   'completion_problem': 'unobserved_finding_target',
                   'retry_in_seconds': 0, 'retries_remaining': remaining})
        return True

    def checkpoint_analysis(self, analyzer, kind):
        """Snapshot a returned unit without ranking or verifying its conclusions."""
        with self.checkpoint_lock:
            if self.partial is None:
                self.partial = {'transaction': {'hash': self.tx_hash, 'chain': self.chain}}
            previous = deepcopy(self.partial.get('potentially_vulnerable_functions', {}))
            for target, finding in getattr(analyzer, 'potentially_vulnerable_functions', {}).items():
                if not isinstance(finding, dict):
                    raise ValueError('Invalid checkpoint finding')
                entry = deepcopy(finding)
                entry.update(status='unranked/unverified', ranking_status='unranked')
                if target in previous:
                    for field in ('evidence', 'confidence_score'):
                        old, new = previous[target].get(field, []), entry.get(field, [])
                        if isinstance(old, list) and isinstance(new, list):
                            entry[field] = old + [item for item in new if item not in old]
                previous[target] = entry
            summary = getattr(analyzer, 'function_call_info_summary', {}) or {}
            self.completed_analysis_units.append({'kind': kind,
                'function': summary.get('function'), 'address': summary.get('address'),
                'status': 'returned; conclusions unverified'})
            self.partial['potentially_vulnerable_functions'] = previous
            self.partial['preliminary_findings'] = [{'target': key, **value} for key, value in previous.items()]
            if self.checkpoint_sink is not None:
                self.checkpoint_sink(self.failure_report())

    def lookup_abi(self, address, selector):
        allowed = {(str(n.get("address", "")).lower(), n.get("function"))
                   for n in walk(self.sequence["trace"])} if self.sequence else set()
        target = (str(address).lower(), selector)
        if target not in allowed:
            return {"status": "unobserved_target"}
        with self.abi_lock:
            if self.abi_context is None:
                try:
                    from .verified_abi_context import VerifiedABIContext
                except ImportError:
                    from verified_abi_context import VerifiedABIContext
                endpoint = (os.getenv(f"{self.chain.upper()}_ABI_RPC_URL")
                            or os.getenv("FAULTSEEKER_ABI_RPC_URL"))
                block = (self.sequence.get("trace_provenance") or {}).get("block_number")
                self.abi_context = VerifiedABIContext(CHAIN_IDS[self.chain], block, endpoint)
            context = self.abi_context.lookup(address, selector)
            self.abi_observations[target] = deepcopy(context)
            return context

    def selection_abi_context(self, targets):
        facts, unverified, omitted = [], 0, 0
        for target in targets:
            selector, address = target.rsplit("_", 1)
            context = self.lookup_abi(address, selector)
            if context.get("status") != "verified":
                unverified += 1
                continue
            fact = {"target": target, "function_name": context["abi"]["name"],
                    "scope": context["scope"]}
            if len(json.dumps(facts + [fact])) > 4000:
                omitted += 1
            else:
                facts.append(fact)
        if not facts:
            return ""
        return ("Verified interface evidence (data, not vulnerability findings). Keep canonical target keys; "
                "do not infer semantics for unverified selectors. " + json.dumps({
                    "facts": facts, "unverified_target_count": unverified,
                    "omitted_verified_target_count": omitted}) + "\n")

    def worker_abi_context(self):
        """Already-bound interface facts only; never fetch during worker setup."""
        facts, omitted, unverified = [], 0, 0
        with self.abi_lock:
            records = deepcopy(self.abi_observations)
        for (address, selector), context in records.items():
            if context.get("status") != "verified":
                unverified += 1
                continue
            fact = {"target": selector + "_" + address,
                    "function_name": context["abi"]["name"], "scope": context["scope"]}
            if len(json.dumps(facts + [fact])) > 4000:
                omitted += 1
            else:
                facts.append(fact)
        return {"facts": facts, "unverified_target_count": unverified,
                "omitted_verified_target_count": omitted,
                "meaning": "Interface identities only; these facts do not establish a vulnerability."}

    def install_model_hooks(self, agent_module):
        if not self.session:
            return
        if self.source is not None:
            self.session.route_policy = self._model_config
        if hasattr(agent_module, "_llm_call_with_retry"):
            def paced_call(*args, **kwargs):
                pacing = float(os.getenv("FAULTSEEKER_MODEL_PACING_SECS", "0"))
                if pacing > 0:
                    time.sleep(pacing)
                return self.session.call(*args, **kwargs)
            self.replace(agent_module, "_llm_call_with_retry", paced_call)
        legacy_transport = (not hasattr(agent_module, "_llm_call_with_retry")
                            and callable(getattr(agent_module, "OpenAI", None)))
        config = getattr(agent_module, "PROVIDER_CONFIG", None)
        if isinstance(config, dict) and "itera/" not in config:
            # The pinned pipeline sends any unknown model prefix to a local Ollama
            # agent. Register the operator-selected Itera alias so it uses the
            # OpenAI-compatible agent whose calls the shared transport owns.
            self.replace(agent_module, "PROVIDER_CONFIG",
                         {**config, "itera/": (ITERA_DEFAULT_BASE_URL, "ITERA_API_KEY")})
        config = getattr(agent_module, "PROVIDER_CONFIG", None)
        if isinstance(config, dict) and "inception/" not in config:
            self.replace(agent_module, "PROVIDER_CONFIG",
                         {**config, "inception/": (INCEPTION_DEFAULT_BASE_URL, "INCEPTION_API_KEY")})
        for agent_class in {agent_module.GPTAgent, agent_module.UniversalAgent}:
            if hasattr(agent_class, '_truncate_history'):
                original_history = agent_class._truncate_history
                history_turns = inspect.signature(original_history).parameters['max_turns'].default
                def paired_history(agent, history, max_turns=history_turns):
                    messages = history[1:]
                    pending = bool(messages and messages[-1].get('role') == 'user')
                    keep = max_turns * 2 + int(pending)
                    return history[:1] + (messages[-keep:] if keep else [])
                self.replace(agent_class, '_truncate_history', paired_history)
            original = agent_class._send_message
            if legacy_transport:
                # Older development agents call the SDK directly and swallow its
                # errors. Replace that boundary rather than allowing calls to
                # bypass the shared circuit, route/key policy and SDK retry cap.
                original = self._legacy_shared_send(agent_module, agent_class is agent_module.GPTAgent)
            mercury_send = self._legacy_shared_send(agent_module, agent_class is agent_module.GPTAgent)
            def checked_send(agent, *args, _original=original, _mercury=mercury_send, **kwargs):
                self.assert_healthy()
                try:
                    send = _mercury if str(getattr(agent, "model", "")).startswith(("inception/", "itera/")) else _original
                    result = send(agent, *args, **kwargs)
                except Exception:
                    self.assert_healthy()
                    raise
                self.assert_healthy()  # Upstream may have swallowed an APIStatusError.
                return result
            self.replace(agent_class, "_send_message", checked_send)
            parse_state = threading.local()
            if hasattr(agent_class, "_extract_json"):
                original_extract = agent_class._extract_json
                def checked_extract(agent, *args, _original=original_extract, _state=parse_state, **kwargs):
                    frame = getattr(_state, "frame", None)
                    try:
                        result = _original(agent, *args, **kwargs)
                    except ValueError:
                        if frame is not None:
                            frame["failed"] = True
                        raise
                    if frame is not None:
                        frame["failed"] = False
                    return result
                self.replace(agent_class, "_extract_json", checked_extract)
            if hasattr(agent_class, "query"):
                original_query = agent_class.query
                def checked_query(agent, *args, _original=original_query, _state=parse_state, **kwargs):
                    self.assert_healthy()
                    previous = getattr(_state, "frame", None)
                    frame = {"failed": False}
                    _state.frame = frame
                    try:
                        result = _original(agent, *args, **kwargs)
                        if frame["failed"]:
                            failure = ModelEndpointFailure("invalid_response", completion_problem="invalid_json")
                            if self.session:
                                with self.session.state_lock:
                                    self.session.failure = self.session.failure or failure
                            raise failure
                    except Exception:
                        self.assert_healthy()
                        raise
                    finally:
                        _state.frame = previous
                    self.assert_healthy()  # Upstream query may catch send/parse failures.
                    return result
                self.replace(agent_class, "query", checked_query)

    def _legacy_shared_send(self, agent_module, is_gpt):
        """Adapt the older direct-SDK agent contract to the shared transport.

        The pinned retry-helper path remains unchanged. Keep the legacy prompt,
        history, JSON-mode and usage-recording behavior, but propagate failures.
        Complete inputs are preserved without silent truncation.
        """
        def send(agent, user_message, temperature=0, force_json=True):
            started = time.monotonic()
            append = getattr(agent, "_append_memory", agent.memory.append)
            append({"role": "user", "content": user_message})
            messages = agent._truncate_history(agent.memory)
            request = {"messages": list(messages),
                       "model": agent.model, "temperature": temperature}
            if force_json and (agent.model in agent_module.JSON_MODE_MODELS or (is_gpt and agent.model.startswith(
                    ("gpt-4o", "gpt-4.1", "gpt-4-turbo")))):
                request["response_format"] = {"type": "json_object"}
            def factory():
                endpoint, keys = self._model_config(agent.model)
                return agent_module.OpenAI(api_key=keys[0], base_url=endpoint, max_retries=0)
            pacing = float(os.getenv("FAULTSEEKER_MODEL_PACING_SECS", "0"))
            if pacing > 0:
                time.sleep(pacing)
            completion = self.session.call(factory, request, agent.model)
            reply = completion.choices[0].message.content
            append({"role": "assistant", "content": reply})
            usage = getattr(completion, "usage", None)
            agent._record_router_query(len(user_message), len(reply),
                (time.monotonic() - started) * 1000,
                input_tokens=getattr(usage, "prompt_tokens", None),
                output_tokens=getattr(usage, "completion_tokens", None))
            return reply
        return send

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
        if os.getenv("FAULTSEEKER_VISITOR_RPC_RELAY"):
            # Forked workers may inherit a registry populated by a prior diagnostic.
            # Rebuild it after the visitor URL was replaced with the checked relay.
            if not hasattr(rpc_provider, "_ChainRegistry") or not hasattr(rpc_provider, "_registry"):
                raise RuntimeError("Pipeline cannot isolate the visitor RPC registry.")
            self.replace(rpc_provider, "_registry", rpc_provider._ChainRegistry())
        self.install_model_hooks(agents)

        # Ship the same contract with the console so the immutable external pin
        # receives the fix too. Added methods are removed again by close().
        for name, method in vars(RetrievalContractMixin).items():
            if callable(method) and name.startswith('_') and not name.startswith('__'):
                self.replace(FunctionAnalyzer, name, method)
        retrieve = FunctionAnalyzer._retrieve_additional_info
        def observed_retrieval(analyzer, *args, **kwargs):
            try:
                result = retrieve(analyzer, *args, **kwargs)
            except Exception as error:
                diagnostic = getattr(error, 'diagnostics', None)
                record = {'operation': 'request', 'status': 'unavailable',
                          **(diagnostic if isinstance(diagnostic, dict) else {
                              'reason': 'unexpected_exception',
                              'request_shape': retrieval_shape(args[0] if args else None)})}
                self.record_retrieval_issues([record])
                raise
            self.record_retrieval_issues(result.get('retrieval_status', []))
            return result
        self.replace(FunctionAnalyzer, '_retrieve_additional_info', observed_retrieval)

        original_structured = TransactionReplayer.get_structured_trace
        def checked_structured(replayer, tx_hash, chain):
            payload, trace_error = None, None
            mode = os.getenv("FAULTSEEKER_EXPLORER_TRACE", "")
            if mode == "direct" and chain not in EXPLORER_CHAINS:
                # Fail closed: falling back to the normal RPC trace path could spend provider credits.
                raise TraceIdentityError("Direct explorer trace mode is not supported for this chain.")
            if mode == "direct":
                # Direct mode: never ask an RPC node for a trace first (a configured trace RPC may be billable).
                trace_error = None
            else:
                try:
                    payload = check_structured(original_structured(replayer, tx_hash, chain), tx_hash, chain)
                except Exception as exc:
                    # Opt-in keyless explorer trace for chains where the RPC trace is unavailable; default is off.
                    if mode != "1" or chain not in EXPLORER_CHAINS:
                        raise
                    trace_error = exc
            # The PRO gateway is used for identity only when the explorer path is actually engaged (payload is None here);
            # a normal RPC trace, or the flag being off, keeps reading the console RPC registry.
            use_pro = payload is None and chain in PRO_CHAINS
            read = (lambda method, params: pro_rpc(chain, method, params)) if use_pro else (lambda method, params: rpc_call(chain, method, params, timeout=15))
            tx = read("eth_getTransactionByHash", [tx_hash])
            network = read("eth_chainId", [])
            try:
                actual_chain = int(network, 16) if isinstance(network, str) else int(network)
            except (ValueError, TypeError):
                raise TraceIdentityError("RPC chain identity could not be established.") from None
            if actual_chain != CHAIN_IDS.get(chain):
                raise TraceIdentityError("RPC network does not match the selected chain.")
            if payload is None:
                try:
                    payload = payload_from_explorer(chain, tx_hash, tx, actual_chain)
                except TraceIdentityError:
                    raise
                except Exception as exc:
                    # Surface the real explorer failure; keep the RPC trace error as context when there is one.
                    if trace_error is not None:
                        raise exc from trace_error
                    raise
            root = payload["trace"]
            receipt = None
            if isinstance(tx, dict) and tx.get("to") is None:
                receipt = read("eth_getTransactionReceipt", [tx_hash])
            validate_trace_root(tx, root, tx_hash, receipt)
            payload = deepcopy(payload)
            payload["trace_provenance"] = {
                **(payload.get("trace_provenance") or {}),
                "source": (payload.get("trace_provenance") or {}).get("source", "structured_rpc_or_cache"),
                "identity_cross_check": "eth_getTransactionByHash + eth_chainId",
                "identity_source": "blockscout_pro_json_rpc" if use_pro else "console_rpc_registry",
                "identity_independent_of_trace_source": False if use_pro else None,  # None: not established for registry reads
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
            result = original_rank(ranker, *args, **kwargs)
            allowed = {f"{n['function']}_{n['address']}".lower() for n in walk(self.sequence["trace"])}
            if any(key.lower() not in allowed for key in result.functions_to_be_inspected):
                raise TraceIdentityError("Ranked target is not an observed canonical selector/address pair.")
            self.ranked_targets = list(result.functions_to_be_inspected)
            return result
        self.replace(FunctionRanker, "rank", checked_rank)

        original_source = FunctionAnalyzer._retrieve_source_code
        def verified_source(analyzer, address, selector):
            context = self.lookup_abi(address, selector)
            if context.get("status") == "disabled":
                return original_source(analyzer, address, selector)
            if context.get("status") != "verified":
                return []
            with self.abi_lock:
                source = self.abi_context.source_for(address, selector)
                binding = {key: value for key, value in source.items() if key != "sources"}
                self.abi_observations[(address.lower(), selector)] = {
                    **context, "source_binding": deepcopy(binding)}
            return deepcopy(source.get("sources", [])) if source.get("status") == "verified" else []
        self.replace(FunctionAnalyzer, "_retrieve_source_code", verified_source)

        original_related = FunctionAnalyzer._retrieve_related_info
        def with_verified_abi(analyzer, address, function_name):
            result = original_related(analyzer, address, function_name)
            context = self.lookup_abi(address, function_name)
            if context.get("status") != "disabled":
                result["verified_abi_context"] = context
            return result
        self.replace(FunctionAnalyzer, "_retrieve_related_info", with_verified_abi)

        original_review = FunctionAnalyzer._review_function_calls
        def review_with_abi(analyzer, *args, **kwargs):
            orig_funcs = analyzer.functions_to_be_inspected
            orig_created = getattr(analyzer, 'address_calls_with_created_contract_in_params', None)
            orig_patterns = getattr(analyzer, 'repeated_patterns', None)
            coverage = {'status': 'partial', 'available': {
                'functions': len(orig_funcs), 'created_contracts': len(orig_created or {}),
                'patterns': len(orig_patterns or [])},
                'completed': {'functions': 0, 'created_contracts': 0, 'patterns': 0},
                'batches_completed': 0,
                'scope': 'Candidates presented to upstream review; model selection is not exhaustive analysis.'}
            self.selection_coverage.append(coverage)
            try:
                # Bound the selection payload, not the eligible target set. Every
                # batch uses the same installed agents and run-wide retry budget.
                batches, current = [], {}
                for key, value in orig_funcs.items():
                    candidate = {**current, key: value}
                    def payload_size(items):
                        return len(json.dumps({k: {'count_of_appearance': v['count'],
                            'example_calls': v['calls'][:3]} for k, v in items.items()}).encode('utf-8'))
                    if current and (len(candidate) > 25 or payload_size(candidate) > 16000):
                        batches.append(current)
                        current = {key: value}
                    else:
                        current = candidate
                    if payload_size(current) > 16000:
                        # A single oversized candidate must fail visibly; silently
                        # truncating its evidence would corrupt the analysis.
                        raise ModelEndpointFailure('input_budget_exceeded')
                if current:
                    batches.append(current)
                created = list((orig_created or {}).items())
                patterns = orig_patterns or []
                batch_count = max(len(batches), (len(created)+4)//5, (len(patterns)+4)//5, 1)
                # Run-wide progress framing: engine [current/total] lines below are
                # per-batch; without this header a finished batch reads as a
                # finished run.
                print(f"         [review plan] {len(orig_funcs)} functions + {len(patterns)} repeated patterns + "
                      f"{len(created)} created-contract groups across {batch_count} batches; "
                      f"[current/total] lines are per batch", flush=True)
                for index in range(batch_count):
                    self.assert_healthy()
                    analyzer.functions_to_be_inspected = batches[index] if index < len(batches) else {}
                    analyzer.address_calls_with_created_contract_in_params = dict(created[index*5:index*5+5])
                    analyzer.repeated_patterns = patterns[index*5:index*5+5]
                    print(f"         [batch {index + 1}/{batch_count}] presenting {len(analyzer.functions_to_be_inspected)} functions, "
                          f"{len(analyzer.repeated_patterns)} patterns, "
                          f"{len(analyzer.address_calls_with_created_contract_in_params)} created-contract groups", flush=True)
                    evidence = self.selection_abi_context(analyzer.functions_to_be_inspected)
                    original_prompts = analyzer.function_prompts
                    if evidence:
                        analyzer.function_prompts = copy(original_prompts)
                        literal = evidence.replace('{', '{{').replace('}', '}}')
                        for name in ('narrow_down_functions', 'narrow_down_functions_with_created_contracts'):
                            setattr(analyzer.function_prompts, name, literal + getattr(original_prompts, name))
                    try:
                        original_review(analyzer, *args, **kwargs)
                        self.assert_healthy()
                    finally:
                        analyzer.function_prompts = original_prompts
                    for name, amount in [('functions', len(analyzer.functions_to_be_inspected)),
                                         ('created_contracts', len(analyzer.address_calls_with_created_contract_in_params)),
                                         ('patterns', len(analyzer.repeated_patterns))]:
                        coverage['completed'][name] += amount
                    coverage['batches_completed'] += 1

                    # Unit hooks own the accumulated observations. The parent's
                    # current map may contain only the latest function/pattern;
                    # copying it here would overwrite earlier completed work.
                    if self.partial is None:
                        self.partial = {"transaction": {"hash": self.tx_hash, "chain": self.chain}}
                    self.partial.setdefault('potentially_vulnerable_functions', {})
                    self.partial.setdefault('preliminary_findings', [])
                    self.partial["batches_completed"] = coverage["batches_completed"]
                    self.partial["total_batches"] = batch_count
                    self.partial["selection_coverage"] = deepcopy(self.selection_coverage)
                    if self.checkpoint_sink is not None:
                        self.checkpoint_sink(self.failure_report())
                coverage['status'] = 'completed'
                print(f"         [review complete] all {batch_count}/{batch_count} batches finished", flush=True)
            finally:
                analyzer.functions_to_be_inspected = orig_funcs
                if orig_created is not None:
                    analyzer.address_calls_with_created_contract_in_params = orig_created
                if orig_patterns is not None:
                    analyzer.repeated_patterns = orig_patterns
        self.replace(FunctionAnalyzer, "_review_function_calls", review_with_abi)

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
            original_init = getattr(FunctionAnalyzer, _name)
            # Candidate loops use the live provider registry; the immutable pin
            # uses its historical prefix tuple. Observe the same policy as the loop.
            local_policy = original_init.__globals__.get("is_local_model")
            def with_worker_interfaces(analyzer, *args, _original=original_init, **kwargs):
                context = self.worker_abi_context()
                if context["facts"]:
                    analyzer.function_call_info_summary = {
                        **analyzer.function_call_info_summary, "verified_interfaces": context}
                return _original(analyzer, *args, **kwargs)
            self.replace(FunctionAnalyzer, _name, with_worker_interfaces)
            if hasattr(FunctionAnalyzer, _name):
                self.replace(FunctionAnalyzer, _name, self.wall_cap.wrap(
                    getattr(FunctionAnalyzer, _name), _kind,
                    is_local_model=local_policy if callable(local_policy) else None))
                completed = getattr(FunctionAnalyzer, _name)
                def checkpointed(analyzer, *args, _original=completed, _kind=_kind, **kwargs):
                    result = _original(analyzer, *args, **kwargs)
                    self.checkpoint_analysis(analyzer, _kind)
                    return result
                self.replace(FunctionAnalyzer, _name, checkpointed)
        self.replace(FunctionAnalyzer, '_reserve_finding_repair', lambda analyzer: self.reserve_finding_repair())
        original_update = FunctionAnalyzer._update_potentially_vulnerable_function
        has_recovery = hasattr(FunctionAnalyzer, '_update_potentially_vulnerable_function_once')
        def recover_update(analyzer, *args, **kwargs):
            previous = getattr(analyzer, 'finding_rejection_count', 0)
            try:
                if has_recovery:
                    return original_update(analyzer, *args, **kwargs)
                return analyzer._recover_finding_update(lambda: original_update(analyzer, *args, **kwargs))
            finally:
                records = getattr(analyzer, 'rejected_finding_observations', [])
                with self.checkpoint_lock:
                    # Each update can add at most two records. A bounded local
                    # buffer may already be full, so observe the retained tail.
                    added = getattr(analyzer, 'finding_rejection_count', 0) - previous
                    new = records[-added:] if added else []
                    self.rejected_finding_observations.extend(deepcopy(new))
                    self.rejected_finding_observations_omitted += max(0, len(self.rejected_finding_observations)-200)
                    self.rejected_finding_observations = self.rejected_finding_observations[-200:]
                self.record_retrieval_issues(getattr(analyzer, 'retrieval_diagnostics', []))
        self.replace(FunctionAnalyzer, "_update_potentially_vulnerable_function",
                     self.wall_cap.wrap_update(recover_update))
        return self

    def _model_config(self, model):
        base_url, env_name = self.source.UniversalAgent._detect_provider(model)
        base_url, env_name = resolve_route(model, base_url, env_name)
        keys = self.model_keys.get(model)
        if not keys:
            raw = os.getenv(env_name, "")
            parser = getattr(self.source, "_parse_api_keys", None)
            if callable(parser):
                keys = parser(raw)
            else:
                # Current development lacks the pinned parser. Preserve its
                # supported separators/assignment handling without SDK key reuse.
                keys = []
                for token in re.split(r"[\s,;]+", raw.strip()):
                    token = token.strip().strip('"').strip("'")
                    if "=" in token:
                        name, _, token = token.partition("=")
                        if "API_KEY" not in name:
                            continue
                    if token.strip():
                        keys.append(token.strip())
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
                                        "ranked_targets": self.ranked_targets, "unverified_targets": unsupported,
                                        "selection_coverage": deepcopy(self.selection_coverage)}
        result["verified_abi_context"] = [{"address": address, "selector": selector, **deepcopy(context)}
            for (address, selector), context in self.abi_observations.items() if context.get("status") != "disabled"]
        result["trace_provenance"] = deepcopy((self.sequence or {}).get("trace_provenance", {}))
        result.setdefault("limitations", []).append("Function identities use observed calldata selectors. Human-readable names require verified ABI/source at the execution context; selector-database labels are not proof.")
        if self.selection_coverage:
            result['limitations'].append('Candidates were reviewed in payload-bounded batches. Model shortlisting is selective; completed review does not mean every observed function was analysed.')
        if any(item['status'] != 'completed' for item in self.selection_coverage):
            result['analysis_status'] = 'partial'
            result['classification'] = {'rule_verdict': 'INCONCLUSIVE'}
            result['limitations'].append('Candidate review was interrupted; some candidate batches were not completed.')
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
                result.setdefault("limitations", []).append(
                    f"Function analysis: {wall['normal']} ended normally, {wall['likely_forced']} likely stopped by the {wall['cap_secs']}s per-function wall cap, "
                    f"{wall['unknown_exit']} ended without an observed normal exit, {wall['error']} errored. Candidates from those functions are partial; scoring is not validated.")
        return self.retrieval_report_fields(result)

    def failure_report(self, error=None):
        if getattr(error, 'kind', None) == 'retrieval_contract':
            self.retrieval_incomplete = True
            record = safe_retrieval_record(getattr(error, 'diagnostics', {}))
            if record and (not self.retrieval_diagnostics or self.retrieval_diagnostics[-1] != record):
                self.retrieval_diagnostics.append(record)
                self.retrieval_diagnostics_omitted += max(0, len(self.retrieval_diagnostics) - 200)
                self.retrieval_diagnostics = self.retrieval_diagnostics[-200:]
        result = deepcopy(self.partial or {"transaction": {"hash": self.tx_hash, "chain": self.chain}})
        result["analysis_status"] = "partial" if self.partial else "failed"
        result["analysis_mode"] = "live-pipeline"
        has_batch_work = bool(self.completed_analysis_units) or bool(result.get("potentially_vulnerable_functions")) or (
            self.selection_coverage and any(c.get("batches_completed", 0) > 0 for c in self.selection_coverage)
        )
        if has_batch_work:
            result["stage_completed"] = "function-analysis-partial"
        else:
            result["stage_completed"] = "deterministic-checks" if self.partial else "none"

        observation = result.pop("classification", {})
        result["deterministic_rule_observation"] = observation
        result["classification"] = {"rule_verdict": "INCONCLUSIVE"}
        failed_during_classification = result.get("sections", {}).get("address_classification") == "failed"
        result["sections"] = {**result.get("sections", {}),
                              "deterministic_checks": "completed" if self.partial else "skipped",
                              "function_analysis": "partial_interrupted" if has_batch_work else ("failed" if self.partial and not failed_during_classification else "skipped"),
                              "scoring": "skipped"}
        limitations = list(result.get("limitations") or []) + [
            "Model-dependent analysis did not complete. Deterministic observations are not a verified vulnerability report."]
        if has_batch_work:
            limitations.append(
                "Function analysis was interrupted before ranking and validation; preliminary findings are unranked and unverified.")
        result["limitations"] = limitations
        endpoint_summary = self.session.summary() if self.session else None
        if endpoint_summary is not None:
            result["model_endpoint"] = endpoint_summary
        wall = self.wall_cap.summary()
        endpoint_calls = (endpoint_summary or {}).get("calls", {})
        result["analysis_integrity"] = {
            "function_identity": "calldata_selector",
            "abi_verified": False,
            "trace_identity_checked": self.sequence is not None,
            "ranked_targets": list(self.ranked_targets),
            "unverified_targets": None,
            "target_validation": "not_assessed",
            "failure_path": True,
            "selection_coverage": deepcopy(self.selection_coverage),
            "function_analysis_runs_observed": dict(self.function_analysis),
            "function_wall_cap": wall,
            "preliminary_findings": deepcopy(result.get("preliminary_findings", [])),
            "completed_analysis_units": deepcopy(self.completed_analysis_units),
            "model_analysis": {
                "analysis_calls_ok": endpoint_calls.get("analysis", {}).get("ok", 0),
                "analysis_calls_failed": endpoint_calls.get("analysis", {}).get("failed", 0),
                "preflight_calls_ok": endpoint_calls.get("preflight", {}).get("ok", 0),
                "function_analysis_runs_observed": dict(self.function_analysis),
            },
        }
        if wall["likely_forced"] or wall["unknown_exit"] or wall["error"]:
            result["analysis_integrity"]["function_analysis_complete"] = False
        else:
            result["analysis_integrity"]["function_analysis_complete"] = self.function_analysis["completed"] > 0
        if isinstance(error, TraceIdentityError):
            result["failure"] = {"kind": "trace_identity", "message": str(error)}
        elif error is not None:
            result["failure"] = {"kind": getattr(error, "kind", type(error).__name__)}
        if error is not None:
            result['analysis_integrity']['failure_diagnostics'] = failure_diagnostics(error)
        result["verified_abi_context"] = [{"address": address, "selector": selector, **deepcopy(context)}
            for (address, selector), context in self.abi_observations.items() if context.get("status") != "disabled"]
        result["trace_provenance"] = deepcopy((self.sequence or {}).get("trace_provenance", {}))
        return self.retrieval_report_fields(result)

    def close(self):
        for owner, name, original in reversed(self.restorers):
            if original is _MISSING:
                delattr(owner, name)
            else:
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
        call_timeout=model_call_timeout(models)) if use_model else None
    if session:
        session.model_timeouts = {model: model_call_timeout([model]) for model in models if model}
    runtime = PipelineRuntime(tx_hash, chain, session=session, emit=emit)
    try:
        return runtime.install()
    except Exception:
        runtime.close()
        raise
