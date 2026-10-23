"""Narrow runtime integration for the external, commit-pinned FaultSeeker pipeline.

Hooks are installed per worker before main() is entered, and removed on exit.
The upstream checkout is not edited. This keeps local and Docker execution on
the same transport/identity policy while retaining the pinned source revision.
"""
from copy import deepcopy
import os

try:
    from .model_endpoint import ModelEndpointSession
    from .trace_identity import TraceIdentityError, canonical_to_legacy, check_structured
except ImportError:  # app/server.py invoked directly
    from model_endpoint import ModelEndpointSession
    from trace_identity import TraceIdentityError, canonical_to_legacy, check_structured


CHAIN_IDS = {"eth": 1, "bsc": 56, "polygon": 137, "arbitrum": 42161,
             "optimism": 10, "avalanche": 43114, "base": 8453, "fantom": 250,
             "zksync": 324, "linea": 59144, "scroll": 534352, "gnosis": 100,
             "celo": 42220, "cronos": 25, "moonbeam": 1284, "aurora": 1313161554}


def walk(node):
    yield node
    for child in node.get("children", []):
        yield from walk(child)


class PipelineRuntime:
    def __init__(self, tx_hash, chain, session=None, emit=lambda event: None):
        self.tx_hash, self.chain = tx_hash.lower(), chain.lower()
        self.session = session
        self.emit = emit
        self.partial = None
        self.sequence = None
        self.ranked_targets = []
        self.restorers = []
        self.source = None

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
        if hasattr(agent_module, "_llm_call_with_retry"):
            self.replace(agent_module, "_llm_call_with_retry", self.session.call)
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
        from faultseeker.forensics.orchestrator import ForensicsOrchestrator
        from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
        from faultseeker.function_analysis.function_ranker import FunctionRanker
        self.source = agents
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
            if not isinstance(tx, dict) or str(tx.get("hash", "")).lower() != tx_hash.lower():
                raise TraceIdentityError("Transaction identity could not be verified from the chain.")
            fields = [(tx.get("to"), root.get("callee") or root.get("to")),
                      (tx.get("from"), root.get("caller") or root.get("from")),
                      (tx.get("input"), root.get("input"))]
            if any(str(a or "").lower() != str(b or "").lower() for a, b in fields):
                raise TraceIdentityError("Structured trace root differs from on-chain transaction calldata or addresses.")
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
            result = original_rank(ranker, *args, **kwargs)
            allowed = {f"{n['function']}_{n['address']}".lower() for n in walk(self.sequence["trace"])}
            if any(key.lower() not in allowed for key in result.functions_to_be_inspected):
                raise TraceIdentityError("Ranked target is not an observed canonical selector/address pair.")
            self.ranked_targets = list(result.functions_to_be_inspected)
            return result
        self.replace(FunctionRanker, "rank", checked_rank)

        original_analyze = FunctionAnalyzer.run
        def checked_analysis(analyzer, *args, **kwargs):
            self.assert_healthy()
            try:
                result = original_analyze(analyzer, *args, **kwargs)
            except Exception:
                self.assert_healthy()
                raise
            self.assert_healthy()  # ThreadPoolExecutor may catch individual failures.
            return result
        self.replace(FunctionAnalyzer, "run", checked_analysis)
        return self

    def preflight(self, models, timeout=20):
        if not self.session:
            return
        # One overall preflight deadline, including any explicitly split stages.
        deadline = self.session.clock() + timeout
        for model in dict.fromkeys(models):
            base_url, env_name = self.source.UniversalAgent._detect_provider(model)
            override = {"OPENAI_API_KEY": "OPENAI_BASE_URL", "GROQ_API_KEY": "GROQ_BASE_URL",
                        "NARAROUTER_API_KEY": "NARAROUTER_BASE_URL"}.get(env_name)
            if override:
                base_url = os.getenv(override) or base_url
            keys = self.source._parse_api_keys(os.getenv(env_name, ""))
            if not keys:
                raise ValueError("The configured model requires an API key.")
            self.session.register_keys(base_url, keys)
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
                                        "ranked_targets": self.ranked_targets, "unverified_targets": unsupported}
        result["trace_provenance"] = deepcopy((self.sequence or {}).get("trace_provenance", {}))
        result.setdefault("limitations", []).append("Function identities use observed calldata selectors. Human-readable names require verified ABI/source at the execution context; selector-database labels are not proof.")
        if unsupported:
            result["analysis_status"] = "partial"
            result["classification"] = {"rule_verdict": "INCONCLUSIVE"}
            result["limitations"].append("Model output contained function labels that could not be linked to the observed canonical targets. Localization is unverified.")
        if self.session:
            result["model_endpoint"] = self.session.summary()
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


def make_runtime(tx_hash, chain, use_model, emit):
    session = ModelEndpointSession(emit=emit,
        retry_limit=int(os.getenv("FAULTSEEKER_MODEL_RETRY_LIMIT", "3")),
        time_budget=float(os.getenv("FAULTSEEKER_MODEL_TIME_BUDGET_SECS", "600")),
        call_timeout=float(os.getenv("FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS", "60"))) if use_model else None
    runtime = PipelineRuntime(tx_hash, chain, session=session, emit=emit)
    try:
        return runtime.install()
    except Exception:
        runtime.close()
        raise
