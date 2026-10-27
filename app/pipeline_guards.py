"""Narrow runtime integration for the external, commit-pinned FaultSeeker pipeline.

Hooks are installed per worker before main() is entered, and removed on exit.
The upstream checkout is not edited. This keeps local and Docker execution on
the same transport/identity policy while retaining the pinned source revision.
"""
from copy import deepcopy
import os

try:
    from .model_endpoint import ModelEndpointSession
    from .model_routes import ITERA_DEFAULT_BASE_URL, resolve_route
    from .trace_identity import TraceIdentityError, canonical_to_legacy, check_structured, validate_trace_root
except ImportError:  # app/server.py invoked directly
    from model_endpoint import ModelEndpointSession
    from model_routes import ITERA_DEFAULT_BASE_URL, resolve_route
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
        if isinstance(config, dict) and "itera/" not in config:
            # The pinned pipeline sends any unknown model prefix to a local Ollama
            # agent. Register the operator-selected Itera alias so it uses the
            # OpenAI-compatible agent whose calls the shared transport owns.
            self.replace(agent_module, "PROVIDER_CONFIG",
                         {**config, "itera/": (ITERA_DEFAULT_BASE_URL, "ITERA_API_KEY")})
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
        if os.getenv("FAULTSEEKER_VISITOR_RPC_RELAY"):
            # Forked workers may inherit a registry populated by a prior diagnostic.
            # Rebuild it after the visitor URL was replaced with the checked relay.
            if not hasattr(rpc_provider, "_ChainRegistry") or not hasattr(rpc_provider, "_registry"):
                raise RuntimeError("Pipeline cannot isolate the visitor RPC registry.")
            self.replace(rpc_provider, "_registry", rpc_provider._ChainRegistry())
        self.install_model_hooks(agents)

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
            "unverified_targets": [],
            "failure_path": True,
            "function_analysis_runs_observed": dict(self.function_analysis),
            "function_wall_cap": wall,
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
            result["failure"] = {"kind": type(error).__name__}
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
