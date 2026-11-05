"""Run-scoped model transport policy. No provider bodies or credentials escape it."""
import re
import threading
import time
from collections import deque

import httpx

# Fork-layer repair (input-side, preview-only experiment): the engine's
# vulnerability-analysis prompt requires a one-sentence "evidence" mechanism
# per flagged function and offers no sanctioned value for an undetermined
# mechanism ("{}" only means "no vulnerable function"). On the Hedgey ETH case
# this correlated with invented mechanism narratives (see runs/ablation_*).
# Appending this contract gives the model an honest path. Reversible: set
# FAULTSEEKER_ABSTENTION_CONTRACT to 0/false/no/off/disabled to turn it off.
#
# Schema compatibility (verified against the pinned engine parser,
# function_analyzer._update_potentially_vulnerable_function): per-entry
# records are read via .get('evidence'|'reason'|'description'|'rationale')
# and .get('confidence_score'|'confidence'|'score'); unknown extra fields are
# silently DISCARDED. The contract therefore introduces no new output field -
# "mechanism undetermined" is a plain nonempty evidence string, which the
# parser accepts verbatim.
ABSTENTION_SENTINEL = "[FAULTSEEKER_ABSTENTION_CONTRACT_V1]"
ABSTENTION_CONTRACT = (
    "\n\n" + ABSTENTION_SENTINEL + "\n"
    "Additional output rules:\n"
    "- If the provided information does not establish HOW a function is "
    "vulnerable, set \"evidence\" to exactly \"mechanism undetermined\". "
    "This is a valid, respected answer.\n"
    "- NEVER invent a mechanism (e.g. swaps, reentrancy, price manipulation) "
    "and NEVER name protocols that are not directly established by the "
    "provided information.\n"
    "- Observed calls, selectors, approvals, transfers and unusual parameters "
    "are not independently proof of a vulnerability. A suspicious function "
    "without sufficient evidence of a fault localized within it must not be "
    "flagged; a flagged function whose mechanism cannot be established uses "
    "\"mechanism undetermined\"."
)
# Trusted prompt identity has TWO halves, both required and both tested:
# (1) Boundary: every kwargs payload reaching augment_vulnerability_prompt
#     arrives through ModelEndpointSession.call, which the fork installs ONLY
#     as the pinned engine's internal _llm_call_with_retry
#     (pipeline_guards.install_model_hooks). No network input, webhook, or
#     user-controlled path calls session.call directly; every message here is
#     constructed by the pinned engine's agent layer.
# (2) Construction: the pinned engine builds the vulnerability prompt as
#     template + appended data (function_analyzer
#     ._update_potentially_vulnerable_function), so untrusted transaction
#     content can only appear AFTER the template, and _send_message appends
#     the constructed prompt as the LAST user message before dispatch (model
#     output enters memory only as assistant messages). Given (1)+(2), an
#     exact full-template prefix match on the last user message is provenance,
#     not pattern matching: within this boundary only the engine's
#     construction path produces it. Both halves are enforced by mandatory
#     source-level tripwire tests against the pinned checkout (Dockerfile ARG
#     FAULTSEEKER_SHA). The 3-element signature below is retained ONLY as a
#     drift-detection signal, never as targeting authority.
ENGINE_VULN_ANALYSIS_TEMPLATE = 'Based on the current understanding of the transaction, decide if any function implementation is potentially vulnerable. The vulnerable function must have the fault localized within it.\n\nReturn ONLY a valid JSON object in this exact schema — no markdown, no explanation:\n{\n  "<functionname>_<address>": {\n    "evidence": "<one-sentence explanation>",\n    "confidence_score": <float 0.0-1.0>\n  }\n}\n\nRules:\n- <functionname> and <address> must exactly match values in the provided information.\n- The <functionname>_<address> key must be one of the exact call ids shown in the provided information (for example a selector_address id such as 0xfa461e33_0x0000...). Any other key is discarded as unverifiable.\n- If no vulnerable function is found, return exactly: {}\n- Do NOT include any text outside the JSON object.\n'


def _normalized(text):
    return " ".join(text.split())


_TEMPLATE_PREFIX = _normalized(ENGINE_VULN_ANALYSIS_TEMPLATE)
_VULN_PROMPT_TOPICS = ("potentially vulnerable", "identify any vulnerable functions")
_VULN_PROMPT_SCHEMA = "confidence_score"
# Third signature element: the prompt's literal JSON key shape. All three are
# matched case-insensitively; co-occurrence is a heuristic boundary, not proof
# of prompt identity - wording drift disables the repair loudly instead of
# mistargeting it.
_VULN_PROMPT_KEYSHAPE = "<functionname>_<address>"
_DISABLE_VALUES = ("0", "false", "no", "off", "disabled")


def _signature_hits(content):
    lowered = content.lower()
    return (any(topic in lowered for topic in _VULN_PROMPT_TOPICS),
            _VULN_PROMPT_SCHEMA in lowered,
            _VULN_PROMPT_KEYSHAPE in lowered)


def augment_vulnerability_prompt(kwargs, phase):
    """Append the abstention contract to vulnerability-analysis prompts only.
    Returns (kwargs, augmented?, targeting_mismatch?).

    Idempotence is STRUCTURAL, never content-derived: the caller augments once
    per request and keeps that state internally (the blank-answer re-ask
    reuses the already-augmented kwargs). Message content is untrusted input -
    a sentinel substring in transaction data or quoted text must neither
    suppress nor prove augmentation, so it is never consulted.

    Targeting authority is structural: the last user message must start with
    the pinned engine's exact template (ENGINE_VULN_ANALYSIS_TEMPLATE).
    Untrusted content - transaction data, quoted text, historical messages -
    can neither activate nor suppress augmentation. The 3-element signature
    remains only as drift detection: a near-matching current prompt (2+ of 3
    elements) is reported as a targeting_mismatch, never silently skipped.
    Never touches other phases or prompt types. Input kwargs are not mutated.
    Malformed structures never crash."""
    import os
    if phase != "analysis":
        return kwargs, False, False
    if os.environ.get("FAULTSEEKER_ABSTENTION_CONTRACT", "1").strip().lower() in _DISABLE_VALUES:
        return kwargs, False, False
    messages = kwargs.get("messages")
    if not isinstance(messages, list):
        return kwargs, False, False
    # Temporal correctness: only the LAST user message can be the current
    # invocation's prompt. Historical messages (engine conversation memory)
    # are never augmented and never satisfy or suppress targeting. The last
    # user message is selected regardless of content type: if its content is
    # not a plain string, the current prompt is unsupported and nothing is
    # augmented - never search backward for a historical substitute.
    idx = None
    for i in range(len(messages) - 1, -1, -1):
        m = messages[i]
        if isinstance(m, dict) and m.get("role") == "user":
            idx = i
            break
    if idx is None:
        return kwargs, False, False
    content = messages[idx].get("content")
    if not isinstance(content, str):
        return kwargs, False, False
    if _normalized(content).startswith(_TEMPLATE_PREFIX):
        kwargs = dict(kwargs)
        messages = [dict(m) if isinstance(m, dict) else m for m in messages]
        messages[idx]["content"] += ABSTENTION_CONTRACT
        kwargs["messages"] = messages
        return kwargs, True, False
    # Drift detection only: a near-matching current prompt (2+ of 3 signature
    # elements) is probably the engine prompt with drifted wording - loud
    # mismatch, never silent skip. Untrusted content that merely embeds the
    # same strings never activates augmentation (prefix authority above).
    return kwargs, False, sum(_signature_hits(content)) >= 2

try:
    from .model_routes import adapt_request
except ImportError:  # app/server.py invoked directly
    from model_routes import adapt_request


class ModelEndpointFailure(RuntimeError):
    def __init__(self, kind, status_code=None, phase="analysis"):
        self.kind = kind
        self.status_code = status_code
        self.phase = phase
        messages = {
            "authentication": "Model endpoint rejected authentication or access.",
            "model_unavailable": "The configured model is unavailable at this endpoint.",
            "timeout": "Model endpoint request timed out.",
            "connection": "Could not connect to the model endpoint.",
            "upstream_http": "Model endpoint returned an upstream HTTP error.",
            "rate_limited": "Model endpoint rate limit was reached.",
            "invalid_request": "Model endpoint rejected the request.",
            "invalid_response": "Model endpoint returned an invalid completion response.",
            "blank_completion": "Model endpoint returned an empty completion.",
            "refusal": "Model endpoint returned a refusal instead of an answer.",
            "truncated_output": "Model endpoint returned a truncated completion (output cap reached).",
            "budget_exhausted": "The shared model-endpoint time budget was exhausted.",
            "endpoint_error": "Model endpoint request failed.",
        }
        message = messages[kind]
        if status_code:
            message += f" HTTP {status_code}."
        super().__init__(message)

    def as_dict(self):
        return {"kind": self.kind, "http_status": self.status_code,
                "phase": self.phase, "message": str(self),
                "scope": "credential" if self.kind in ("authentication", "rate_limited") else "endpoint"}


def _error_detail(exc):
    """Whitelisted diagnostics: retry-after + provider error message with
    credential-shaped strings redacted. Never auth headers or request bodies."""
    detail = {}
    response = getattr(exc, "response", None)
    if response is None:
        return detail
    retry_after = response.headers.get("retry-after")
    if retry_after:
        detail["retry_after"] = retry_after
    # Provider error text is captured only for 429s (rate-limit diagnosis);
    # other statuses can embed private upstream content and stay body-free.
    if response.status_code != 429:
        return detail
    try:
        body = response.json()
    except Exception:
        return detail
    message = None
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        message = body["error"].get("message")
    if isinstance(message, str):
        message = re.sub(r"(?i)(bearer\s+|sk-|key-)[A-Za-z0-9_\-]{6,}", "[redacted]", message)[:200]
        detail["provider_message"] = message
    return detail


def classify(error, phase):
    # SDK exceptions wrap HTTPX errors; do not include their potentially secret body.
    status = getattr(error, "status_code", None)
    if isinstance(error, httpx.TimeoutException) or type(error).__name__ == "APITimeoutError":
        return ModelEndpointFailure("timeout", phase=phase), True
    if isinstance(error, httpx.TransportError) or type(error).__name__ == "APIConnectionError":
        return ModelEndpointFailure("connection", phase=phase), True
    if status in (401, 403):
        return ModelEndpointFailure("authentication", status, phase), False
    if status == 404:
        return ModelEndpointFailure("model_unavailable", status, phase), False
    if status == 429:
        return ModelEndpointFailure("rate_limited", status, phase), True
    if isinstance(status, int) and 500 <= status <= 599:
        return ModelEndpointFailure("upstream_http", status, phase), True
    if isinstance(status, int) and 400 <= status <= 499:
        return ModelEndpointFailure("invalid_request", status, phase), False
    if isinstance(error, ModelEndpointFailure):
        return error, False
    return ModelEndpointFailure("endpoint_error", phase=phase), False


class ModelEndpointSession:
    """One lock, retry allowance, cumulative HTTP/wait budget and sticky circuit.

    All agent instances and function-analysis threads share this object. Successful
    calls never reset the retry allowance. SDK automatic retries are always disabled.
    Analysis/RPC/CPU time outside model transport is not charged to this budget.
    Preflight retries are bounded by the preflight deadline, not the shared retry
    allowance, so a cold-starting endpoint gets its whole window to wake up.
    """
    def __init__(self, emit=lambda event: None, retry_limit=3, time_budget=600,
                 call_timeout=60, clock=time.monotonic, sleep=time.sleep,
                 output_budget_per_min=90000):
        self.emit = emit
        self.retries_left = max(0, int(retry_limit))
        self.time_budget = max(0.1, float(time_budget))
        self.call_timeout = max(0.1, float(call_timeout))
        self.clock, self.sleep = clock, sleep
        self.spent = 0.0
        self.attempts = 0
        self.calls = {}  # phase -> {"ok": n, "failed": n}; real completions, not token counts
        self.abstention_augmented_calls = 0  # vuln prompts carrying the abstention contract
        # Probable vuln prompts whose signature drifted (2 of 3 elements):
        # observable drift signal, never a silent feature disable.
        self.abstention_targeting_mismatches = 0
        self.failure = None
        self.lock = threading.RLock()
        self.blank_answer_retries = 0  # ledgered: user-granted blank-answer re-asks
        # counted at dispatch time - a dispatched attempt, not proof the
        # provider received and executed the request.
        self.key_pools = {}
        self.model_routes = {}
        self.route_policy = None
        self.tokens = {"prompt": 0, "completion": 0, "reasoning": 0}
        # Effective request configs recorded at the provider send boundary,
        # deduped. Reaching the recorder proves the request was constructed and
        # dispatched; outcomes are ledgered separately (tokens, failure kind).
        self.dispatched_configs = []
        # Rolling one-minute output budget (completion tokens incl. reasoning),
        # paced conservatively below provider per-minute limits.
        self.output_budget_per_min = int(output_budget_per_min)
        self.output_window = deque()

    def register_keys(self, base_url, keys, model=None):
        """Keep credential state per endpoint/model, private to this run's memory.

        Registration never resets retries or elapsed time. Analysis rotations
        consume the shared retry allowance; preflight uses its shared deadline.
        """
        with self.lock:
            endpoint = str(httpx.URL(str(base_url))).rstrip("/")
            if model is not None:
                endpoint = (endpoint, model)
            pool = self.key_pools.setdefault(endpoint, {"keys": [], "rejected": set(), "active": None})
            for key in keys:
                if key not in pool["keys"]:
                    pool["keys"].append(key)
            if pool["active"] is None and pool["keys"]:
                pool["active"] = pool["keys"][0]

    def assert_healthy(self):
        if self.failure:
            raise self.failure

    def _fail(self, error):
        self.failure = error
        self.emit({"state": "model_endpoint_failed", **error.as_dict(),
                   **getattr(error, "detail", {}),
                   "attempts": self.attempts})
        raise error from None

    def _pace_output(self, estimate, phase, model, deadline):
        """Hold calls so the rolling 60s output-token spend (incl. reasoning)
        stays under the budget. Pacing sleeps count against the shared
        transport budget, never outside it."""
        if self.output_budget_per_min <= 0:
            return
        while True:
            now = self.clock()
            while self.output_window and now - self.output_window[0][0] >= 60.0:
                self.output_window.popleft()
            used = sum(tokens for _, tokens in self.output_window)
            if used + estimate <= self.output_budget_per_min:
                return
            wait = 60.0 - (now - self.output_window[0][0]) + 0.05
            remaining = self.time_budget - self.spent
            if deadline is not None:
                remaining = min(remaining, deadline - now)
            if wait >= remaining:
                self._fail(ModelEndpointFailure("budget_exhausted", phase=phase))
            self.emit({"state": "waiting_on_model_endpoint", "phase": phase,
                       "model": model, "retry_in_seconds": round(wait, 2),
                       "output_pacing": True, "output_window_tokens": used})
            before = self.clock()
            self.sleep(wait)
            self.spent += max(0.0, self.clock() - before)

    def _out_of_time(self, phase, deadline, last_error):
        # A preflight that retried transient failures until its deadline reports
        # that failure. The shared budget is named only when it actually ran out.
        budget_left = self.time_budget - self.spent
        deadline_left = (deadline - self.clock()) if deadline is not None else None
        if (phase == "preflight" and last_error is not None
                and deadline_left is not None and deadline_left <= budget_left):
            return last_error
        return ModelEndpointFailure("budget_exhausted", phase=phase)

    def preflight(self, factory, model, timeout=20, deadline=None):
        """A minimal authenticated completion on the SAME configured model.

        Called only when a user starts live model analysis, never as a keep-warm
        task. It exercises the real completion route, not an unauthenticated health
        page. Offline tests replace HTTP with MockTransport.
        """
        return self.call(factory, {"model": model, "messages": [
            {"role": "user", "content": "Reply OK."}], "max_tokens": 8,
            "temperature": 0}, model, phase="preflight",
            deadline=deadline if deadline is not None else self.clock() + max(0.1, float(timeout)))

    def call(self, factory, kwargs, model, phase="analysis", deadline=None):
        with self.lock:
            self.assert_healthy()
            retry_number = 0
            blank_retried = False  # one blank-answer re-ask per call, never per run
            pending_blank_reask = False  # granted but not yet dispatched
            last_error = None
            # Augment exactly once per call. Augmentation state is trusted
            # per-request state held here, never inferred from message content;
            # the blank-answer re-ask reuses this kwargs, so the contract
            # survives the retry exactly once, un-duplicated.
            kwargs, abstention_augmented, abstention_mismatch = \
                augment_vulnerability_prompt(kwargs, phase)
            if abstention_augmented:
                self.abstention_augmented_calls += 1
            if abstention_mismatch:
                self.abstention_targeting_mismatches += 1
                self.emit({"warning": "abstention_targeting_mismatch",
                           "phase": phase, "model": model})
            while True:
                remaining = self.time_budget - self.spent
                if deadline is not None:
                    remaining = min(remaining, deadline - self.clock())
                if remaining <= 0:
                    self._fail(self._out_of_time(phase, deadline, last_error))
                estimate = kwargs.get("max_tokens")
                estimate = min(estimate, 16384) if isinstance(estimate, int) else 16384
                self._pace_output(estimate, phase, model, deadline)
                started = self.clock()
                client = None
                pool = None
                error = None
                blank_retry = False
                try:
                    if model not in self.model_routes and self.route_policy is not None:
                        route, keys = self.route_policy(model)
                        self.model_routes[model] = route
                        self.register_keys(route, keys, model=model)
                    client = factory()
                    remaining -= self.clock() - started
                    if remaining <= 0:
                        raise ModelEndpointFailure("budget_exhausted", phase=phase)
                    route = self.model_routes.get(model)
                    endpoint = str(httpx.URL(str(route or client.base_url))).rstrip("/")
                    pool = self.key_pools.get((endpoint, model)) or self.key_pools.get(endpoint)
                    options = {"max_retries": 0, "timeout": min(self.call_timeout, remaining)}
                    if route:
                        options["base_url"] = route
                    if pool:
                        # Upstream agents round-robin their own keys. Override
                        # that choice so rejected keys cannot reappear later.
                        options["api_key"] = pool["active"]
                    bounded = client.with_options(**options)
                    self.attempts += 1
                    self.emit({"state": "waiting_on_model_endpoint", "phase": phase,
                               "attempt": self.attempts, "model": model,
                               "retry_in_seconds": 0})
                    if pending_blank_reask:
                        # Ledger the re-ask only when it is actually dispatched;
                        # a grant that never reaches the wire is not a spent retry.
                        self.blank_answer_retries += 1
                        pending_blank_reask = False
                    adapted = adapt_request(model, kwargs)
                    self._record_dispatched(model, adapted, phase)
                    completion = bounded.chat.completions.create(**adapted)
                    # Token accounting happens at receipt, before any validation can
                    # raise: blank completions and refusals still consumed tokens, and
                    # their usage belongs in the ledger and the rolling output window.
                    self._count_tokens(completion)
                    choices = getattr(completion, "choices", None)
                    content = getattr(choices[0].message, "content", None) if choices else None
                    finish = getattr(choices[0], "finish_reason", None) if choices else None
                    refusal = getattr(choices[0].message, "refusal", None) if choices else None
                    if (choices and finish == "stop"
                            and (content is None or (isinstance(content, str) and not content.strip()))):
                        if isinstance(refusal, str) and refusal.strip():
                            # A refusal is a meaningful answer, not an empty one:
                            # terminal, and never eligible for the blank-answer grant.
                            raise ModelEndpointFailure("refusal", phase=phase)
                        # The exact granted case: a real response whose answer is empty.
                        raise ModelEndpointFailure("blank_completion", phase=phase)
                    if not choices or not isinstance(content, str) or not content.strip():
                        # Malformed structure, non-string content, or an empty answer
                        # on a non-stop finish (e.g. a reasoning blowout at the cap):
                        # NOT the granted blank-answer case, no re-ask.
                        raise ModelEndpointFailure("invalid_response", phase=phase)
                    if finish == "length":
                        # Truncated output is never silently used as an answer.
                        raise ModelEndpointFailure("truncated_output", phase=phase)
                except Exception as exc:
                    error, retryable = classify(exc, phase)
                    # User-granted narrow exception (2026-11-05, comparison task):
                    # a verified blank Mercury completion (HTTP 200, choices present,
                    # empty content, finish_reason "stop" - kind blank_completion)
                    # may be re-asked exactly once per call, preflight included
                    # (bounded by the existing preflight deadline). The blank answer
                    # still consumed tokens and the re-ask is another real, ledgered
                    # call; every other failure kind and model keeps zero retries.
                    blank_retry = (not retryable and not blank_retried
                                   and str(model).startswith("mercury-")
                                   and getattr(error, "kind", None) == "blank_completion")
                    if blank_retry:
                        retryable = True
                        blank_retried = True
                        pending_blank_reask = True
                    error.detail = _error_detail(exc)
                    response = getattr(exc, "response", None)
                    retry_hint = getattr(response, "headers", {}).get("retry-after", "")
                finally:
                    self.spent += max(0.0, self.clock() - started)
                    if client is not None:
                        client.close()
                phase_calls = self.calls.setdefault(phase, {"ok": 0, "failed": 0})
                phase_calls["failed" if error is not None else "ok"] += 1
                if error is not None:
                    last_error = error
                if self.spent > self.time_budget:
                    self._fail(ModelEndpointFailure("budget_exhausted", phase=phase))
                if deadline is not None and self.clock() > deadline:
                    self._fail(self._out_of_time(phase, deadline, error))
                if error is None:
                    self.emit({"state": "model_endpoint_ready", "phase": phase,
                               "model": model, "attempts": self.attempts})
                    return completion
                # Valid completions at the boundary are useful. Errors at the
                # boundary cannot start another attempt, nor can a later query.
                if self.spent >= self.time_budget:
                    self._fail(ModelEndpointFailure("budget_exhausted", phase=phase))
                if deadline is not None and self.clock() >= deadline:
                    self._fail(self._out_of_time(phase, deadline, last_error))
                next_key = None
                if pool and len(pool["keys"]) > 1 and error.kind in ("authentication", "rate_limited"):
                    pool["rejected"].add(pool["active"])
                    next_key = next((key for key in pool["keys"] if key not in pool["rejected"]), None)
                    if next_key is None:
                        self._fail(error)  # All configured credentials rejected.
                    retryable = True
                if not retryable:
                    self._fail(error)
                if phase != "preflight" and not blank_retry:
                    # Only analysis retries consume the shared allowance. Preflight
                    # retries are bounded by the preflight deadline instead, so a
                    # cold-starting endpoint gets the whole window to wake up.
                    # The granted blank-answer re-ask has its own per-call budget
                    # and never touches the shared allowance.
                    if self.retries_left <= 0:
                        self._fail(error)
                    self.retries_left -= 1
                if next_key is not None:
                    pool["active"] = next_key
                    self.emit({"state": "waiting_on_model_endpoint", **error.as_dict(),
                               "attempt": self.attempts, "model": model, "key_rotation": True,
                               "retry_in_seconds": 0, "retries_remaining": self.retries_left})
                    continue
                retry_number += 1
                delay = min(2 ** (retry_number - 1), 4)
                try:
                    delay = max(delay, float(retry_hint))
                except (ValueError, TypeError):
                    pass
                remaining = self.time_budget - self.spent
                if deadline is not None:
                    remaining = min(remaining, deadline - self.clock())
                if delay >= remaining:
                    self._fail(self._out_of_time(phase, deadline, last_error))
                self.emit({"state": "waiting_on_model_endpoint", **error.as_dict(),
                           **getattr(error, "detail", {}),
                           "attempt": self.attempts, "model": model,
                           "blank_answer_retry": blank_retry,
                           "retry_in_seconds": delay, "retries_remaining": self.retries_left})
                before = self.clock()
                self.sleep(delay)
                self.spent += max(0.0, self.clock() - before)

    def _record_dispatched(self, model, adapted, phase):
        extra = adapted.get("extra_body") or {}
        rec = {"model": str(adapted.get("model", model)),
               "temperature": adapted.get("temperature"),
               "reasoning_effort": extra.get("reasoning_effort"),
               "max_tokens": adapted.get("max_tokens"),
               "phase": phase}
        if rec not in self.dispatched_configs:
            self.dispatched_configs.append(rec)

    def _count_tokens(self, completion):
        usage = getattr(completion, "usage", None)
        if usage is None:
            return
        details = getattr(usage, "completion_tokens_details", None)
        self.tokens["prompt"] += int(getattr(usage, "prompt_tokens", 0) or 0)
        completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        self.tokens["completion"] += completion_tokens
        self.tokens["reasoning"] += int(getattr(details, "reasoning_tokens", 0) or 0)
        self.output_window.append((self.clock(), completion_tokens))

    def summary(self):
        return {"attempts": self.attempts, "tokens": dict(self.tokens), "retries_remaining": self.retries_left,
                "blank_answer_retries": self.blank_answer_retries,
                "calls": {phase: dict(counts) for phase, counts in self.calls.items()},
                "transport_seconds": round(self.spent, 3),
                "time_budget_seconds": self.time_budget,
                "failure": self.failure.as_dict() if self.failure else None}
