"""Run-scoped model transport policy. No provider bodies or credentials escape it."""
import threading
import time

import httpx

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
                "scope": "credential" if self.kind == "authentication" else ("provider_limit" if self.kind == "rate_limited" else "endpoint")}


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
        # Usage/rate limits are an operator action, not a transient retry signal.
        # Do not multiply a provider quota response into more requests.
        return ModelEndpointFailure("rate_limited", status, phase), False
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
                 call_timeout=60, admission_timeout=30, clock=time.monotonic, sleep=time.sleep):
        self.emit = emit
        self.retries_left = max(0, int(retry_limit))
        self.time_budget = max(0.1, float(time_budget))
        self.call_timeout = max(0.1, float(call_timeout))
        # Bounds time spent waiting to enter the serialized request path.
        # This is separate from the per-attempt SDK timeout and transport budget.
        self.admission_timeout = max(0.0, float(admission_timeout))
        self.clock, self.sleep = clock, sleep
        self.spent = 0.0
        self.attempts = 0
        self.calls = {}  # phase -> {"ok": n, "failed": n}; real completions, not token counts
        self.failure = None
        self.failure_lock = threading.Lock()
        self.lock = threading.RLock()
        self.key_pools = {}
        self.model_routes = {}
        self.route_policy = None
        self.tokens = {"prompt": 0, "completion": 0, "reasoning": 0}

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
        with self.failure_lock:
            failure = self.failure
        if failure:
            raise failure

    def _fail(self, error):
        # Admission can fail from a thread that does not own the serialized
        # request lock. Preserve the first terminal failure across that race.
        with self.failure_lock:
            first_failure = self.failure is None
            if first_failure:
                self.failure = error
            else:
                error = self.failure
        if first_failure:
            self.emit({"state": "model_endpoint_failed", **error.as_dict(),
                       "attempts": self.attempts})
        raise error from None

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
        queued_at = self.clock()
        # Deadline is absolute from the caller; admission_timeout independently
        # bounds contention when no earlier caller deadline exists. Do not change
        # call_timeout: it remains the per-attempt SDK timeout.
        admission_wait = min(self.admission_timeout, max(0.0, deadline - queued_at)) if deadline is not None else self.admission_timeout
        if deadline is not None and deadline <= queued_at:
            self._fail(self._out_of_time(phase, deadline, None))
        if not self.lock.acquire(timeout=admission_wait):
            self.emit({"state": "model_request_admission_timeout", "phase": phase,
                       "model": model, "queue_wait_seconds": round(max(0.0, self.clock() - queued_at), 3)})
            self._fail(ModelEndpointFailure("budget_exhausted", phase=phase))
        try:
            lock_acquired = self.clock()
            queue_wait = max(0.0, lock_acquired - queued_at)
            self.emit({"state": "model_request_started", "phase": phase, "model": model,
                       "queue_wait_seconds": round(queue_wait, 3)})
            self.assert_healthy()
            retry_number = 0
            last_error = None
            while True:
                remaining = self.time_budget - self.spent
                if deadline is not None:
                    remaining = min(remaining, deadline - self.clock())
                if remaining <= 0:
                    self._fail(self._out_of_time(phase, deadline, last_error))
                started = self.clock()
                client = None
                pool = None
                error = None
                attempt_number = None
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
                    attempt_number = self.attempts
                    self.emit({"state": "waiting_on_model_endpoint", "phase": phase,
                               "attempt": attempt_number, "model": model,
                               "retry_in_seconds": 0})
                    completion = bounded.chat.completions.create(**adapt_request(model, kwargs))
                    choices = getattr(completion, "choices", None)
                    if not choices or not isinstance(getattr(choices[0].message, "content", None), str) or not choices[0].message.content.strip():
                        raise ModelEndpointFailure("invalid_response", phase=phase)
                except Exception as exc:
                    error, retryable = classify(exc, phase)
                    response = getattr(exc, "response", None)
                    retry_hint = getattr(response, "headers", {}).get("retry-after", "")
                finally:
                    self.spent += max(0.0, self.clock() - started)
                    if client is not None:
                        client.close()
                phase_calls = self.calls.setdefault(phase, {"ok": 0, "failed": 0})
                phase_calls["failed" if error is not None else "ok"] += 1
                self.emit({"state": "model_request_attempt", "phase": phase, "model": model,
                           "attempt": attempt_number,
                           "elapsed_seconds": round(max(0.0, self.clock() - started), 3),
                           "outcome": "failed" if error is not None else "ok",
                           "error_kind": error.kind if error is not None else None,
                           "http_status": error.status_code if error is not None else None})
                if error is not None:
                    last_error = error
                if self.spent > self.time_budget:
                    self._fail(ModelEndpointFailure("budget_exhausted", phase=phase))
                if deadline is not None and self.clock() > deadline:
                    self._fail(self._out_of_time(phase, deadline, error))
                if error is None:
                    # Commit success atomically against a terminal failure that
                    # may have been set by a concurrent admission timeout.
                    with self.failure_lock:
                        if self.failure is not None:
                            raise self.failure
                        self._count_tokens(completion)
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
                if pool and len(pool["keys"]) > 1 and error.kind == "authentication":
                    pool["rejected"].add(pool["active"])
                    next_key = next((key for key in pool["keys"] if key not in pool["rejected"]), None)
                    if next_key is None:
                        self._fail(error)  # All configured credentials rejected.
                    retryable = True
                if not retryable:
                    self._fail(error)
                if phase != "preflight":
                    # Only analysis retries consume the shared allowance. Preflight
                    # retries are bounded by the preflight deadline instead, so a
                    # cold-starting endpoint gets the whole window to wake up.
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
                           "attempt": self.attempts, "model": model,
                           "retry_in_seconds": delay, "retries_remaining": self.retries_left})
                before = self.clock()
                self.sleep(delay)
                self.spent += max(0.0, self.clock() - before)
        finally:
            self.lock.release()

    def _count_tokens(self, completion):
        usage = getattr(completion, "usage", None)
        if usage is None:
            return
        details = getattr(usage, "completion_tokens_details", None)
        self.tokens["prompt"] += int(getattr(usage, "prompt_tokens", 0) or 0)
        self.tokens["completion"] += int(getattr(usage, "completion_tokens", 0) or 0)
        self.tokens["reasoning"] += int(getattr(details, "reasoning_tokens", 0) or 0)

    def summary(self):
        return {"attempts": self.attempts, "tokens": dict(self.tokens), "retries_remaining": self.retries_left,
                "calls": {phase: dict(counts) for phase, counts in self.calls.items()},
                "transport_seconds": round(self.spent, 3),
                "time_budget_seconds": self.time_budget,
                "failure": self.failure.as_dict() if self.failure else None}
