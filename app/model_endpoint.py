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
    """Run-scoped concurrent transport policy with atomic shared accounting.

    State locks protect counters, credential pools, and the sticky circuit only.
    Client construction, network I/O, and retry sleeps never hold the state lock.
    """
    def __init__(self, emit=lambda event: None, retry_limit=3, time_budget=600,
                 call_timeout=60, admission_timeout=30, clock=time.monotonic, sleep=time.sleep):
        self.emit = emit
        self.retries_left = max(0, int(retry_limit))
        self.time_budget = max(0.1, float(time_budget))
        self.call_timeout = max(0.1, float(call_timeout))
        # Kept for constructor compatibility; requests wait on the short state
        # lock/available reservations rather than failing a healthy queued worker.
        self.admission_timeout = max(0.0, float(admission_timeout))
        self.clock, self.sleep = clock, sleep
        self.spent = 0.0
        self.reserved = 0.0
        self.attempts = 0
        self.calls = {}
        self.failure = None
        self.state_lock = threading.RLock()
        self.condition = threading.Condition(self.state_lock)
        self.key_pools = {}
        self.model_routes = {}
        self.route_policy = None
        self.tokens = {"prompt": 0, "completion": 0, "reasoning": 0}

    def register_keys(self, base_url, keys, model=None):
        endpoint = str(httpx.URL(str(base_url))).rstrip("/")
        if model is not None:
            endpoint = (endpoint, model)
        with self.state_lock:
            pool = self.key_pools.setdefault(endpoint, {"keys": [], "rejected": set(), "active": None})
            for key in keys:
                if key not in pool["keys"]:
                    pool["keys"].append(key)
            if pool["active"] is None and pool["keys"]:
                pool["active"] = pool["keys"][0]

    def assert_healthy(self):
        with self.state_lock:
            failure = self.failure
        if failure:
            raise failure

    def _fail(self, error):
        with self.state_lock:
            first_failure = self.failure is None
            if first_failure:
                self.failure = error
            else:
                error = self.failure
            self.condition.notify_all()
            attempts = self.attempts
        if first_failure:
            self.emit({"state": "model_endpoint_failed", **error.as_dict(),
                       "attempts": attempts})
        raise error from None

    def _local_deadline_failure(self, phase):
        # A single request missing its entry-time deadline does not trip the
        # shared circuit or misreport a transport-budget exhaustion.
        return ModelEndpointFailure("request_deadline_exceeded", phase=phase)

    def _out_of_time(self, phase, deadline, last_error):
        with self.state_lock:
            budget_left = self.time_budget - self.spent
        deadline_left = (deadline - self.clock()) if deadline is not None else None
        if (phase == "preflight" and last_error is not None
                and deadline_left is not None and deadline_left <= budget_left):
            return last_error
        return ModelEndpointFailure("budget_exhausted", phase=phase)

    def preflight(self, factory, model, timeout=20, deadline=None):
        """Authenticated completion on the same configured model; tests use MockTransport."""
        return self.call(factory, {"model": model, "messages": [
            {"role": "user", "content": "Reply OK."}], "max_tokens": 8,
            "temperature": 0}, model, phase="preflight",
            deadline=deadline if deadline is not None else self.clock() + max(0.1, float(timeout)))

    def _route_and_pool(self, factory, model):
        with self.state_lock:
            route_known = model in self.model_routes
            route = self.model_routes.get(model)
            policy = self.route_policy
        if not route_known and policy is not None:
            candidate_route, keys = policy(model)
            with self.state_lock:
                route = self.model_routes.setdefault(model, candidate_route)
            self.register_keys(route, keys, model=model)
        client = factory()
        with self.state_lock:
            route = self.model_routes.get(model)
            endpoint = str(httpx.URL(str(route or client.base_url))).rstrip("/")
            pool = self.key_pools.get((endpoint, model)) or self.key_pools.get(endpoint)
            active_key = pool["active"] if pool else None
        return client, route, pool, active_key

    def call(self, factory, kwargs, model, phase="analysis", deadline=None):
        queued_at = self.clock()
        with self.state_lock:
            if self.failure is not None:
                raise self.failure
            # An ordinary call receives an entry-time deadline based on the
            # shared budget visible at entry. Explicit preflight deadlines win.
            entry_budget = max(0.0, self.time_budget - self.spent)
        request_deadline = deadline if deadline is not None else queued_at + entry_budget
        retry_number = 0
        last_error = None

        while True:
            client = None
            completion = None
            error = None
            retryable = False
            retry_hint = ""
            pool = None
            attempt_key = None

            # Atomically reserve one attempt's maximum transport time. If all
            # remaining budget is reserved by in-flight attempts, wait for a
            # reservation to be released instead of killing a healthy worker.
            with self.condition:
                while True:
                    if self.failure is not None:
                        raise self.failure
                    now = self.clock()
                    if now >= request_deadline:
                        raise self._local_deadline_failure(phase)
                    available = self.time_budget - self.spent - self.reserved
                    if available > 0:
                        break
                    if self.reserved <= 0:
                        self.condition.notify_all()
                        budget_error = ModelEndpointFailure("budget_exhausted", phase=phase)
                        # Release the lock before publishing the sticky failure.
                        break
                    self.condition.wait(timeout=max(0.0, request_deadline - now))
                if available <= 0:
                    # Do not publish a budget failure if another attempt still
                    # owns the remaining budget reservation.
                    exhausted = self.reserved <= 0
                else:
                    exhausted = False
                if exhausted:
                    pass
                else:
                    now = self.clock()
                    left = request_deadline - now
                    reservation = min(self.call_timeout, available, left)
                    if reservation <= 0:
                        raise self._local_deadline_failure(phase)
                    self.reserved += reservation
                    self.attempts += 1
                    attempt_number = self.attempts
            if exhausted:
                self._fail(budget_error)

            started = self.clock()
            try:
                client, route, pool, attempt_key = self._route_and_pool(factory, model)
                remaining = min(reservation, request_deadline - self.clock())
                if remaining <= 0:
                    raise self._local_deadline_failure(phase)
                options = {"max_retries": 0, "timeout": remaining}
                if route:
                    options["base_url"] = route
                if pool and attempt_key is not None:
                    options["api_key"] = attempt_key
                bounded = client.with_options(**options)
                self.emit({"state": "model_request_started", "phase": phase, "model": model,
                           "queue_wait_seconds": round(max(0.0, started - queued_at), 3)})
                self.emit({"state": "waiting_on_model_endpoint", "phase": phase,
                           "attempt": attempt_number, "model": model, "retry_in_seconds": 0})
                completion = bounded.chat.completions.create(**adapt_request(model, kwargs))
                choices = getattr(completion, "choices", None)
                if not choices or not isinstance(getattr(choices[0].message, "content", None), str) or not choices[0].message.content.strip():
                    raise ModelEndpointFailure("invalid_response", phase=phase)
            except Exception as exc:
                if isinstance(exc, ModelEndpointFailure) and exc.kind == "request_deadline_exceeded":
                    error, retryable = exc, False
                else:
                    error, retryable = classify(exc, phase)
                response = getattr(exc, "response", None)
                retry_hint = getattr(response, "headers", {}).get("retry-after", "")
            finally:
                elapsed = max(0.0, self.clock() - started)
                if client is not None:
                    client.close()
                with self.condition:
                    self.reserved = max(0.0, self.reserved - reservation)
                    self.spent += elapsed
                    phase_calls = self.calls.setdefault(phase, {"ok": 0, "failed": 0})
                    phase_calls["failed" if error is not None else "ok"] += 1
                    if error is not None and error.kind == "rate_limited":
                        # 429 is sticky as soon as observed; any in-flight success
                        # committing afterward must see this circuit state.
                        if self.failure is None:
                            self.failure = error
                    self.condition.notify_all()
                    current_failure = self.failure
                    attempts = self.attempts

            self.emit({"state": "model_request_attempt", "phase": phase, "model": model,
                       "attempt": attempt_number,
                       "elapsed_seconds": round(elapsed, 3),
                       "outcome": "failed" if error is not None else "ok",
                       "error_kind": error.kind if error is not None else None,
                       "http_status": error.status_code if error is not None else None})

            if error is None:
                with self.state_lock:
                    if self.failure is not None:
                        raise self.failure
                    self._count_tokens(completion)
                    tokens_committed = True
                self.emit({"state": "model_endpoint_ready", "phase": phase,
                           "model": model, "attempts": attempts})
                return completion

            if error.kind == "rate_limited":
                self._fail(error)
            if current_failure is not None:
                raise current_failure
            last_error = error
            now = self.clock()
            if now >= request_deadline:
                if phase == "preflight":
                    self._fail(self._out_of_time(phase, request_deadline, last_error))
                raise self._local_deadline_failure(phase)
            with self.state_lock:
                budget_left = self.time_budget - self.spent - self.reserved
                if budget_left <= 0:
                    # In-flight reservations may still free budget. Do not call
                    # this exhausted while those reservations remain outstanding.
                    if self.reserved <= 0:
                        budget_error = ModelEndpointFailure("budget_exhausted", phase=phase)
                    else:
                        budget_error = None
                else:
                    budget_error = None
                if budget_error is not None:
                    pass
            if budget_error is not None:
                self._fail(budget_error)

            next_key = None
            if pool and len(pool["keys"]) > 1 and error.kind == "authentication":
                with self.state_lock:
                    # Do not let a stale 401 from key A reject/overwrite key B
                    # after another in-flight request has already rotated it.
                    if pool["active"] == attempt_key:
                        pool["rejected"].add(attempt_key)
                        next_key = next((key for key in pool["keys"] if key not in pool["rejected"]), None)
                        if next_key is not None:
                            pool["active"] = next_key
                    elif pool["active"] not in pool["rejected"]:
                        next_key = pool["active"]
                    if next_key is None:
                        all_rejected = True
                    else:
                        all_rejected = False
                if all_rejected:
                    self._fail(error)
                retryable = True

            if not retryable:
                self._fail(error)

            with self.state_lock:
                if phase != "preflight":
                    if self.retries_left <= 0:
                        no_retry = True
                    else:
                        self.retries_left -= 1
                        no_retry = False
                else:
                    no_retry = False
            if no_retry:
                self._fail(error)

            if next_key is not None:
                self.emit({"state": "waiting_on_model_endpoint", **error.as_dict(),
                           "attempt": attempts, "model": model, "key_rotation": True,
                           "retry_in_seconds": 0, "retries_remaining": self.retries_left})
                continue

            retry_number += 1
            delay = min(2 ** (retry_number - 1), 4)
            try:
                delay = max(delay, float(retry_hint))
            except (ValueError, TypeError):
                pass
            with self.condition:
                available = self.time_budget - self.spent - self.reserved
                until_deadline = request_deadline - self.clock()
                if delay >= available or delay >= until_deadline:
                    should_fail = True
                else:
                    self.reserved += delay
                    should_fail = False
            if should_fail:
                if phase == "preflight":
                    self._fail(self._out_of_time(phase, request_deadline, last_error))
                raise self._local_deadline_failure(phase)
            self.emit({"state": "waiting_on_model_endpoint", **error.as_dict(),
                       "attempt": attempts, "model": model,
                       "retry_in_seconds": delay, "retries_remaining": self.retries_left})
            before = self.clock()
            try:
                self.sleep(delay)
            finally:
                slept = max(0.0, self.clock() - before)
                with self.condition:
                    self.reserved = max(0.0, self.reserved - delay)
                    self.spent += slept
                    self.condition.notify_all()

    def _count_tokens(self, completion):
        usage = getattr(completion, "usage", None)
        if usage is None:
            return
        details = getattr(usage, "completion_tokens_details", None)
        self.tokens["prompt"] += int(getattr(usage, "prompt_tokens", 0) or 0)
        self.tokens["completion"] += int(getattr(usage, "completion_tokens", 0) or 0)
        self.tokens["reasoning"] += int(getattr(details, "reasoning_tokens", 0) or 0)

    def summary(self):
        with self.state_lock:
            return {"attempts": self.attempts, "tokens": dict(self.tokens), "retries_remaining": self.retries_left,
                    "calls": {phase: dict(counts) for phase, counts in self.calls.items()},
                    "transport_seconds": round(self.spent, 3),
                    "time_budget_seconds": self.time_budget,
                    "failure": self.failure.as_dict() if self.failure else None}
