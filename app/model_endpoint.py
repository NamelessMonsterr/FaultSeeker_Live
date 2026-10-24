"""Run-scoped model transport policy. No provider bodies or credentials escape it."""
import threading
import time

import httpx


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
                "scope": "credential" if self.kind in ("authentication", "rate_limited") else "endpoint"}


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
                 call_timeout=60, clock=time.monotonic, sleep=time.sleep):
        self.emit = emit
        self.retries_left = max(0, int(retry_limit))
        self.time_budget = max(0.1, float(time_budget))
        self.call_timeout = max(0.1, float(call_timeout))
        self.clock, self.sleep = clock, sleep
        self.spent = 0.0
        self.attempts = 0
        self.failure = None
        self.lock = threading.RLock()
        self.key_pools = {}

    def register_keys(self, base_url, keys):
        """Keep credential state per endpoint, private to this run's memory.

        Registration never resets rejections, retries or elapsed time. A key
        rotation consumes the same retry allowance as any other extra attempt.
        """
        with self.lock:
            endpoint = str(base_url).rstrip("/")
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
        with self.lock:
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
                try:
                    client = factory()
                    remaining -= self.clock() - started
                    if remaining <= 0:
                        raise ModelEndpointFailure("budget_exhausted", phase=phase)
                    pool = self.key_pools.get(str(client.base_url).rstrip("/"))
                    options = {"max_retries": 0, "timeout": min(self.call_timeout, remaining)}
                    if pool:
                        # Upstream agents round-robin their own keys. Override
                        # that choice so rejected keys cannot reappear later.
                        options["api_key"] = pool["active"]
                    bounded = client.with_options(**options)
                    self.attempts += 1
                    self.emit({"state": "waiting_on_model_endpoint", "phase": phase,
                               "attempt": self.attempts, "model": model,
                               "retry_in_seconds": 0})
                    completion = bounded.chat.completions.create(**kwargs)
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

    def summary(self):
        return {"attempts": self.attempts, "retries_remaining": self.retries_left,
                "transport_seconds": round(self.spent, 3),
                "time_budget_seconds": self.time_budget,
                "failure": self.failure.as_dict() if self.failure else None}
