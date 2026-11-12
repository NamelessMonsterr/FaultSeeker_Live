"""Access protection: a server-configured access code, revocable sessions and login rate limiting.

* The code is compared in constant time (SHA-256 digests through hmac.compare_digest, so length does not leak either).
* A successful login creates a random 256-bit session token. Only its SHA-256 is kept server side, so a logout (or the
  expiry) really revokes it. The token travels in an HttpOnly, SameSite=Strict cookie, Secure whenever the request is HTTPS.
* Failed logins are limited per client address and, more loosely, globally.
"""
import hashlib
import hmac
import secrets
import time
from collections import deque
from typing import Callable, Deque, Dict

COOKIE_NAME = "fs_session"
MAX_SESSIONS = 1000


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


class AccessControl:
    def __init__(self, code: str, *, session_seconds: float, max_failures_per_ip: int, window_seconds: int,
                 max_failures_global: int, now: Callable[[], float] = time.time):
        self._code_digest = _digest(code) if code else None
        self.enabled = bool(code)
        self.session_seconds = session_seconds
        self._max_ip, self._window, self._max_global = max_failures_per_ip, window_seconds, max_failures_global
        self._now = now
        self._sessions: Dict[bytes, float] = {}
        self._failures: Dict[str, Deque[float]] = {}
        self._global: Deque[float] = deque()

    # ---- code ----------------------------------------------------------------------------------------
    def check_code(self, supplied: str) -> bool:
        if not self._code_digest:
            return False
        return hmac.compare_digest(_digest(supplied or ""), self._code_digest)

    # ---- sessions ------------------------------------------------------------------------------------
    def create_session(self) -> str:
        self._prune_sessions()
        if len(self._sessions) >= MAX_SESSIONS:
            self._sessions.pop(min(self._sessions, key=self._sessions.get))
        token = secrets.token_urlsafe(32)
        self._sessions[_digest(token)] = self._now() + self.session_seconds
        return token

    def valid_session(self, token: str) -> bool:
        if not token:
            return False
        key = _digest(token)
        expiry = self._sessions.get(key)
        if expiry is None:
            return False
        if expiry <= self._now():
            self._sessions.pop(key, None)
            return False
        return True

    def revoke(self, token: str) -> None:
        if token:
            self._sessions.pop(_digest(token), None)

    def _prune_sessions(self) -> None:
        now = self._now()
        for key in [k for k, exp in self._sessions.items() if exp <= now]:
            del self._sessions[key]

    # ---- rate limiting -------------------------------------------------------------------------------
    @staticmethod
    def _trim(q: Deque[float], horizon: float) -> None:
        while q and q[0] <= horizon:
            q.popleft()

    def retry_after(self, ip: str) -> int:
        """Seconds until another attempt is allowed; 0 when allowed."""
        now = self._now()
        horizon = now - self._window
        self._trim(self._global, horizon)
        q = self._failures.get(ip)
        wait = 0.0
        if q is not None:
            self._trim(q, horizon)
            if len(q) >= self._max_ip:
                wait = max(wait, q[0] + self._window - now)
        if len(self._global) >= self._max_global:
            wait = max(wait, self._global[0] + self._window - now)
        return int(wait) + 1 if wait > 0 else 0

    def record_failure(self, ip: str) -> None:
        now = self._now()
        if len(self._failures) > 5000:           # bound memory under address-rotating floods
            self._failures.clear()
        self._failures.setdefault(ip, deque()).append(now)
        self._global.append(now)

    def record_success(self, ip: str) -> None:
        self._failures.pop(ip, None)
