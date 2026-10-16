"""Passwords, login throttling and short-lived in-memory holding areas."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from urllib.parse import urlsplit

MIN_PASSWORD = 12
_N, _R, _P = 2 ** 15, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=128 * 1024 * 1024, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, dk = stored.split("$")
        if scheme != "scrypt":
            return False
        want = base64.b64decode(dk)
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=128 * 1024 * 1024, dklen=len(want))
        return hmac.compare_digest(got, want)
    except Exception:
        return False


_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"  # no look-alikes


def random_password(n: int = 16) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def safe_next(target: str | None) -> str:
    """Only allow same-site relative redirects."""
    if not target:
        return "/"
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return "/"
    return target


class RateLimiter:
    """After 5 failures from a key, lock it out for 1 minute, doubling each further failure (max 1 hour)."""

    def __init__(self, free: int = 5):
        self.free = free
        self._fail: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def locked_for(self, key: str) -> int:
        with self._lock:
            n, until = self._fail.get(key, (0, 0.0))
            return max(0, int(until - time.time()) + 1) if until > time.time() else 0

    def failed(self, key: str) -> None:
        with self._lock:
            n, _ = self._fail.get(key, (0, 0.0))
            n += 1
            wait = 0 if n < self.free else min(60 * 2 ** (n - self.free), 3600)
            self._fail[key] = (n, time.time() + wait)
            if len(self._fail) > 5000:  # don't grow without bound
                for k in [k for k, (_, u) in self._fail.items() if u < time.time() - 3600]:
                    self._fail.pop(k, None)

    def succeeded(self, key: str) -> None:
        with self._lock:
            self._fail.pop(key, None)


class Ephemeral:
    """In-memory, time-limited store. Used for things we deliberately never put on disk
    (freshly generated private keys, half-finished CSR reviews)."""

    def __init__(self, ttl: int):
        self.ttl = ttl
        self._items: dict[str, tuple[float, object]] = {}
        self._lock = threading.Lock()

    def _purge(self) -> None:
        now = time.time()
        for k in [k for k, (exp, _) in self._items.items() if exp < now]:
            del self._items[k]

    def put(self, value: object, key: str | None = None) -> str:
        token = key or secrets.token_urlsafe(24)
        with self._lock:
            self._purge()
            self._items[token] = (time.time() + self.ttl, value)
        return token

    def get(self, token: str | None):
        if not token:
            return None
        with self._lock:
            self._purge()
            hit = self._items.get(token)
            return hit[1] if hit else None

    def pop(self, token: str | None):
        if not token:
            return None
        with self._lock:
            self._purge()
            hit = self._items.pop(token, None)
            return hit[1] if hit else None

    def expires_in(self, token: str | None) -> int:
        with self._lock:
            hit = self._items.get(token or "")
            return max(0, int(hit[0] - time.time())) if hit else 0
