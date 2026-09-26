"""Server-issued DPoP nonces (RFC 9449 §8 and §9).

A nonce proves a proof was made *after* the server said something — which
``iat`` cannot, because ``iat`` is whatever the client (or an attacker who
briefly held the key) chose to write. It limits pre-generated proofs to the
nonce's lifetime, however far into the future their ``iat`` was set.

Nonces here are random, shared through Redis, and rotate: one is current
and handed out for ``rotation`` seconds, and each stays acceptable for twice
that, so a client that fetched one just before a rotation is not refused
immediately after it.
"""

import re
import secrets
from typing import Protocol

from redis import Redis

# Nonce values are ours, so anything not shaped like one is refused before it
# reaches Redis.
_NONCE_SHAPE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def _text(value: bytes | str) -> str:
    # Whether Redis hands back bytes or str depends on how the client was built.
    return value.decode("ascii") if isinstance(value, bytes) else value


class NonceStore(Protocol):
    def current(self) -> str:
        """The nonce clients should put in their next proof."""
        ...

    def is_valid(self, nonce: str) -> bool:
        """Whether ``nonce`` was issued by this server and has not expired."""
        ...


class RedisNonceStore:
    def __init__(self, redis: "Redis", *, rotation: int, namespace: str = "dpop:nonce") -> None:
        self._redis = redis
        self._rotation = rotation
        self._current_key = f"{namespace}:current"
        self._valid_prefix = f"{namespace}:valid:"

    def current(self) -> str:
        existing = self._redis.get(self._current_key)
        if existing is not None:
            return _text(existing)
        candidate = secrets.token_urlsafe(24)
        # Valid before it is published, so no client can receive a nonce the
        # server would refuse.
        self._redis.set(f"{self._valid_prefix}{candidate}", b"1", ex=2 * self._rotation)
        if self._redis.set(self._current_key, candidate, nx=True, ex=self._rotation):
            return candidate
        # Another worker rotated first; converge on its nonce.
        winner = self._redis.get(self._current_key)
        return _text(winner) if winner is not None else candidate

    def is_valid(self, nonce: str) -> bool:
        if not _NONCE_SHAPE.match(nonce):
            return False
        return bool(self._redis.exists(f"{self._valid_prefix}{nonce}"))
