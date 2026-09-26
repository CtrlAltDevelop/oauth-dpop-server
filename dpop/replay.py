"""Remembering which proofs have been seen (RFC 9449 §11.1).

A proof's ``iat`` window stops an old proof from being replayed; it does
nothing about a proof replayed *inside* the window, a few seconds after an
attacker lifted it off the wire or out of a log. For that the server must
remember every ``jti`` it has accepted for as long as the proof could still
pass the ``iat`` check, and refuse to see one twice.
"""

import hashlib
from typing import Protocol

from redis import Redis


class ReplayCache(Protocol):
    def first_use(self, key: str, ttl: int) -> bool:
        """Record ``key``; True if it had not been seen within its ttl."""
        ...


class RedisReplayCache:
    """Replay cache in Redis, shared by every worker and instance.

    One atomic ``SET NX EX`` per proof: there is no read-then-write window in
    which two concurrent requests carrying the same proof could both pass.
    """

    def __init__(self, redis: "Redis", namespace: str = "dpop:jti") -> None:
        self._redis = redis
        self._namespace = namespace

    def first_use(self, key: str, ttl: int) -> bool:
        # Hashed so an attacker-chosen jti cannot shape our keyspace.
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return bool(self._redis.set(f"{self._namespace}:{digest}", b"1", nx=True, ex=ttl))
