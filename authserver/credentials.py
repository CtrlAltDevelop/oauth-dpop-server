"""Generating, hashing and comparing the server's opaque credentials."""

import hashlib
import hmac
import secrets

# 32 bytes is 256 bits of entropy: far past guessing, and past the point where
# a birthday collision between two live tokens is worth a thought.
TOKEN_BYTES = 32


def new_token() -> str:
    """A fresh URL-safe credential with 256 bits of entropy."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def digest(value: str) -> str:
    """The SHA-256 hex digest under which a credential is stored.

    Lookups go by digest, so the plaintext never touches the database and a
    timing difference in the index lookup reveals nothing about it.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    """Compare two secrets without leaking where they first differ."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
