"""Where the authorization server's signing keys come from.

Fetched keys are cached for ``JWKS_CACHE_SECONDS``. A token signed by a
``kid`` the cache does not know triggers one early refetch — that is how a
freshly rotated key is picked up — but no more than once every
``_REFETCH_FLOOR`` seconds, so a stream of tokens with invented ``kid``
values cannot turn this server into a load generator aimed at the issuer.
"""

import json
import threading
import time
import urllib.request
from typing import Any

from django.utils.module_loading import import_string
from joserfc.jwk import KeySet

_REFETCH_FLOOR = 30
_TIMEOUT = 5
_MAX_BYTES = 256 * 1024


class _CachedKeySet:
    def __init__(self) -> None:
        self.keys: KeySet | None = None
        self.fetched_at = 0.0
        self.lock = threading.Lock()


_cache: dict[str, _CachedKeySet] = {}
_cache_lock = threading.Lock()


def _fetch(url: str) -> dict[str, Any]:
    if not url.startswith(("https://", "http://")):
        raise ValueError("JWKS URL must be http(s)")
    request = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:  # noqa: S310
        body: dict[str, Any] = json.loads(response.read(_MAX_BYTES))
    return body


def _load(source: str) -> dict[str, Any]:
    if source.startswith(("https://", "http://")):
        return _fetch(source)
    loader = import_string(source)
    body: dict[str, Any] = loader()
    return body


def key_set(source: str, *, max_age: int, kid: str | None = None) -> KeySet:
    """The key set from ``source``, refreshed when stale or missing ``kid``."""
    with _cache_lock:
        entry = _cache.setdefault(source, _CachedKeySet())
    with entry.lock:
        now = time.monotonic()
        stale = entry.keys is None or now - entry.fetched_at > max_age
        unknown = (
            kid is not None
            and entry.keys is not None
            and not any(key.kid == kid for key in entry.keys.keys)
            and now - entry.fetched_at > _REFETCH_FLOOR
        )
        if entry.keys is None or stale or unknown:
            entry.keys = KeySet.import_key_set(_load(source))  # type: ignore[arg-type]
            entry.fetched_at = now
        return entry.keys


def clear_cache() -> None:
    """Forget every cached key set (for tests, and after an emergency rotation)."""
    with _cache_lock:
        _cache.clear()
