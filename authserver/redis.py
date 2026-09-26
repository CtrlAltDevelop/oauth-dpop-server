"""The Redis connection shared by the replay cache, nonces and rate limits."""

from django.conf import settings
from redis import Redis

_client: "Redis | None" = None


def get_redis() -> "Redis":
    """One client per process; redis-py pools connections underneath it."""
    global _client
    if _client is None:
        _client = Redis.from_url(settings.REDIS_URL)
    return _client


def use_redis(client: "Redis | None") -> None:
    """Replace the process's connection. The test suite points it at fakeredis."""
    global _client
    _client = client
