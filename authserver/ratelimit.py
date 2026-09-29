"""A fixed-window rate limit on the token endpoint, kept in Redis.

The token endpoint is where client secrets, authorization codes and refresh
tokens are guessed, and every request to it costs a signature verification.
The limit is per client address and applied before any of that work.

``REMOTE_ADDR`` is used as-is. Behind a reverse proxy it is the proxy's
address, so the proxy must set it from the real client address (with a
trusted-proxy aware middleware) or every client shares one budget.
"""

import time

from django.http import HttpRequest

from authserver.conf import server_settings
from authserver.errors import OAuthError
from authserver.redis import get_redis


def enforce_token_rate_limit(request: HttpRequest) -> None:
    conf = server_settings()
    window = int(time.time()) // conf.token_rate_window
    address = request.META.get("REMOTE_ADDR", "unknown")
    key = f"authserver:ratelimit:token:{address}:{window}"
    redis = get_redis()
    # INCR then EXPIRE in one round trip. The key only ever grows inside its
    # window, so a lost EXPIRE race costs at most one window's memory.
    pipeline = redis.pipeline()
    pipeline.incr(key)
    pipeline.expire(key, conf.token_rate_window, nx=True)
    count, _ = pipeline.execute()
    if int(count) > conf.token_rate_limit:
        retry_after = conf.token_rate_window - int(time.time()) % conf.token_rate_window
        raise OAuthError(
            "temporarily_unavailable",
            f"rate limit exceeded for {address}",
            status=429,
            headers={"Retry-After": str(retry_after)},
        )
