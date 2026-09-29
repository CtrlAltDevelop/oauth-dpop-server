"""Configuration, read from ``settings.NINJA_DPOP`` on every request.

Required keys:

``ISSUER``     the authorization server's issuer identifier, compared exactly
               with each token's ``iss``.
``AUDIENCE``   this resource server's identifier; a token's ``aud`` must
               contain it (RFC 9068 §4).
``JWKS``       where the issuer's signing keys come from: an ``https://`` URL
               (fetched and cached), or the dotted path of a callable
               returning a JWK Set dict (for a resource server living in the
               authorization server's process).
``REDIS``      dotted path of a callable returning a ``redis.Redis`` client,
               used for the jti replay cache and nonces.

Optional keys, with defaults:

``ORIGIN``              the public origin requests arrive at, e.g.
                        ``https://api.example.com``. The ``htu`` of every
                        proof is compared with ``ORIGIN + request.path``.
                        Unset, the origin is taken from the request, which is
                        only as trustworthy as ``ALLOWED_HOSTS`` and the proxy
                        in front — set it in production.
``ALGORITHMS``          DPoP proof algorithms accepted: ``["ES256"]``.
``TOKEN_ALGORITHMS``    access token algorithms accepted: ``["ES256"]``.
``PROOF_MAX_AGE``       seconds a proof stays acceptable: 60.
``CLOCK_SKEW``          seconds of clock difference tolerated: 5.
``REQUIRE_NONCE``       demand server nonces (RFC 9449 §9): ``False``.
``NONCE_ROTATION``      seconds between nonce rotations: 300.
``JWKS_CACHE_SECONDS``  how long fetched keys are trusted: 300.
"""

from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

_REQUIRED = ("ISSUER", "AUDIENCE", "JWKS", "REDIS")


@dataclass(frozen=True, slots=True)
class ResourceServerSettings:
    issuer: str
    audience: str
    jwks: str
    redis: str
    origin: str | None
    algorithms: frozenset[str]
    token_algorithms: frozenset[str]
    proof_max_age: int
    clock_skew: int
    require_nonce: bool
    nonce_rotation: int
    jwks_cache_seconds: int


def resource_server_settings() -> ResourceServerSettings:
    raw: dict[str, Any] = getattr(settings, "NINJA_DPOP", None) or {}
    missing = [key for key in _REQUIRED if not raw.get(key)]
    if missing:
        raise ImproperlyConfigured(f"NINJA_DPOP is missing {', '.join(missing)}")
    origin = raw.get("ORIGIN")
    return ResourceServerSettings(
        issuer=str(raw["ISSUER"]),
        audience=str(raw["AUDIENCE"]),
        jwks=str(raw["JWKS"]),
        redis=str(raw["REDIS"]),
        origin=str(origin).rstrip("/") if origin else None,
        algorithms=frozenset(raw.get("ALGORITHMS", ["ES256"])),
        token_algorithms=frozenset(raw.get("TOKEN_ALGORITHMS", ["ES256"])),
        proof_max_age=int(raw.get("PROOF_MAX_AGE", 60)),
        clock_skew=int(raw.get("CLOCK_SKEW", 5)),
        require_nonce=bool(raw.get("REQUIRE_NONCE", False)),
        nonce_rotation=int(raw.get("NONCE_ROTATION", 300)),
        jwks_cache_seconds=int(raw.get("JWKS_CACHE_SECONDS", 300)),
    )
