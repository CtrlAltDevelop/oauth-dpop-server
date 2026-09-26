"""Typed access to the authorization server's settings.

Every value is read from ``django.conf.settings`` at call time rather than
captured at import, so ``override_settings`` in a test changes behaviour the
way it would in a real deployment.
"""

from dataclasses import dataclass
from typing import Any

from django.conf import settings

DEFAULT_SCOPES: dict[str, str] = {
    "profile": "See your username",
    "orders:read": "See your orders",
    "orders:write": "Place orders on your behalf",
}

# RFC 9449 leaves the choice to the server. ES256 is what clients actually
# ship (dpop_client signs with nothing else). Ed25519 is the fully-specified
# name RFC 9864 gives what used to be "EdDSA". PS256 covers RSA keys; RS256's
# PKCS #1 v1.5 padding is left out on purpose.
DEFAULT_DPOP_ALGORITHMS: tuple[str, ...] = ("ES256", "ES384", "Ed25519", "PS256")


@dataclass(frozen=True, slots=True)
class ServerSettings:
    issuer: str
    audience: str
    scopes: dict[str, str]
    access_token_ttl: int
    authorization_code_ttl: int
    refresh_token_ttl: int
    refresh_family_ttl: int
    par_ttl: int
    dpop_algorithms: frozenset[str]
    dpop_proof_max_age: int
    dpop_clock_skew: int
    dpop_require_nonce: bool
    dpop_nonce_rotation: int
    signing_key_retention: int
    key_encryption_secret: str
    token_rate_limit: int
    token_rate_window: int

    def endpoint(self, path: str) -> str:
        """The absolute URL of one of this server's endpoints."""
        return f"{self.issuer}{path}"


def _get(name: str, default: Any) -> Any:
    return getattr(settings, name, default)


def server_settings() -> ServerSettings:
    issuer = str(_get("OAUTH_ISSUER", "http://localhost:8000")).rstrip("/")
    access_token_ttl = int(_get("OAUTH_ACCESS_TOKEN_TTL", 300))
    return ServerSettings(
        issuer=issuer,
        audience=str(_get("OAUTH_ACCESS_TOKEN_AUDIENCE", f"{issuer}/api")),
        scopes=dict(_get("OAUTH_SCOPES", DEFAULT_SCOPES)),
        access_token_ttl=access_token_ttl,
        authorization_code_ttl=int(_get("OAUTH_AUTHORIZATION_CODE_TTL", 60)),
        refresh_token_ttl=int(_get("OAUTH_REFRESH_TOKEN_TTL", 14 * 24 * 3600)),
        refresh_family_ttl=int(_get("OAUTH_REFRESH_FAMILY_TTL", 30 * 24 * 3600)),
        par_ttl=int(_get("OAUTH_PAR_TTL", 60)),
        dpop_algorithms=frozenset(_get("OAUTH_DPOP_ALGORITHMS", DEFAULT_DPOP_ALGORITHMS)),
        dpop_proof_max_age=int(_get("OAUTH_DPOP_PROOF_MAX_AGE", 60)),
        dpop_clock_skew=int(_get("OAUTH_DPOP_CLOCK_SKEW", 5)),
        dpop_require_nonce=bool(_get("OAUTH_DPOP_REQUIRE_NONCE", True)),
        dpop_nonce_rotation=int(_get("OAUTH_DPOP_NONCE_ROTATION", 300)),
        # A retired key stays in the JWKS until every token it signed has
        # expired, plus a margin for resource servers' clocks and caches.
        signing_key_retention=int(
            _get("OAUTH_SIGNING_KEY_RETENTION", access_token_ttl + 3600),
        ),
        key_encryption_secret=str(_get("OAUTH_KEY_ENCRYPTION_SECRET", settings.SECRET_KEY)),
        token_rate_limit=int(_get("OAUTH_TOKEN_RATE_LIMIT", 60)),
        token_rate_window=int(_get("OAUTH_TOKEN_RATE_WINDOW", 60)),
    )
