"""``DPoPAuth``: a Django Ninja auth class for DPoP-bound access tokens.

For each request it checks, in this order:

1. ``Authorization: DPoP <token>`` is present — never ``Bearer``, which for a
   bound token is itself a reason to refuse (RFC 9449 §7.2);
2. the token is a valid RFC 9068 access token from the configured issuer,
   for this audience, and carries ``cnf.jkt`` (RFC 9449 §6.1);
3. the ``DPoP`` proof passes every check of RFC 9449 §4.3, including
   ``ath`` against this exact token and a signature from the ``cnf.jkt`` key
   (§4.3 step 12, §7.1);
4. the token grants every scope the operation asks for.
"""

from dataclasses import dataclass, field
from typing import Any

from django.http import HttpRequest
from django.utils.module_loading import import_string
from ninja.security.base import AuthBase

from dpop import (
    DPoPError,
    ProofPolicy,
    ProofVerifier,
    RedisNonceStore,
    RedisReplayCache,
    UseDPoPNonce,
    single_proof,
)
from ninja_dpop.conf import ResourceServerSettings, resource_server_settings
from ninja_dpop.errors import DPoPAuthError
from ninja_dpop.tokens import InvalidAccessToken, validate_access_token

_NAMESPACE = "ninja_dpop"


@dataclass(frozen=True, slots=True)
class DPoPPrincipal:
    """What an authenticated request is allowed to know about its caller.

    Available to operations as ``request.auth``.
    """

    subject: str
    client_id: str
    scopes: frozenset[str]
    jkt: str
    claims: dict[str, Any] = field(repr=False)


def _nonces(conf: ResourceServerSettings) -> RedisNonceStore:
    return RedisNonceStore(
        import_string(conf.redis)(), rotation=conf.nonce_rotation, namespace=f"{_NAMESPACE}:nonce"
    )


def _verifier(conf: ResourceServerSettings) -> ProofVerifier:
    return ProofVerifier(
        ProofPolicy(
            algorithms=conf.algorithms,
            max_age=conf.proof_max_age,
            clock_skew=conf.clock_skew,
            require_nonce=conf.require_nonce,
        ),
        replay_cache=RedisReplayCache(import_string(conf.redis)(), namespace=f"{_NAMESPACE}:jti"),
        nonces=_nonces(conf) if conf.require_nonce else None,
    )


def _request_url(request: HttpRequest, conf: ResourceServerSettings) -> str:
    if conf.origin is not None:
        return f"{conf.origin}{request.path}"
    return request.build_absolute_uri(request.path)


class DPoPAuth(AuthBase):
    """Authenticate with a DPoP-bound access token, optionally requiring scopes.

    ::

        api = NinjaAPI(auth=DPoPAuth())
        ninja_dpop.install(api)

        @api.post("/orders", auth=DPoPAuth(scopes=["orders:write"]))
        def place_order(request): ...
    """

    openapi_type = "http"
    openapi_scheme = "DPoP"

    def __init__(self, scopes: list[str] | None = None) -> None:
        super().__init__()
        self.scopes = frozenset(scopes or [])

    def __call__(self, request: HttpRequest) -> DPoPPrincipal:
        conf = resource_server_settings()
        scheme, _, token = request.META.get("HTTP_AUTHORIZATION", "").partition(" ")
        token = token.strip()
        scheme = scheme.lower()
        if not scheme:
            raise DPoPAuthError(None, "no Authorization header")
        if scheme == "bearer":
            # RFC 9449 §7.2: every token here is DPoP-bound, and a bound token
            # presented as Bearer means either a confused client or a thief
            # hoping the proof is not checked.
            raise DPoPAuthError("invalid_token", "DPoP-bound token presented as Bearer")
        if scheme != "dpop" or not token or " " in token:
            raise DPoPAuthError("invalid_request", "Authorization is not 'DPoP <token>'")

        try:
            claims = validate_access_token(token, conf)
        except InvalidAccessToken as exc:
            raise DPoPAuthError("invalid_token", exc.reason) from exc
        jkt = claims["cnf"]["jkt"]

        raw = request.META.get("HTTP_DPOP")
        try:
            proof = single_proof([raw] if raw is not None else [])
            if proof is None:
                raise DPoPAuthError("invalid_dpop_proof", "no DPoP proof")
            _verifier(conf).verify(
                proof,
                method=request.method or "",
                url=_request_url(request, conf),
                access_token=token,
                bound_jkt=jkt,
            )
        except UseDPoPNonce as exc:
            raise DPoPAuthError(exc.error, exc.reason, nonce=_nonces(conf).current()) from exc
        except DPoPError as exc:
            raise DPoPAuthError(exc.error, exc.reason) from exc

        granted = frozenset(str(claims.get("scope", "")).split())
        if not self.scopes <= granted:
            raise DPoPAuthError(
                "insufficient_scope",
                f"token lacks {sorted(self.scopes - granted)}",
                status=403,
                scope=" ".join(sorted(self.scopes)),
            )
        return DPoPPrincipal(
            subject=str(claims["sub"]),
            client_id=str(claims.get("client_id", "")),
            scopes=granted,
            jkt=jkt,
            claims=claims,
        )
