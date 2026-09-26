"""DPoP at the authorization server: checking proofs sent to its endpoints."""

from django.http import HttpRequest

from authserver.conf import server_settings
from authserver.errors import OAuthError
from authserver.redis import get_redis
from dpop import (
    DPoPError,
    ProofPolicy,
    ProofVerifier,
    RedisNonceStore,
    RedisReplayCache,
    VerifiedProof,
    single_proof,
)

_NAMESPACE = "authserver"


def nonce_store() -> RedisNonceStore:
    conf = server_settings()
    return RedisNonceStore(
        get_redis(), rotation=conf.dpop_nonce_rotation, namespace=f"{_NAMESPACE}:dpop:nonce"
    )


def nonce_headers() -> dict[str, str]:
    """The ``DPoP-Nonce`` header for a response (RFC 9449 §8).

    Sent on every response from an endpoint that takes proofs, success or
    failure, so a client always holds the current nonce and rotation never
    costs it an extra round trip.
    """
    if not server_settings().dpop_require_nonce:
        return {}
    return {"DPoP-Nonce": nonce_store().current()}


def _verifier() -> ProofVerifier:
    conf = server_settings()
    return ProofVerifier(
        ProofPolicy(
            algorithms=conf.dpop_algorithms,
            max_age=conf.dpop_proof_max_age,
            clock_skew=conf.dpop_clock_skew,
            require_nonce=conf.dpop_require_nonce,
        ),
        replay_cache=RedisReplayCache(get_redis(), namespace=f"{_NAMESPACE}:dpop:jti"),
        nonces=nonce_store() if conf.dpop_require_nonce else None,
    )


def optional_proof(request: HttpRequest, path: str) -> VerifiedProof | None:
    """Check the DPoP proof on a request to one of this server's endpoints,
    if it carries one.

    ``htu`` is compared with the endpoint's URL as derived from the configured
    issuer, not with whatever ``Host`` header the request arrived with — a
    value an attacker controls and a reverse proxy may rewrite.
    """
    raw = request.META.get("HTTP_DPOP")
    try:
        proof = single_proof([raw] if raw is not None else [])
        if proof is None:
            return None
        return _verifier().verify(
            proof, method=request.method or "", url=server_settings().endpoint(path)
        )
    except DPoPError as exc:
        raise OAuthError(exc.error, exc.reason) from exc


def require_proof(request: HttpRequest, path: str) -> VerifiedProof:
    """As ``optional_proof``, for endpoints where a missing proof is an error."""
    proof = optional_proof(request, path)
    if proof is None:
        raise OAuthError("invalid_dpop_proof", "DPoP proof is required")
    return proof
