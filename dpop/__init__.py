"""DPoP proof verification (RFC 9449), independent of any web framework.

Used by both halves of this project: the authorization server checks proofs
at its token endpoint, and ``ninja_dpop`` checks them at resource servers.
"""

from dpop.errors import DPoPError, InvalidDPoPProof, UseDPoPNonce
from dpop.htu import normalize_htu
from dpop.nonce import NonceStore, RedisNonceStore
from dpop.proof import ProofPolicy, ProofVerifier, VerifiedProof, single_proof
from dpop.replay import RedisReplayCache, ReplayCache
from dpop.thumbprint import access_token_hash, jwk_thumbprint

__all__ = [
    "DPoPError",
    "InvalidDPoPProof",
    "NonceStore",
    "ProofPolicy",
    "ProofVerifier",
    "RedisNonceStore",
    "RedisReplayCache",
    "ReplayCache",
    "UseDPoPNonce",
    "VerifiedProof",
    "access_token_hash",
    "jwk_thumbprint",
    "normalize_htu",
    "single_proof",
]
