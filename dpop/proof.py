"""Verifying a DPoP proof JWT, following RFC 9449 §4.3 step by step.

The numbered comments in ``ProofVerifier.verify`` are the step numbers of
§4.3's checklist, so the code can be audited against the RFC line by line.
The one deliberate reordering: step 7 (no private key in ``jwk``) runs before
step 6 (signature), because there is no point verifying a signature with a
key the client has just published to the world.
"""

import hmac
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import JWKRegistry, Key, RSAKey

from dpop.errors import InvalidDPoPProof
from dpop.htu import normalize_htu
from dpop.thumbprint import access_token_hash

# Asymmetric algorithms only (§4.3 step 5 forbids MAC-based ones and "none"),
# each pinned to the key type and curve it may be used with. Pinning closes
# off key-confusion games that the JOSE library would otherwise have to
# catch for us.
ALGORITHM_KEY_TYPES: dict[str, tuple[str, str | None]] = {
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
    "ES512": ("EC", "P-521"),
    "Ed25519": ("OKP", "Ed25519"),
    "PS256": ("RSA", None),
    "PS384": ("RSA", None),
    "PS512": ("RSA", None),
    "RS256": ("RSA", None),
}
SUPPORTED_ALGORITHMS = frozenset(ALGORITHM_KEY_TYPES)

MIN_RSA_BITS = 2048
# RFC 7517 §6.2.2, §6.3.2 and §6.4: members that only a private key has.
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
# A proof is a few hundred bytes; an RSA-4096 key in the header takes it past
# one kilobyte. Anything past this is not a proof.
MAX_PROOF_LENGTH = 8192
MAX_JTI_LENGTH = 256


@dataclass(frozen=True, slots=True)
class ProofPolicy:
    """What a verifier accepts. Immutable, so it can be shared across requests."""

    algorithms: frozenset[str]
    max_age: int = 60
    clock_skew: int = 5

    def __post_init__(self) -> None:
        unsupported = self.algorithms - SUPPORTED_ALGORITHMS
        if unsupported:
            raise ValueError(f"unsupported DPoP algorithms: {sorted(unsupported)}")
        if not self.algorithms:
            raise ValueError("at least one DPoP algorithm must be allowed")


@dataclass(frozen=True, slots=True)
class VerifiedProof:
    """A proof that passed every check, and what the caller needs from it."""

    jkt: str
    jti: str
    htm: str
    htu: str
    iat: int
    nonce: str | None
    jwk: dict[str, Any] = field(repr=False)


def single_proof(values: list[str]) -> str | None:
    """The one proof carried by a request's ``DPoP`` header field(s).

    §4.3 step 1: "there is not more than one DPoP HTTP request header field".
    A proxy may fold repeated fields into one comma-separated value, and a
    compact JWS contains no comma, so a comma is a second proof as well.
    """
    if not values:
        return None
    if len(values) > 1 or "," in values[0]:
        raise InvalidDPoPProof("more than one DPoP header")
    return values[0].strip()


def _registry(algorithm: str | None) -> jws.JWSRegistry:
    registry = jws.JWSRegistry(
        algorithms=[algorithm] if algorithm else None, strict_check_header=False
    )
    # joserfc caps the protected header at 512 bytes, which an RSA public key
    # in `jwk` alone exceeds.
    registry.max_header_length = MAX_PROOF_LENGTH
    return registry


def _import_public_key(jwk: Any, algorithm: str) -> Key:
    if not isinstance(jwk, dict):
        raise InvalidDPoPProof("jwk header is not a JSON object")
    # Step 7.
    if PRIVATE_JWK_MEMBERS & jwk.keys():
        raise InvalidDPoPProof("jwk header contains private key material")
    kty, crv = ALGORITHM_KEY_TYPES[algorithm]
    if jwk.get("kty") != kty or (crv is not None and jwk.get("crv") != crv):
        raise InvalidDPoPProof("jwk key type does not match alg")
    if "alg" in jwk and jwk["alg"] != algorithm:
        raise InvalidDPoPProof("jwk alg member contradicts the alg header")
    try:
        key = JWKRegistry.import_key(jwk)
    except (JoseError, ValueError, TypeError) as exc:
        raise InvalidDPoPProof("jwk header is not a valid public key") from exc
    if isinstance(key, RSAKey) and key.public_key.key_size < MIN_RSA_BITS:
        raise InvalidDPoPProof("RSA key is too short")
    return key


def _require_str(claims: dict[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise InvalidDPoPProof(f"{name} claim is missing or not a string")
    return value


class ProofVerifier:
    """Checks DPoP proofs against one policy.

    ``clock`` returns the current Unix time; tests pass a fixed one.
    """

    def __init__(self, policy: ProofPolicy, *, clock: Callable[[], float] = time.time) -> None:
        self._policy = policy
        self._clock = clock

    def verify(
        self,
        proof: str,
        *,
        method: str,
        url: str,
        access_token: str | None = None,
        bound_jkt: str | None = None,
    ) -> VerifiedProof:
        """Verify ``proof`` for a request of ``method`` to ``url``.

        Pass ``access_token`` when the request presents one (resource server
        requests): the proof must then carry a matching ``ath``. Pass
        ``bound_jkt`` when the credential in play is bound to a key — a token's
        ``cnf.jkt``, a refresh token's binding, an authorization request's
        ``dpop_jkt`` — and the proof must be signed by that key.

        Raises ``InvalidDPoPProof`` naming the first check that failed.
        """
        if len(proof) > MAX_PROOF_LENGTH:
            raise InvalidDPoPProof("proof is too large")

        # Step 2: a well-formed JWT.
        try:
            compact = jws.extract_compact(proof.encode("ascii"), registry=_registry(None))
            header = compact.headers()
            claims = json.loads(compact.payload)
        except (JoseError, ValueError, UnicodeError) as exc:
            raise InvalidDPoPProof("proof is not a well-formed JWT") from exc
        if not isinstance(claims, dict):
            raise InvalidDPoPProof("proof payload is not a JSON object")

        # Step 3: every required header member and claim is present.
        for member in ("typ", "alg", "jwk"):
            if member not in header:
                raise InvalidDPoPProof(f"{member} header is missing")
        jti = _require_str(claims, "jti")
        htm = _require_str(claims, "htm")
        htu = _require_str(claims, "htu")
        iat = claims.get("iat")
        # bool is an int in Python, and `"iat": true` is not a timestamp.
        if not isinstance(iat, int) or isinstance(iat, bool):
            raise InvalidDPoPProof("iat claim is missing or not an integer")
        if len(jti) > MAX_JTI_LENGTH:
            raise InvalidDPoPProof("jti claim is too long")

        # Step 4: typ is dpop+jwt. Media types compare case-insensitively
        # (RFC 7515 §4.1.9).
        typ = header["typ"]
        if not isinstance(typ, str) or typ.lower() != "dpop+jwt":
            raise InvalidDPoPProof("typ header is not dpop+jwt")

        # Step 5: an asymmetric algorithm this server accepts. "none" and the
        # HMAC family are not in SUPPORTED_ALGORITHMS, so they cannot be allowed.
        algorithm = header["alg"]
        if not isinstance(algorithm, str) or algorithm not in self._policy.algorithms:
            raise InvalidDPoPProof("alg is not an accepted asymmetric algorithm")

        # Step 7, then step 6: a public key, and a signature it verifies.
        public_key = _import_public_key(header["jwk"], algorithm)
        try:
            valid = jws.validate_compact(compact, public_key, registry=_registry(algorithm))
        except JoseError as exc:
            raise InvalidDPoPProof("signature does not verify") from exc
        if not valid:
            raise InvalidDPoPProof("signature does not verify")

        # Step 8: htm matches the request method. Methods are case-sensitive
        # (RFC 9110 §9.1).
        if htm != method:
            raise InvalidDPoPProof("htm does not match the request method")

        # Step 9: htu matches the request URI, ignoring query and fragment.
        try:
            matches = normalize_htu(htu) == normalize_htu(url)
        except ValueError as exc:
            raise InvalidDPoPProof("htu is not a valid request URI") from exc
        if not matches:
            raise InvalidDPoPProof("htu does not match the request URI")

        # Step 11: created within the acceptable window. Up to `clock_skew`
        # seconds in the future is tolerated for clients whose clocks run
        # fast; older than `max_age` (plus the same skew) is stale.
        now = int(self._clock())
        if iat > now + self._policy.clock_skew:
            raise InvalidDPoPProof("iat is in the future")
        if iat < now - self._policy.max_age - self._policy.clock_skew:
            raise InvalidDPoPProof("proof has expired")

        jkt = public_key.thumbprint()

        # Step 12: bound to the access token presented with it, and signed by
        # the key that token is bound to.
        if access_token is not None:
            ath = claims.get("ath")
            if not isinstance(ath, str):
                raise InvalidDPoPProof("ath claim is missing")
            try:
                expected = access_token_hash(access_token)
            except UnicodeError as exc:
                raise InvalidDPoPProof("access token is not ASCII") from exc
            if not hmac.compare_digest(ath.encode("ascii", "replace"), expected.encode("ascii")):
                raise InvalidDPoPProof("ath does not match the access token")
        if bound_jkt is not None and not hmac.compare_digest(
            jkt.encode("ascii"), bound_jkt.encode("ascii", "replace")
        ):
            raise InvalidDPoPProof("proof key does not match the bound key")

        nonce = claims.get("nonce")
        return VerifiedProof(
            jkt=jkt,
            jti=jti,
            htm=htm,
            htu=htu,
            iat=iat,
            nonce=nonce if isinstance(nonce, str) else None,
            jwk=dict(header["jwk"]),
        )
