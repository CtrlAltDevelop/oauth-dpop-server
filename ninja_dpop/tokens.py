"""Validating JWT access tokens at a resource server (RFC 9068 §4)."""

import time
from typing import Any

from joserfc import jws, jwt
from joserfc.errors import JoseError

from ninja_dpop.conf import ResourceServerSettings
from ninja_dpop.jwks import key_set

ACCESS_TOKEN_TYP = "at+jwt"
_MAX_TOKEN_LENGTH = 8192


class InvalidAccessToken(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def validate_access_token(token: str, conf: ResourceServerSettings) -> dict[str, Any]:
    """Return the claims of ``token`` if it may be used here, else raise.

    Following RFC 9068 §4: ``typ`` is ``at+jwt``, the signature verifies with
    one of the issuer's keys under an allowed algorithm, ``iss`` is the issuer
    exactly, ``aud`` names this resource server, and the token is within its
    lifetime. On top, RFC 9449 §6.1: the token is bound to a key.
    """
    if len(token) > _MAX_TOKEN_LENGTH or token.count(".") != 2:
        raise InvalidAccessToken("not a compact JWS")
    try:
        header = jws.extract_compact(token.encode("ascii")).headers()
    except (JoseError, ValueError, UnicodeError) as exc:
        raise InvalidAccessToken("unreadable JWT") from exc
    # Checked before the signature: the media type is what stops an ID token
    # or some other JWT from the same issuer being replayed as an access token.
    typ = header.get("typ")
    if not isinstance(typ, str) or typ.lower() not in {ACCESS_TOKEN_TYP, "application/at+jwt"}:
        raise InvalidAccessToken("typ is not at+jwt")
    kid = header.get("kid")
    try:
        keys = key_set(conf.jwks, max_age=conf.jwks_cache_seconds, kid=kid)
        decoded = jwt.decode(token, keys, algorithms=list(conf.token_algorithms))
    except (JoseError, ValueError) as exc:
        raise InvalidAccessToken("signature does not verify") from exc

    claims = dict(decoded.claims)
    if claims.get("iss") != conf.issuer:
        raise InvalidAccessToken("wrong issuer")
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if conf.audience not in audiences:
        raise InvalidAccessToken("wrong audience")

    now = int(time.time())
    exp, iat = claims.get("exp"), claims.get("iat")
    if not isinstance(exp, int) or not isinstance(iat, int):
        raise InvalidAccessToken("exp or iat missing")
    if exp <= now - conf.clock_skew:
        raise InvalidAccessToken("token expired")
    if iat > now + conf.clock_skew:
        raise InvalidAccessToken("token issued in the future")
    nbf = claims.get("nbf")
    if isinstance(nbf, int) and nbf > now + conf.clock_skew:
        raise InvalidAccessToken("token not yet valid")
    if not isinstance(claims.get("sub"), str):
        raise InvalidAccessToken("sub missing")

    cnf = claims.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jkt"), str):
        raise InvalidAccessToken("token is not DPoP-bound")
    return claims
