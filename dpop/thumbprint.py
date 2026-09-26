"""JWK SHA-256 thumbprints (RFC 7638), the ``jkt`` a DPoP token is bound to."""

import base64
import hashlib
from typing import Any

from joserfc.jwk import JWKRegistry


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """The base64url SHA-256 thumbprint of a JWK's required members.

    RFC 7638 §3.2 fixes the members per key type and §3.3 the serialization
    (lexicographic order, no whitespace); joserfc implements both, and the
    test suite pins it to the RFC's own example.
    """
    return JWKRegistry.import_key(jwk).thumbprint()


def access_token_hash(access_token: str) -> str:
    """The ``ath`` value for a token: base64url(SHA-256(ASCII(token))), RFC 9449 §4.2."""
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
