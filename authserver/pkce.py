"""Proof Key for Code Exchange (RFC 7636), S256 only.

OAuth 2.1 §4.1.1 makes PKCE mandatory for every client, and this server
accepts only the S256 method: "plain" sends the verifier's equal over the
front channel, which defends against nothing that S256 does not.
"""

import base64
import hashlib
import hmac
import re

S256 = "S256"

# RFC 7636 §4.1: 43 to 128 characters from the unreserved set.
_VERIFIER = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
# RFC 7636 §4.2: BASE64URL(SHA256(verifier)) is always exactly 43 characters.
_CHALLENGE = re.compile(r"^[A-Za-z0-9\-_]{43}$")


def is_valid_challenge(challenge: str) -> bool:
    return bool(_CHALLENGE.match(challenge))


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify(verifier: str, challenge: str) -> bool:
    """Whether ``verifier`` answers ``challenge`` (RFC 7636 §4.6)."""
    if not _VERIFIER.match(verifier):
        return False
    return hmac.compare_digest(s256(verifier).encode("ascii"), challenge.encode("ascii"))
