"""Building DPoP proofs for tests, correct by default and wrong on request."""

import base64
import json
import time
import uuid
from typing import Any

from joserfc import jws
from joserfc.jwk import ECKey, Key

from dpop.thumbprint import access_token_hash


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class ProofFactory:
    """Signs proofs with one key, the way a well-behaved client would.

    Every keyword argument of ``proof`` exists so a test can break exactly
    one thing and leave the rest valid.
    """

    def __init__(self, key: Key | None = None, algorithm: str = "ES256") -> None:
        self.key = key if key is not None else ECKey.generate_key("P-256", private=True)
        self.algorithm = algorithm

    @property
    def public_jwk(self) -> dict[str, Any]:
        return dict(self.key.as_dict(private=False))

    @property
    def jkt(self) -> str:
        return self.key.thumbprint()

    def proof(
        self,
        method: str,
        url: str,
        *,
        access_token: str | None = None,
        nonce: str | None = None,
        iat: int | None = None,
        jti: str | None = None,
        header: dict[str, Any] | None = None,
        claims: dict[str, Any] | None = None,
        drop: tuple[str, ...] = (),
    ) -> str:
        protected: dict[str, Any] = {
            "typ": "dpop+jwt",
            "alg": self.algorithm,
            "jwk": self.public_jwk,
        }
        protected.update(header or {})
        payload: dict[str, Any] = {
            "jti": jti or str(uuid.uuid4()),
            "htm": method,
            "htu": url,
            "iat": int(time.time()) if iat is None else iat,
        }
        if access_token is not None:
            payload["ath"] = access_token_hash(access_token)
        if nonce is not None:
            payload["nonce"] = nonce
        payload.update(claims or {})
        for name in drop:
            protected.pop(name, None)
            payload.pop(name, None)
        # Signed below the JOSE library's header validation, so a test can
        # produce exactly the malformed header it wants to see refused.
        signing_input = (
            f"{b64url(json.dumps(protected).encode())}.{b64url(json.dumps(payload).encode())}"
        )
        signature = jws.JWSRegistry.algorithms[self.algorithm].sign(
            signing_input.encode("ascii"), self.key
        )
        return f"{signing_input}.{b64url(signature)}"


def unsigned_proof(method: str, url: str, jwk: dict[str, Any]) -> str:
    """An ``alg: none`` proof, which no verifier may accept."""
    header = {"typ": "dpop+jwt", "alg": "none", "jwk": jwk}
    payload = {"jti": str(uuid.uuid4()), "htm": method, "htu": url, "iat": int(time.time())}
    return f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}."
