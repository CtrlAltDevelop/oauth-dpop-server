"""OAuth error responses, with deliberately uniform descriptions.

A client learns *which* error code applies — the RFCs require that — but the
description never says which of several checks failed. "Unknown code",
"expired code", "code for another client" and "wrong PKCE verifier" all read
the same, so an attacker probing the token endpoint learns nothing from the
difference. The precise reason goes to the server log instead.
"""

import logging

from django.http import JsonResponse

logger = logging.getLogger("authserver")

# One description per error code, used for every cause of that error.
DESCRIPTIONS: dict[str, str] = {
    "invalid_request": "The request is missing a parameter, repeats one, or is malformed.",
    "invalid_client": "Client authentication failed.",
    "invalid_grant": "The grant is invalid, expired, revoked, or was issued to another client.",
    "unauthorized_client": "The client is not allowed to use this grant type.",
    "unsupported_grant_type": "The grant type is not supported.",
    "unsupported_response_type": "The response type is not supported.",
    "invalid_scope": "The requested scope is invalid or exceeds what the client may request.",
    "access_denied": "The resource owner denied the request.",
    "invalid_dpop_proof": "The DPoP proof is invalid.",
    "use_dpop_nonce": "The authorization server requires a nonce in the DPoP proof.",
    "unsupported_token_type": "The token type is not supported.",
    "temporarily_unavailable": "Too many requests. Retry after the time given in Retry-After.",
}


class OAuthError(Exception):
    """An error the client is told about (RFC 6749 §5.2, RFC 9449 §5 and §8)."""

    def __init__(
        self,
        error: str,
        reason: str,
        *,
        status: int = 400,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(reason)
        self.error = error
        self.reason = reason
        self.status = status
        self.headers = headers or {}

    @property
    def description(self) -> str:
        return DESCRIPTIONS[self.error]

    def response(self) -> JsonResponse:
        logger.info("oauth error %s: %s", self.error, self.reason)
        response = JsonResponse(
            {"error": self.error, "error_description": self.description}, status=self.status
        )
        # RFC 6749 §5.1/§5.2: token responses, errors included, are never cached.
        response["Cache-Control"] = "no-store"
        for name, value in self.headers.items():
            response[name] = value
        return response
