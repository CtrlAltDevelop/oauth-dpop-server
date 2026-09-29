"""Resource server error responses (RFC 9449 §7.1 and §9, RFC 6750 §3)."""

from typing import ClassVar

from django.http import HttpRequest, HttpResponse, JsonResponse
from ninja import NinjaAPI

from ninja_dpop.conf import resource_server_settings


def _quote(value: str) -> str:
    # auth-param values are quoted-strings (RFC 9110 §11.2); none of ours
    # contain a quote or backslash, but a scope a client sent might.
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class DPoPAuthError(Exception):
    """A request the resource server refuses.

    ``error`` is None when the request carried no credentials at all:
    RFC 6750 §3.1 has the challenge omit the error code in that case.
    ``reason`` is for the log; the description sent to the client is fixed
    per error code.
    """

    DESCRIPTIONS: ClassVar[dict[str, str]] = {
        "invalid_token": "The access token is invalid, expired, or not bound to this proof.",
        "invalid_dpop_proof": "The DPoP proof is invalid.",
        "use_dpop_nonce": "The resource server requires a nonce in the DPoP proof.",
        "insufficient_scope": "The access token does not grant the scope this request needs.",
        "invalid_request": "The request is malformed.",
    }

    def __init__(
        self,
        error: str | None,
        reason: str,
        *,
        status: int = 401,
        scope: str | None = None,
        nonce: str | None = None,
    ) -> None:
        super().__init__(reason)
        self.error = error
        self.reason = reason
        self.status = status
        self.scope = scope
        self.nonce = nonce

    def challenge(self) -> str:
        params: list[str] = []
        if self.error is not None:
            params.append(f"error={_quote(self.error)}")
            params.append(f"error_description={_quote(self.DESCRIPTIONS[self.error])}")
        if self.scope is not None:
            params.append(f"scope={_quote(self.scope)}")
        # RFC 9449 §7.1: tell the client which proof algorithms will do.
        algorithms = " ".join(sorted(resource_server_settings().algorithms))
        params.append(f"algs={_quote(algorithms)}")
        return "DPoP " + ", ".join(params)

    def response(self) -> HttpResponse:
        body = {"detail": self.DESCRIPTIONS.get(self.error or "", "Authentication required.")}
        response = JsonResponse(body, status=self.status)
        response["WWW-Authenticate"] = self.challenge()
        response["Cache-Control"] = "no-store"
        if self.nonce is not None:
            response["DPoP-Nonce"] = self.nonce
        return response


def install(api: NinjaAPI) -> None:
    """Register the handler that turns ``DPoPAuthError`` into a challenge."""

    def handler(request: HttpRequest, exc: DPoPAuthError | type[DPoPAuthError]) -> HttpResponse:
        # Ninja always passes the instance; the union is its signature, not ours.
        if isinstance(exc, DPoPAuthError):
            return exc.response()
        return DPoPAuthError(None, "authentication failed").response()

    api.add_exception_handler(DPoPAuthError, handler)
