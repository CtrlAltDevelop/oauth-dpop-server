"""The authorization server's HTTP endpoints, other than the browser-facing ones."""

from django.http import HttpRequest, JsonResponse
from ninja import NinjaAPI

from authserver.clients import authenticate_client
from authserver.errors import OAuthError
from authserver.grants import GRANT_HANDLERS
from authserver.http import form_params, form_schema, no_store
from authserver.keys import published_jwks
from authserver.metadata import JWKS_PATH, METADATA_PATH, TOKEN_PATH, server_metadata
from authserver.proofs import nonce_headers, require_proof

api = NinjaAPI(
    title="OAuth 2.1 Authorization Server",
    version="1",
    urls_namespace="oauth-api",
    docs_url="/oauth/docs",
    openapi_url="/oauth/openapi.json",
)


@api.get(METADATA_PATH, tags=["discovery"], summary="Authorization server metadata (RFC 8414)")
def metadata(request: HttpRequest) -> JsonResponse:
    response = JsonResponse(server_metadata())
    response["Cache-Control"] = "public, max-age=3600"
    return response


@api.get(JWKS_PATH, tags=["discovery"], summary="Access-token signing keys (RFC 7517)")
def jwks(request: HttpRequest) -> JsonResponse:
    response = JsonResponse(published_jwks())
    # Short enough that a pending key reaches every cache long before it signs.
    response["Cache-Control"] = "public, max-age=300"
    return response


@api.post(
    TOKEN_PATH,
    tags=["oauth"],
    summary="Token endpoint (OAuth 2.1 §3.2, RFC 9449 §5)",
    description=(
        "Every request carries a DPoP proof in the `DPoP` header, and every token issued is "
        "bound to the proof's key. When the server requires a nonce, the first request is "
        "answered `400 use_dpop_nonce` with a `DPoP-Nonce` header to retry with."
    ),
    openapi_extra=form_schema(
        {
            "grant_type": "authorization_code, refresh_token or client_credentials",
            "code": "authorization_code: the code from the authorization response",
            "code_verifier": "authorization_code: the PKCE verifier",
            "redirect_uri": "authorization_code: the redirect_uri of the authorization request",
            "refresh_token": "refresh_token: the current refresh token",
            "scope": "refresh_token, client_credentials: optional narrower scope",
            "client_id": "public clients, and client_secret_post",
            "client_secret": "client_secret_post",
        },
        required=["grant_type"],
    ),
)
def token(request: HttpRequest) -> JsonResponse:
    try:
        params = form_params(request)
        client = authenticate_client(request, params)
        grant_type = params.get("grant_type")
        if not grant_type:
            raise OAuthError("invalid_request", "grant_type is required")
        handler = GRANT_HANDLERS.get(grant_type)
        if handler is None:
            raise OAuthError("unsupported_grant_type", f"unsupported grant_type {grant_type!r}")
        if not client.allows_grant(grant_type):
            raise OAuthError("unauthorized_client", f"client may not use {grant_type}")
        # DPoP is not optional here: every token this server issues is bound.
        proof = require_proof(request, TOKEN_PATH)
        result = handler(client, params, proof)
    except OAuthError as exc:
        return no_store(exc.response(), nonce_headers())
    return no_store(JsonResponse(result.as_dict()), nonce_headers())
