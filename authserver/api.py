"""The authorization server's HTTP endpoints, other than the browser-facing ones."""

from django.http import HttpRequest, JsonResponse
from ninja import NinjaAPI

from authserver.clients import authenticate_client
from authserver.errors import OAuthError
from authserver.grants import GRANT_HANDLERS
from authserver.http import FORM_CONTENT_TYPE, form_params, form_schema, no_store
from authserver.introspection import introspect, revoke
from authserver.keys import published_jwks
from authserver.metadata import (
    INTROSPECTION_PATH,
    JWKS_PATH,
    METADATA_PATH,
    PAR_PATH,
    REVOCATION_PATH,
    TOKEN_PATH,
    server_metadata,
)
from authserver.par import push
from authserver.proofs import nonce_headers, optional_proof, require_proof
from authserver.ratelimit import enforce_token_rate_limit

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
        enforce_token_rate_limit(request)
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


def _token_param(params: dict[str, str]) -> str:
    token = params.get("token")
    if not token:
        raise OAuthError("invalid_request", "token is required")
    return token


@api.post(
    INTROSPECTION_PATH,
    tags=["oauth"],
    summary="Token introspection (RFC 7662)",
    description=(
        "Confidential clients only. A client may introspect its own tokens; a client registered "
        "with `can_introspect` (a resource server) may introspect any. Everything else, "
        'including unknown tokens, answers `{"active": false}`.'
    ),
    openapi_extra=form_schema(
        {
            "token": "The token to describe",
            "token_type_hint": "access_token or refresh_token (optional; never needed)",
            "client_id": "client_secret_post",
            "client_secret": "client_secret_post",
        },
        required=["token"],
    ),
)
def introspection(request: HttpRequest) -> JsonResponse:
    try:
        params = form_params(request)
        client = authenticate_client(request, params)
        if not client.is_confidential:
            # RFC 7662 §2.1: the endpoint requires authorization, and a public
            # client has nothing to authenticate with.
            raise OAuthError("invalid_client", "public clients may not introspect", status=401)
        body = introspect(client, _token_param(params))
    except OAuthError as exc:
        return exc.response()
    return no_store(JsonResponse(body))


@api.post(
    REVOCATION_PATH,
    tags=["oauth"],
    summary="Token revocation (RFC 7009)",
    description=(
        "Revoking a refresh token revokes every token of its grant. Unknown tokens and tokens "
        "of other clients succeed without effect (RFC 7009 §2.2)."
    ),
    openapi_extra=form_schema(
        {
            "token": "The token to revoke",
            "token_type_hint": "access_token or refresh_token (optional; never needed)",
            "client_id": "public clients, and client_secret_post",
            "client_secret": "client_secret_post",
        },
        required=["token"],
    ),
)
def revocation(request: HttpRequest) -> JsonResponse:
    try:
        params = form_params(request)
        client = authenticate_client(request, params)
        revoke(client, _token_param(params))
    except OAuthError as exc:
        return exc.response()
    return no_store(JsonResponse({}))


@api.post(
    PAR_PATH,
    tags=["oauth"],
    summary="Pushed authorization request (RFC 9126)",
    description=(
        "Takes the parameters of an authorization request, authenticated as at the token "
        "endpoint, and answers `201` with a one-time `request_uri` for the authorization "
        "endpoint. A `DPoP` proof here binds the eventual code to its key (RFC 9449 §10.1)."
    ),
    openapi_extra=form_schema(
        {
            "response_type": "code",
            "redirect_uri": "One of the client's registered redirect URIs",
            "scope": "Space-separated scopes",
            "state": "Opaque value returned with the response",
            "code_challenge": "PKCE S256 challenge",
            "code_challenge_method": "S256",
            "dpop_jkt": "Optional: thumbprint of the key the code will be bound to",
            "client_id": "The client",
            "client_secret": "client_secret_post",
        },
        required=["response_type", "redirect_uri", "scope", "code_challenge"],
    ),
)
def pushed_authorization_request(request: HttpRequest) -> JsonResponse:
    try:
        if request.content_type != FORM_CONTENT_TYPE:
            raise OAuthError("invalid_request", f"content type must be {FORM_CONTENT_TYPE}")
        lists = dict(request.POST.lists())
        params = {name: values[-1] for name, values in lists.items()}
        client = authenticate_client(request, params)
        lists.pop("client_secret", None)
        proof = optional_proof(request, PAR_PATH)
        request_uri, expires_in = push(client, lists, proof)
    except OAuthError as exc:
        return no_store(exc.response(), nonce_headers())
    response = JsonResponse({"request_uri": request_uri, "expires_in": expires_in}, status=201)
    return no_store(response, nonce_headers())
