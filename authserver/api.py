"""The authorization server's HTTP endpoints, other than the browser-facing ones."""

from django.http import HttpRequest, JsonResponse
from ninja import NinjaAPI

from authserver.keys import published_jwks
from authserver.metadata import JWKS_PATH, METADATA_PATH, server_metadata

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
