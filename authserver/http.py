"""Request parsing and response headers shared by the back-channel endpoints."""

from django.http import HttpRequest, JsonResponse

from authserver.errors import OAuthError

FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


def single_valued(lists: dict[str, list[str]]) -> tuple[dict[str, str], set[str]]:
    """Flatten request parameters, reporting any that were repeated.

    RFC 6749 §3.1: "Request and response parameters MUST NOT be included more
    than once." A repeated parameter is how parameter-pollution attacks make
    two components disagree about what was asked for.
    """
    repeated = {name for name, values in lists.items() if len(values) > 1}
    return {name: values[-1] for name, values in lists.items()}, repeated


def form_params(request: HttpRequest) -> dict[str, str]:
    """The parameters of a back-channel POST (RFC 6749 §3.2)."""
    if request.content_type != FORM_CONTENT_TYPE:
        raise OAuthError("invalid_request", f"content type must be {FORM_CONTENT_TYPE}")
    params, repeated = single_valued(dict(request.POST.lists()))
    if repeated:
        raise OAuthError("invalid_request", f"repeated parameters: {sorted(repeated)}")
    return params


def no_store(response: JsonResponse, extra: dict[str, str] | None = None) -> JsonResponse:
    """Mark a response carrying credentials as uncacheable (RFC 6749 §5.1)."""
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    for name, value in (extra or {}).items():
        response[name] = value
    return response


def form_schema(fields: dict[str, str], required: list[str]) -> dict[str, object]:
    """An OpenAPI request body for a form-encoded endpoint.

    The endpoints read ``request.POST`` themselves — Ninja's form binding
    would quietly keep one of two repeated parameters — so the schema is
    declared by hand for the docs.
    """
    return {
        "requestBody": {
            "required": True,
            "content": {
                FORM_CONTENT_TYPE: {
                    "schema": {
                        "type": "object",
                        "required": required,
                        "properties": {
                            name: {"type": "string", "description": text}
                            for name, text in fields.items()
                        },
                    }
                }
            },
        }
    }
