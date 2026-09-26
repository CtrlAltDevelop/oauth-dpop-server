"""Client registration and authentication."""

import base64
from urllib.parse import unquote_plus, urlsplit

from django.db import transaction
from django.http import HttpRequest

from authserver.conf import server_settings
from authserver.credentials import constant_time_equals, digest, new_token
from authserver.errors import OAuthError
from authserver.models import Client

# RFC 8414 §2 names for the methods `authenticate_client` accepts.
CLIENT_AUTH_METHODS = ("client_secret_basic", "client_secret_post", "none")

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def validate_redirect_uri(uri: str) -> None:
    """Reject a redirect URI that could not be registered under OAuth 2.1 §2.3.

    Accepted: ``https`` anywhere, ``http`` on a loopback host only (RFC 8252
    §7.3), and a private-use scheme in reverse-domain form for native apps
    (RFC 8252 §7.1). Never a fragment (RFC 6749 §3.1.2).
    """
    parts = urlsplit(uri)
    if parts.fragment or "#" in uri:
        raise ValueError(f"redirect URI must not carry a fragment: {uri}")
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS:
        return
    if parts.scheme not in {"http", "https"} and "." in parts.scheme and parts.path:
        return
    raise ValueError(f"redirect URI is not acceptable: {uri}")


@transaction.atomic
def register_client(
    *,
    name: str,
    client_type: str,
    grant_types: list[str],
    redirect_uris: list[str],
    scopes: list[str],
    can_introspect: bool = False,
) -> tuple[Client, str | None]:
    """Create a client, returning it with its plaintext secret (if any).

    The secret exists only in the return value: the database keeps its
    digest, so it cannot be recovered later — only replaced.
    """
    unknown_grants = set(grant_types) - set(Client.GrantType.values)
    if unknown_grants:
        raise ValueError(f"unknown grant types: {sorted(unknown_grants)}")
    confidential = client_type == Client.ClientType.CONFIDENTIAL
    if not confidential and Client.GrantType.CLIENT_CREDENTIALS in grant_types:
        # A public client has no credentials, so the grant would authenticate nothing.
        raise ValueError("a public client cannot use the client_credentials grant")
    if not confidential and can_introspect:
        raise ValueError("a public client cannot be allowed to introspect tokens")
    if Client.GrantType.AUTHORIZATION_CODE in grant_types and not redirect_uris:
        raise ValueError("the authorization_code grant needs at least one redirect URI")
    for uri in redirect_uris:
        validate_redirect_uri(uri)
    unknown_scopes = set(scopes) - set(server_settings().scopes)
    if unknown_scopes:
        raise ValueError(f"unknown scopes: {sorted(unknown_scopes)}")

    secret = new_token() if confidential else None
    client = Client.objects.create(
        client_id=new_token(),
        name=name,
        client_type=client_type,
        secret_hash=digest(secret) if secret else "",
        redirect_uris=list(redirect_uris),
        grant_types=list(dict.fromkeys(grant_types)),
        scopes=list(dict.fromkeys(scopes)),
        can_introspect=can_introspect,
    )
    return client, secret


# Compared against when the client_id is unknown, so a miss costs the same as
# a wrong secret and client_ids cannot be enumerated by timing.
_DUMMY_DIGEST = digest("no-such-client")
_BASIC_CHALLENGE = {"WWW-Authenticate": 'Basic realm="oauth"'}


def _basic_credentials(header: str) -> tuple[str, str] | None:
    """Parse ``Authorization: Basic`` per RFC 6749 §2.3.1.

    Both halves are form-urlencoded before being joined, so they are decoded
    after splitting — a secret containing ':' or '%' survives the trip.
    """
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic":
        return None
    try:
        decoded = base64.b64decode(value.strip(), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise OAuthError(
            "invalid_client", "malformed Basic credentials", status=401, headers=_BASIC_CHALLENGE
        ) from None
    client_id, separator, secret = decoded.partition(":")
    if not separator:
        raise OAuthError(
            "invalid_client", "malformed Basic credentials", status=401, headers=_BASIC_CHALLENGE
        )
    return unquote_plus(client_id), unquote_plus(secret)


def authenticate_client(request: HttpRequest, params: dict[str, str]) -> Client:
    """Identify and authenticate the client calling a back-channel endpoint.

    Supports ``client_secret_basic`` and ``client_secret_post`` for
    confidential clients and ``none`` for public ones (identified, not
    authenticated — PKCE and DPoP carry their security instead). Every failure
    is the same ``invalid_client``; the log says which.
    """
    basic = _basic_credentials(request.META.get("HTTP_AUTHORIZATION", ""))
    body_secret = params.get("client_secret")
    secret: str | None
    if basic is not None:
        client_id, secret = basic
        # RFC 6749 §2.3: one authentication method per request. A client_id
        # repeated in the body is tolerated only if it says the same thing.
        if body_secret is not None or params.get("client_id", client_id) != client_id:
            raise OAuthError("invalid_request", "more than one client authentication method")
    else:
        client_id, secret = params.get("client_id", ""), body_secret
    challenge = _BASIC_CHALLENGE if basic is not None else {}

    client = Client.objects.filter(client_id=client_id).first() if client_id else None
    if secret is None:
        if client is not None and not client.is_confidential:
            return client
        raise OAuthError(
            "invalid_client", "no credentials for a confidential or unknown client", status=401
        )

    expected = client.secret_hash if client is not None and client.is_confidential else ""
    matches = constant_time_equals(digest(secret), expected or _DUMMY_DIGEST)
    if client is None or not expected or not matches:
        raise OAuthError(
            "invalid_client", "unknown client or wrong secret", status=401, headers=challenge
        )
    return client
