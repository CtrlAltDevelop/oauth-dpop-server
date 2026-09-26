"""Client registration."""

from urllib.parse import urlsplit

from django.db import transaction

from authserver.conf import server_settings
from authserver.credentials import digest, new_token
from authserver.models import Client

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
