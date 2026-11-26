"""Resource indicators (RFC 8707): which resource server a token is for.

The configured ``OAUTH_RESOURCES`` are the only identifiers ever accepted, so
membership is the whole validation. Every token has exactly one audience: a
token good at two resource servers could be replayed at either.
"""

from authserver.conf import server_settings
from authserver.errors import OAuthError
from authserver.models import Client


def known_resources(client: Client, requested: list[str]) -> list[str]:
    """``requested`` without repeats; ``ValueError`` unless the server has
    registered each one and ``client`` may ask for it."""
    registered = set(server_settings().resources)
    if not all(r in registered and client.allows_resource(r) for r in requested):
        raise ValueError("unknown resource")
    return list(dict.fromkeys(requested))


def audience_for(requested: str | None, granted: list[str]) -> str:
    """The audience for a token request (RFC 8707 §2.2).

    ``granted`` is what the authorization covered; empty means the request
    named no resource, which covers the default audience only. A request may
    narrow the grant, never widen it.
    """
    conf = server_settings()
    # Re-checked against the registry: dropping a resource from the settings
    # also stops grants that already covered it.
    allowed = [r for r in granted or [conf.audience] if r in conf.resources]
    if not allowed:
        raise OAuthError("invalid_target", "the grant's resources are no longer registered")
    if requested is None:
        if len(allowed) > 1:
            raise OAuthError("invalid_target", "the grant covers several resources; name one")
        return allowed[0]
    if requested not in allowed:
        raise OAuthError("invalid_target", "resource is outside the grant")
    return requested


def client_credentials_audience(client: Client, requested: str | None) -> str:
    """A client acting for itself may name any resource it is registered for."""
    if requested is None:
        return server_settings().audience
    if requested not in server_settings().resources or not client.allows_resource(requested):
        raise OAuthError("invalid_target", "unknown resource")
    return requested
