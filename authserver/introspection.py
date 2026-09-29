"""Token introspection (RFC 7662) and revocation (RFC 7009)."""

from typing import Any

from django.utils import timezone

from authserver.conf import server_settings
from authserver.lookup import find_access_token, find_refresh_token
from authserver.models import AccessToken, Client, RefreshToken, TokenFamily
from authserver.tokens import revoke_family

INACTIVE: dict[str, Any] = {"active": False}


def _access_token_is_active(record: AccessToken) -> bool:
    if record.revoked_at is not None or record.expires_at <= timezone.now():
        return False
    return record.family is None or record.family.revoked_at is None


def _refresh_token_is_active(record: RefreshToken) -> bool:
    return (
        record.rotated_at is None and record.expires_at > timezone.now() and record.family.is_active
    )


def introspect(caller: Client, token: str) -> dict[str, Any]:
    """RFC 7662 §2.2: what the caller may know about ``token``.

    A client learns about its own tokens; only a client registered as a
    resource server (``can_introspect``) learns about anyone else's. Every
    other case is ``{"active": false}``, indistinguishable from a token that
    never existed, so introspection is not an oracle for token scanning
    (RFC 7662 §4).
    """
    conf = server_settings()
    access = find_access_token(token)
    if access is not None:
        if not (caller.can_introspect or access.client_id == caller.pk):
            return INACTIVE
        if not _access_token_is_active(access):
            return INACTIVE
        return {
            "active": True,
            "scope": access.scope,
            "client_id": access.client.client_id,
            "sub": access.subject,
            "aud": access.audience,
            "iss": conf.issuer,
            "exp": int(access.expires_at.timestamp()),
            "iat": int(access.issued_at.timestamp()),
            "jti": access.jti,
            # RFC 9449 §6.2: say the token is DPoP-bound, and to which key.
            "token_type": "DPoP",
            "cnf": {"jkt": access.jkt},
        }

    refresh = find_refresh_token(token)
    if refresh is None:
        return INACTIVE
    family = refresh.family
    if not (caller.can_introspect or family.client_id == caller.pk):
        return INACTIVE
    if not _refresh_token_is_active(refresh):
        return INACTIVE
    body: dict[str, Any] = {
        "active": True,
        "scope": refresh.scope,
        "client_id": family.client.client_id,
        "iss": conf.issuer,
        "exp": int(refresh.expires_at.timestamp()),
        "iat": int(refresh.created_at.timestamp()),
        "token_type": "refresh_token",
    }
    if family.user_id is not None:
        body["sub"] = str(family.user_id)
    if refresh.jkt:
        body["cnf"] = {"jkt": refresh.jkt}
    return body


def revoke(caller: Client, token: str) -> None:
    """RFC 7009 §2.1: revoke ``token`` if ``caller`` owns it.

    Revoking a refresh token revokes its family: every refresh and access
    token descended from the same grant, as §2.1 recommends. Revoking an
    access token revokes that token alone; a resource server validating it
    locally keeps accepting it until it expires, at most one access-token
    lifetime away (see ADR 0001).

    Unknown tokens and tokens belonging to another client succeed silently.
    RFC 7009 §2.2 already treats an invalid token as success, and answering
    another client's token differently would tell the caller it exists.
    """
    access = find_access_token(token)
    if access is not None:
        if access.client_id == caller.pk:
            AccessToken.objects.filter(pk=access.pk, revoked_at__isnull=True).update(
                revoked_at=timezone.now()
            )
        return
    refresh = find_refresh_token(token)
    if refresh is not None and refresh.family.client_id == caller.pk:
        revoke_family(refresh.family_id, TokenFamily.RevocationReason.CLIENT_REQUEST)
