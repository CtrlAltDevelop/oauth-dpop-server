"""Minting access and refresh tokens.

Access tokens are JWTs in the RFC 9068 profile, bound to a DPoP key through
``cnf.jkt`` (RFC 9449 §6.1): a resource server verifies them offline, and a
copy lifted from a log is useless without the private key that goes with it.

Refresh tokens are opaque, stored only as a digest, and belong to a family —
see ``authserver.refresh`` for rotation and reuse detection.
"""

import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.utils import timezone

from authserver.conf import server_settings
from authserver.credentials import digest, new_token
from authserver.keys import sign_jwt
from authserver.models import AccessToken, Client, RefreshToken, TokenFamily
from authserver.scopes import format_scope

# RFC 9068 §2.1: the media type that stops an access token being mistaken
# for an ID token or any other JWT signed by the same keys.
ACCESS_TOKEN_TYP = "at+jwt"


@dataclass(frozen=True, slots=True)
class TokenResponse:
    """A successful token response (RFC 6749 §5.1, RFC 9449 §5)."""

    access_token: str
    expires_in: int
    scope: str
    refresh_token: str | None = None

    def as_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "access_token": self.access_token,
            # RFC 9449 §5: a DPoP-bound token says so, and is presented with
            # `Authorization: DPoP`, never `Bearer`.
            "token_type": "DPoP",
            "expires_in": self.expires_in,
            "scope": self.scope,
        }
        if self.refresh_token is not None:
            body["refresh_token"] = self.refresh_token
        return body


def issue_access_token(
    *,
    client: Client,
    scope: list[str],
    jkt: str,
    family: TokenFamily | None = None,
) -> tuple[str, int]:
    """Sign a DPoP-bound access token and record it; return it with its lifetime."""
    conf = server_settings()
    now = timezone.now()
    expires_at = now + timedelta(seconds=conf.access_token_ttl)
    jti = secrets.token_urlsafe(18)
    user = family.user if family is not None else None
    # RFC 9068 §2.2: sub is the resource owner, or the client itself when the
    # client acts on its own behalf. The primary key, not the username, which
    # can change hands.
    subject = str(user.pk) if user is not None else client.client_id

    claims: dict[str, Any] = {
        "iss": conf.issuer,
        "sub": subject,
        "aud": conf.audience,
        "client_id": client.client_id,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": jti,
        "scope": format_scope(scope),
        "cnf": {"jkt": jkt},
    }
    if family is not None and family.auth_time is not None:
        claims["auth_time"] = int(family.auth_time.timestamp())

    token = sign_jwt({"typ": ACCESS_TOKEN_TYP}, claims)
    AccessToken.objects.create(
        jti=jti,
        client=client,
        family=family,
        user=user,
        subject=subject,
        audience=conf.audience,
        scope=format_scope(scope),
        jkt=jkt,
        issued_at=now,
        expires_at=expires_at,
    )
    return token, conf.access_token_ttl


def issue_refresh_token(family: TokenFamily, scope: list[str], jkt: str | None) -> str:
    """Add a new generation to ``family``; return the plaintext token."""
    token = new_token()
    now = timezone.now()
    expires_at = min(
        now + timedelta(seconds=server_settings().refresh_token_ttl), family.expires_at
    )
    RefreshToken.objects.create(
        token_hash=digest(token),
        family=family,
        scope=format_scope(scope),
        jkt=jkt or "",
        created_at=now,
        expires_at=expires_at,
    )
    return token


def refresh_binding(client: Client, jkt: str) -> str | None:
    """The key a refresh token for ``client`` is bound to, if any.

    RFC 9449 §5: a public client's refresh token is bound to its DPoP key,
    since nothing else ties the token to it. A confidential client already
    proves possession through client authentication, and may rotate its DPoP
    key between refreshes.
    """
    return None if client.is_confidential else jkt


def new_family(
    client: Client, *, user_id: int | None, scope: list[str], auth_time: datetime | None
) -> TokenFamily:
    return TokenFamily.objects.create(
        client=client,
        user_id=user_id,
        scope=format_scope(scope),
        auth_time=auth_time,
        expires_at=timezone.now() + timedelta(seconds=server_settings().refresh_family_ttl),
    )


def revoke_family(family_id: uuid.UUID, reason: TokenFamily.RevocationReason) -> None:
    """Revoke a family: its refresh tokens stop working and its access tokens
    introspect as inactive from now on."""
    now = timezone.now()
    TokenFamily.objects.filter(pk=family_id, revoked_at__isnull=True).update(
        revoked_at=now, revoked_reason=reason
    )
    AccessToken.objects.filter(family_id=family_id, revoked_at__isnull=True).update(revoked_at=now)
