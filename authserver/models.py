"""The authorization server's state.

Every credential the server hands out — client secrets, authorization codes,
refresh tokens, PAR request URIs — is stored only as a SHA-256 digest. They
are all 256-bit random values generated here, so a fast hash is the right
tool: there is nothing to brute-force, and a slow KDF would only turn the
token endpoint into a CPU-exhaustion target. A database dump therefore
yields nothing that can be presented back to the server.

Access tokens are JWTs and verify on their own; the ``AccessToken`` row is
kept so introspection and revocation can answer for them.
"""

from __future__ import annotations

import uuid
from typing import ClassVar

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone


class Client(models.Model):
    """A registered OAuth client (RFC 6749 §2)."""

    class ClientType(models.TextChoices):
        # OAuth 2.1 §2.1: a confidential client can hold a secret; a public
        # one (a mobile or browser app) cannot, and is identified only.
        CONFIDENTIAL = "confidential"
        PUBLIC = "public"

    class GrantType(models.TextChoices):
        AUTHORIZATION_CODE = "authorization_code"
        REFRESH_TOKEN = "refresh_token"
        CLIENT_CREDENTIALS = "client_credentials"

    client_id = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=200)
    client_type = models.CharField(max_length=16, choices=ClientType.choices)
    secret_hash = models.CharField(max_length=64, blank=True)
    # Compared byte-for-byte against the request, never pattern-matched
    # (OAuth 2.1 §2.3.1, and the reason open redirectors stopped being fun).
    redirect_uris = models.JSONField(default=list, blank=True)
    grant_types = models.JSONField(default=list)
    scopes = models.JSONField(default=list)
    # A resource server may introspect any token; other clients only their own.
    can_introspect = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self) -> str:
        return f"{self.name} ({self.client_id})"

    @property
    def is_confidential(self) -> bool:
        return self.client_type == self.ClientType.CONFIDENTIAL

    def allows_grant(self, grant_type: str) -> bool:
        return grant_type in self.grant_types


class AuthorizationCode(models.Model):
    """A one-time code from the authorization endpoint (OAuth 2.1 §4.1.2)."""

    code_hash = models.CharField(max_length=64, unique=True)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    redirect_uri = models.TextField()
    scope = models.TextField()
    # Only S256 is accepted, so only the challenge is stored.
    code_challenge = models.CharField(max_length=128)
    # RFC 9449 §10: the key the client committed to at the authorization
    # endpoint, if it did. The token request must then prove that key.
    dpop_jkt = models.CharField(max_length=128, blank=True)
    auth_time = models.DateTimeField()
    expires_at = models.DateTimeField()
    redeemed_at = models.DateTimeField(null=True, blank=True)
    # Set on redemption, so a second redemption can revoke what the first
    # one issued (OAuth 2.1 §4.1.3).
    family = models.OneToOneField(
        "TokenFamily", null=True, blank=True, on_delete=models.SET_NULL, related_name="code"
    )

    def __str__(self) -> str:
        return f"code for {self.client.client_id}"


class TokenFamily(models.Model):
    """Every token descended from one grant.

    A refresh token is rotated on each use, and the whole lineage shares a
    family. Presenting a rotated-away token means two parties hold the same
    lineage, and the server cannot tell which is legitimate — so the family
    is revoked and both must re-authenticate (OAuth 2.1 §4.3.1,
    RFC 9700 §4.14.2).
    """

    class RevocationReason(models.TextChoices):
        REFRESH_TOKEN_REUSE = "refresh_token_reuse"
        AUTHORIZATION_CODE_REUSE = "authorization_code_reuse"
        CLIENT_REQUEST = "client_request"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE
    )
    scope = models.TextField()
    auth_time = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    # An absolute ceiling: rotation extends a refresh token, never the family.
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=32, choices=RevocationReason.choices, blank=True)

    class Meta:
        verbose_name_plural = "token families"

    def __str__(self) -> str:
        return f"family {self.id}"

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.expires_at > timezone.now()


class RefreshToken(models.Model):
    """One generation of a rotating refresh token."""

    token_hash = models.CharField(max_length=64, unique=True)
    family = models.ForeignKey(TokenFamily, on_delete=models.CASCADE, related_name="refresh_tokens")
    scope = models.TextField()
    # RFC 9449 §5: a public client's refresh token is bound to its DPoP key.
    # A confidential client's is bound by client authentication instead, and
    # this stays blank.
    jkt = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    rotated_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"refresh token in {self.family_id}"


class AccessToken(models.Model):
    """The server's record of an issued JWT access token.

    Resource servers validate the JWT locally and never consult this table;
    it exists so introspection (RFC 7662) and revocation (RFC 7009) can give a
    truthful answer before the token's short lifetime runs out.
    """

    jti = models.CharField(max_length=64, unique=True)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    family = models.ForeignKey(
        TokenFamily, null=True, blank=True, on_delete=models.CASCADE, related_name="access_tokens"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE
    )
    subject = models.CharField(max_length=255)
    audience = models.CharField(max_length=255)
    scope = models.TextField()
    jkt = models.CharField(max_length=128)
    issued_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"access token {self.jti}"


class SigningKey(models.Model):
    """A key that signs access tokens, moving through a fixed lifecycle.

    ``pending``  published in the JWKS but not yet signing, so resource
                 servers have cached it before the first token carries its kid.
    ``active``   signs new tokens. Exactly one at a time.
    ``retired``  no longer signs, still published until every token it signed
                 has expired.

    The private half is stored encrypted; see ``authserver.keys``.
    """

    class State(models.TextChoices):
        PENDING = "pending"
        ACTIVE = "active"
        RETIRED = "retired"

    kid = models.CharField(max_length=64, unique=True)
    algorithm = models.CharField(max_length=16)
    state = models.CharField(max_length=16, choices=State.choices)
    public_jwk = models.JSONField()
    private_key_encrypted = models.BinaryField()
    created_at = models.DateTimeField(default=timezone.now)
    activated_at = models.DateTimeField(null=True, blank=True)
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints: ClassVar = [
            models.UniqueConstraint(
                fields=["state"], condition=Q(state="active"), name="one_active_signing_key"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.kid} ({self.state})"


class PushedAuthorizationRequest(models.Model):
    """An authorization request pushed ahead of time (RFC 9126)."""

    request_uri_hash = models.CharField(max_length=64, unique=True)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    parameters = models.JSONField()
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"PAR for {self.client.client_id}"
