from django.contrib import admin

from authserver.models import AccessToken, Client, SigningKey, TokenFamily


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin[Client]):
    list_display = ("name", "client_id", "client_type", "created_at")
    # Secrets are issued once by `manage.py create_client` and never shown again.
    readonly_fields = ("client_id", "secret_hash", "created_at")


@admin.register(TokenFamily)
class TokenFamilyAdmin(admin.ModelAdmin[TokenFamily]):
    list_display = ("id", "client", "user", "created_at", "revoked_at", "revoked_reason")
    list_filter = ("revoked_reason",)
    readonly_fields = ("id", "client", "user", "scope", "auth_time", "created_at", "expires_at")


@admin.register(AccessToken)
class AccessTokenAdmin(admin.ModelAdmin[AccessToken]):
    list_display = ("jti", "client", "subject", "issued_at", "expires_at", "revoked_at")
    readonly_fields = (
        "jti",
        "client",
        "family",
        "user",
        "subject",
        "audience",
        "scope",
        "jkt",
        "issued_at",
        "expires_at",
    )


@admin.register(SigningKey)
class SigningKeyAdmin(admin.ModelAdmin[SigningKey]):
    list_display = ("kid", "algorithm", "state", "created_at", "activated_at", "retired_at")
    # Keys change state only through `manage.py rotate_signing_keys`.
    exclude = ("private_key_encrypted",)
    readonly_fields = (
        "kid",
        "algorithm",
        "state",
        "public_jwk",
        "created_at",
        "activated_at",
        "retired_at",
    )
