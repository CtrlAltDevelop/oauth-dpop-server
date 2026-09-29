"""Token endpoint grant handlers (OAuth 2.1 §4).

Each handler receives an authenticated client, the request parameters and a
verified DPoP proof, and returns a ``TokenResponse`` or raises ``OAuthError``.

Where a failure must leave a trace — a burned authorization code, a revoked
family — the transactional part *returns* the error rather than raising it,
and the handler raises once the transaction has committed. Raising inside it
would roll the evidence back.
"""

from collections.abc import Callable

from django.db import transaction
from django.utils import timezone

from authserver import pkce
from authserver.credentials import constant_time_equals, digest
from authserver.errors import OAuthError
from authserver.models import AuthorizationCode, Client, RefreshToken, TokenFamily
from authserver.scopes import format_scope, parse_scope
from authserver.tokens import (
    TokenResponse,
    issue_access_token,
    issue_refresh_token,
    new_family,
    refresh_binding,
    revoke_family,
)
from dpop import VerifiedProof

GrantHandler = Callable[[Client, dict[str, str], VerifiedProof], TokenResponse]


def _require(params: dict[str, str], *names: str) -> list[str]:
    missing = [name for name in names if not params.get(name)]
    if missing:
        raise OAuthError("invalid_request", f"missing parameters: {missing}")
    return [params[name] for name in names]


def authorization_code(
    client: Client, params: dict[str, str], proof: VerifiedProof
) -> TokenResponse:
    """Redeem an authorization code (OAuth 2.1 §4.1.3)."""
    code, verifier, redirect_uri = _require(params, "code", "code_verifier", "redirect_uri")
    outcome = _redeem_code(client, code, verifier, redirect_uri, proof)
    if isinstance(outcome, OAuthError):
        raise outcome
    return outcome


@transaction.atomic
def _redeem_code(
    client: Client, code: str, verifier: str, redirect_uri: str, proof: VerifiedProof
) -> TokenResponse | OAuthError:
    record = AuthorizationCode.objects.select_for_update().filter(code_hash=digest(code)).first()
    if record is None or record.client_id != client.pk:
        return OAuthError("invalid_grant", "unknown code, or a code issued to another client")

    now = timezone.now()
    if record.redeemed_at is not None:
        # OAuth 2.1 §4.1.3: a code used twice means it leaked. Whatever the
        # first redemption produced is now suspect, so it is revoked.
        if record.family_id is not None:
            revoke_family(record.family_id, TokenFamily.RevocationReason.AUTHORIZATION_CODE_REUSE)
        return OAuthError("invalid_grant", "authorization code reused")

    # Burned on first contact, whether or not the rest checks out: a code
    # gets exactly one attempt.
    record.redeemed_at = now
    record.save(update_fields=["redeemed_at"])
    if record.expires_at <= now:
        return OAuthError("invalid_grant", "authorization code expired")
    if not constant_time_equals(redirect_uri, record.redirect_uri):
        return OAuthError("invalid_grant", "redirect_uri differs from the authorization request")
    if not pkce.verify(verifier, record.code_challenge):
        return OAuthError("invalid_grant", "code_verifier does not match code_challenge")
    if record.dpop_jkt and not constant_time_equals(record.dpop_jkt, proof.jkt):
        # RFC 9449 §10: the proof must come from the key the client committed
        # to with dpop_jkt at the authorization endpoint.
        return OAuthError("invalid_dpop_proof", "proof key differs from dpop_jkt")

    scope = parse_scope(record.scope)
    family = new_family(client, user_id=record.user_id, scope=scope, auth_time=record.auth_time)
    record.family = family
    record.save(update_fields=["family"])
    access_token, expires_in = issue_access_token(
        client=client, scope=scope, jkt=proof.jkt, family=family
    )
    refresh_token = None
    if client.allows_grant(Client.GrantType.REFRESH_TOKEN):
        refresh_token = issue_refresh_token(family, scope, refresh_binding(client, proof.jkt))
    return TokenResponse(access_token, expires_in, record.scope, refresh_token)


def refresh_token(client: Client, params: dict[str, str], proof: VerifiedProof) -> TokenResponse:
    """Rotate a refresh token (OAuth 2.1 §4.3), detecting reuse."""
    (token,) = _require(params, "refresh_token")
    outcome = _rotate_refresh_token(client, token, params.get("scope"), proof)
    if isinstance(outcome, OAuthError):
        raise outcome
    return outcome


@transaction.atomic
def _rotate_refresh_token(
    client: Client, token: str, requested_scope: str | None, proof: VerifiedProof
) -> TokenResponse | OAuthError:
    record = RefreshToken.objects.select_for_update().filter(token_hash=digest(token)).first()
    if record is None:
        return OAuthError("invalid_grant", "unknown refresh token")
    # Locked too, so a reuse-triggered revocation and a legitimate rotation in
    # the same family cannot interleave.
    family = TokenFamily.objects.select_for_update().get(pk=record.family_id)
    if family.client_id != client.pk:
        return OAuthError("invalid_grant", "refresh token issued to another client")
    if family.revoked_at is not None:
        return OAuthError("invalid_grant", "token family is revoked")
    if record.rotated_at is not None:
        # OAuth 2.1 §4.3.1 / RFC 9700 §4.14.2: a rotated-away token came back.
        # Either the client or an attacker holds a copy, and there is no telling
        # which, so neither keeps the lineage.
        revoke_family(family.id, TokenFamily.RevocationReason.REFRESH_TOKEN_REUSE)
        return OAuthError("invalid_grant", "refresh token reused; family revoked")

    now = timezone.now()
    if record.expires_at <= now or family.expires_at <= now:
        return OAuthError("invalid_grant", "refresh token expired")
    if record.jkt and not constant_time_equals(record.jkt, proof.jkt):
        # RFC 9449 §5: a key-bound refresh token needs a proof from that key.
        # Refused without rotating: a thief holding the token but not the key
        # must not be able to knock the real client off its lineage.
        return OAuthError("invalid_dpop_proof", "proof key differs from the refresh token's key")

    granted = parse_scope(record.scope)
    scope = granted
    if requested_scope is not None:
        try:
            scope = parse_scope(requested_scope)
        except ValueError:
            return OAuthError("invalid_scope", "scope is malformed")
        # RFC 6749 §6: never more than was originally granted.
        if not set(scope) <= set(granted):
            return OAuthError("invalid_scope", "scope exceeds the original grant")

    record.rotated_at = now
    record.save(update_fields=["rotated_at"])
    access_token, expires_in = issue_access_token(
        client=client, scope=scope, jkt=proof.jkt, family=family
    )
    # RFC 6749 §6: the new refresh token carries the same scope as the old one,
    # whatever this particular access token was narrowed to.
    new_refresh = issue_refresh_token(family, granted, refresh_binding(client, proof.jkt))
    return TokenResponse(access_token, expires_in, format_scope(scope), new_refresh)


def client_credentials(
    client: Client, params: dict[str, str], proof: VerifiedProof
) -> TokenResponse:
    """A client acting on its own behalf (OAuth 2.1 §4.2).

    Confidential clients only: the grant *is* the client's credentials, so a
    public client would be authenticating nothing. No refresh token either —
    the client can simply ask again (OAuth 2.1 §4.2.3).
    """
    if not client.is_confidential:
        raise OAuthError("unauthorized_client", "client_credentials needs a confidential client")
    requested = params.get("scope")
    if requested is None:
        scope = list(client.scopes)
    else:
        try:
            scope = parse_scope(requested)
        except ValueError:
            raise OAuthError("invalid_scope", "scope is malformed") from None
    if not scope or not set(scope) <= set(client.scopes):
        raise OAuthError("invalid_scope", "scope exceeds the client's registration")
    access_token, expires_in = issue_access_token(client=client, scope=scope, jkt=proof.jkt)
    return TokenResponse(access_token, expires_in, format_scope(scope))


GRANT_HANDLERS: dict[str, GrantHandler] = {
    Client.GrantType.CLIENT_CREDENTIALS: client_credentials,
    Client.GrantType.AUTHORIZATION_CODE: authorization_code,
    Client.GrantType.REFRESH_TOKEN: refresh_token,
}
