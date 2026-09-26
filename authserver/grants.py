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
from authserver.models import AuthorizationCode, Client, TokenFamily
from authserver.scopes import parse_scope
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


GRANT_HANDLERS: dict[str, GrantHandler] = {
    Client.GrantType.AUTHORIZATION_CODE: authorization_code,
}
