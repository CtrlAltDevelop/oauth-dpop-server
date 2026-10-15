"""Expired-row purging, JWKS refresh failures and strict input shapes."""

from datetime import timedelta
from typing import Any

import pytest
from django.contrib.auth.models import User
from django.core.management import call_command
from django.utils import timezone

from authserver import pkce
from authserver.models import (
    AccessToken,
    AuthorizationCode,
    Client,
    PushedAuthorizationRequest,
    RefreshToken,
    TokenFamily,
)
from authserver.scopes import parse_scope
from authserver.tokens import issue_access_token, issue_refresh_token, new_family
from ninja_dpop import jwks


@pytest.mark.django_db
def test_purge_deletes_expired_rows_and_keeps_live_ones(public_client: Client, user: User) -> None:
    now = timezone.now()
    past = now - timedelta(days=1)
    live = new_family(public_client, user_id=user.pk, scope=["profile"], auth_time=now)
    dead = new_family(public_client, user_id=user.pk, scope=["profile"], auth_time=now)
    issue_refresh_token(live, ["profile"], None)
    issue_refresh_token(dead, ["profile"], None)
    issue_access_token(client=public_client, scope=["profile"], jkt="k", family=dead)
    issue_access_token(client=public_client, scope=["profile"], jkt="k", family=live)
    TokenFamily.objects.filter(pk=dead.pk).update(expires_at=past)
    code = {"client": public_client, "user": user, "redirect_uri": "x", "scope": "profile"}
    code |= {"code_challenge": "c", "auth_time": now, "expires_at": past}
    # Expired, but its family lives: kept so a replay can still revoke it.
    AuthorizationCode.objects.create(code_hash="a", family=live, **code)
    AuthorizationCode.objects.create(code_hash="b", **code)
    PushedAuthorizationRequest.objects.create(
        request_uri_hash="p", client=public_client, parameters={}, expires_at=past
    )

    call_command("purge_expired")

    assert list(TokenFamily.objects.all()) == [live]
    assert RefreshToken.objects.get().family == live
    assert AccessToken.objects.get().family == live
    assert AuthorizationCode.objects.get().code_hash == "a"
    assert not PushedAuthorizationRequest.objects.exists()


def test_a_failed_jwks_refresh_keeps_the_cached_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    jwks.clear_cache()
    calls: list[str] = []

    def load(source: str) -> dict[str, Any]:
        calls.append(source)
        if len(calls) > 1:
            raise OSError("issuer is down")
        return {"keys": [{"kty": "oct", "k": "c2VjcmV0c2VjcmV0c2VjcmV0", "kid": "one"}]}

    monkeypatch.setattr(jwks, "_load", load)
    first = jwks.key_set("issuer", max_age=0)
    # Stale, the refetch fails, and the cached keys are served instead of an error.
    assert jwks.key_set("issuer", max_age=0) is first
    # ...and the issuer is left alone for a while rather than hit on every request.
    assert jwks.key_set("issuer", max_age=0) is first
    assert len(calls) == 2
    jwks.clear_cache()


def test_a_trailing_newline_is_not_a_valid_shape() -> None:
    assert not pkce.is_valid_challenge("A" * 43 + "\n")
    with pytest.raises(ValueError, match="malformed"):
        parse_scope("profile\n")
