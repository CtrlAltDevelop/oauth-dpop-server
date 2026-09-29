from datetime import timedelta

import pytest
from django.conf import settings
from django.test import Client as HttpClient
from django.test import override_settings
from django.utils import timezone
from joserfc import jwt
from joserfc.jwk import KeySet

from authserver.conf import server_settings
from authserver.keys import published_jwks, rotate, sign_jwt
from authserver.models import SigningKey

pytestmark = pytest.mark.django_db


def _kid(token: str) -> str:
    return str(jwt.decode(token, KeySet.import_key_set(published_jwks())).header["kid"])


def test_first_use_bootstraps_an_active_key_and_publishes_a_pending_one() -> None:
    jwks = published_jwks()
    states = sorted(SigningKey.objects.values_list("state", flat=True))
    assert states == ["active", "pending"]
    assert len(jwks["keys"]) == 2


def test_the_jwks_carries_public_keys_only() -> None:
    for jwk in published_jwks()["keys"]:
        assert "d" not in jwk
        assert {"kid", "kty", "crv", "x", "y", "alg", "use"} <= jwk.keys()


def test_private_keys_are_encrypted_at_rest() -> None:
    published_jwks()
    for record in SigningKey.objects.all():
        assert b"PRIVATE KEY" not in bytes(record.private_key_encrypted)


def test_tokens_carry_the_kid_of_the_active_key() -> None:
    token = sign_jwt({"typ": "at+jwt"}, {"sub": "alice"})
    active = SigningKey.objects.get(state="active")
    assert _kid(token) == active.kid


def test_rotation_promotes_the_key_that_was_already_published() -> None:
    published_jwks()
    pending_before = SigningKey.objects.get(state="pending").kid

    result = rotate()

    assert result.activated == pending_before
    assert SigningKey.objects.get(state="active").kid == pending_before
    token = sign_jwt({"typ": "at+jwt"}, {"sub": "alice"})
    assert _kid(token) == pending_before


def test_a_token_signed_before_rotation_still_verifies_after_it() -> None:
    token = sign_jwt({"typ": "at+jwt"}, {"sub": "alice"})
    rotate()
    decoded = jwt.decode(token, KeySet.import_key_set(published_jwks()))
    assert decoded.claims["sub"] == "alice"


def test_the_jwks_holds_retired_active_and_pending_keys_during_overlap() -> None:
    published_jwks()
    rotate()
    states = sorted(SigningKey.objects.values_list("state", flat=True))
    assert states == ["active", "pending", "retired"]
    assert len(published_jwks()["keys"]) == 3


def test_a_retired_key_is_dropped_once_its_tokens_can_no_longer_be_valid() -> None:
    published_jwks()
    first_active = SigningKey.objects.get(state="active").kid
    rotate()
    later = timezone.now() + timedelta(days=1)

    result = rotate(now=later)

    assert first_active in result.deleted
    assert first_active not in {k["kid"] for k in published_jwks()["keys"]}


def test_rotating_with_no_keys_at_all_still_leaves_one_active() -> None:
    result = rotate()
    assert result.retired is None
    assert SigningKey.objects.filter(state="active").count() == 1


def test_the_jwks_endpoint_is_cacheable_json(client: HttpClient) -> None:
    response = client.get("/oauth/jwks")
    assert response.status_code == 200
    assert "max-age" in response["Cache-Control"]
    assert len(response.json()["keys"]) == 2


@override_settings(OAUTH_KEY_ENCRYPTION_SECRET="")
def test_an_empty_encryption_secret_falls_back_rather_than_encrypting_under_nothing() -> None:
    assert server_settings().key_encryption_secret == settings.SECRET_KEY
