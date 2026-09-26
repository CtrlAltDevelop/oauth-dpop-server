"""Refresh token rotation and reuse detection (OAuth 2.1 §4.3, RFC 9700 §4.14,
RFC 9449 §5)."""

from datetime import timedelta
from typing import Any

import pytest
from django.contrib.auth.models import User
from django.test import Client as HttpClient
from django.utils import timezone
from joserfc import jwt
from joserfc.jwk import KeySet

from authserver.keys import published_jwks
from authserver.models import AccessToken, Client, RefreshToken, TokenFamily
from tests.flows import basic_auth, code_grant_form, obtain_code, post_token
from tests.proofs import ProofFactory

pytestmark = pytest.mark.django_db


@pytest.fixture
def signer() -> ProofFactory:
    return ProofFactory()


def _tokens(
    http: HttpClient, client: Client, user: User, signer: ProofFactory, **auth: Any
) -> dict[str, Any]:
    code = obtain_code(client, user, scope="orders:read orders:write")
    form = code_grant_form(client, code)
    if auth:
        del form["client_id"]
    response = post_token(http, form, signer, **auth)
    assert response.status_code == 200, response.content
    body: dict[str, Any] = response.json()
    return body


def _refresh(
    http: HttpClient,
    client: Client,
    token: str,
    signer: ProofFactory,
    **extra: Any,
) -> Any:
    form = {"grant_type": "refresh_token", "refresh_token": token}
    auth = extra.pop("auth", None)
    if auth is None:
        form["client_id"] = client.client_id
    else:
        extra["HTTP_AUTHORIZATION"] = auth
    form.update(extra.pop("form", {}))
    return post_token(http, form, signer, **extra)


def test_a_refresh_rotates_the_token(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """OAuth 2.1 §4.3.1: a new refresh token is issued and the old one retired."""
    first = _tokens(client, public_client, user, signer)
    response = _refresh(client, public_client, first["refresh_token"], signer)

    assert response.status_code == 200, response.content
    body = response.json()
    assert body["token_type"] == "DPoP"
    assert body["refresh_token"] != first["refresh_token"]
    assert body["access_token"] != first["access_token"]
    assert RefreshToken.objects.filter(rotated_at__isnull=False).count() == 1
    assert RefreshToken.objects.filter(rotated_at__isnull=True).count() == 1


def test_a_refreshed_access_token_stays_bound_to_the_proof_key(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    first = _tokens(client, public_client, user, signer)
    body = _refresh(client, public_client, first["refresh_token"], signer).json()
    claims = jwt.decode(body["access_token"], KeySet.import_key_set(published_jwks())).claims
    assert claims["cnf"]["jkt"] == signer.jkt


def test_reusing_a_rotated_refresh_token_revokes_the_whole_family(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9700 §4.14.2: reuse of an invalidated refresh token revokes the grant."""
    first = _tokens(client, public_client, user, signer)
    second = _refresh(client, public_client, first["refresh_token"], signer).json()

    # Someone presents the first token again — the client, or a thief.
    replay = _refresh(client, public_client, first["refresh_token"], signer)
    assert replay.json()["error"] == "invalid_grant"

    family = TokenFamily.objects.get()
    assert family.revoked_reason == "refresh_token_reuse"
    # The newest token in the lineage is dead too, whoever held it.
    newest = _refresh(client, public_client, second["refresh_token"], signer)
    assert newest.json()["error"] == "invalid_grant"
    # And every access token of the family introspects as revoked.
    assert not AccessToken.objects.filter(family=family, revoked_at__isnull=True).exists()


def test_a_public_clients_refresh_needs_a_proof_from_the_bound_key(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §5: the proof must be signed by the key the refresh token is bound to."""
    first = _tokens(client, public_client, user, signer)
    thief = _refresh(client, public_client, first["refresh_token"], ProofFactory())
    assert thief.json()["error"] == "invalid_dpop_proof"
    # The thief's attempt did not rotate anything away from the real client.
    assert _refresh(client, public_client, first["refresh_token"], signer).status_code == 200


def test_a_confidential_client_may_move_to_a_new_key_on_refresh(
    client: HttpClient, confidential_client: tuple[Client, str], user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §5: a confidential client's refresh token is not bound to the key."""
    oauth_client, secret = confidential_client
    auth = basic_auth(oauth_client.client_id, secret)
    first = _tokens(client, oauth_client, user, signer, HTTP_AUTHORIZATION=auth)
    new_key = ProofFactory()
    response = _refresh(client, oauth_client, first["refresh_token"], new_key, auth=auth)
    assert response.status_code == 200, response.content
    claims = jwt.decode(
        response.json()["access_token"], KeySet.import_key_set(published_jwks())
    ).claims
    assert claims["cnf"]["jkt"] == new_key.jkt


def test_a_confidential_client_must_authenticate_to_refresh(
    client: HttpClient, confidential_client: tuple[Client, str], user: User, signer: ProofFactory
) -> None:
    oauth_client, secret = confidential_client
    auth = basic_auth(oauth_client.client_id, secret)
    first = _tokens(client, oauth_client, user, signer, HTTP_AUTHORIZATION=auth)
    response = _refresh(client, oauth_client, first["refresh_token"], signer)
    assert response.status_code == 401


def test_a_refresh_token_is_useless_to_another_client(
    client: HttpClient,
    public_client: Client,
    confidential_client: tuple[Client, str],
    user: User,
    signer: ProofFactory,
) -> None:
    other, secret = confidential_client
    first = _tokens(client, public_client, user, signer)
    response = _refresh(
        client, other, first["refresh_token"], signer, auth=basic_auth(other.client_id, secret)
    )
    assert response.json()["error"] == "invalid_grant"
    assert TokenFamily.objects.get().revoked_at is None


def test_an_expired_refresh_token_is_refused(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    first = _tokens(client, public_client, user, signer)
    RefreshToken.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    assert _refresh(client, public_client, first["refresh_token"], signer).json()["error"] == (
        "invalid_grant"
    )


def test_rotation_never_extends_the_familys_absolute_lifetime(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    first = _tokens(client, public_client, user, signer)
    TokenFamily.objects.update(expires_at=timezone.now() + timedelta(minutes=5))
    body = _refresh(client, public_client, first["refresh_token"], signer).json()
    newest = RefreshToken.objects.get(rotated_at__isnull=True)
    assert newest.expires_at <= TokenFamily.objects.get().expires_at
    TokenFamily.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    assert _refresh(client, public_client, body["refresh_token"], signer).json()["error"] == (
        "invalid_grant"
    )


def test_scope_can_be_narrowed_on_refresh(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 6749 §6: a narrower scope may be requested."""
    first = _tokens(client, public_client, user, signer)
    body = _refresh(
        client, public_client, first["refresh_token"], signer, form={"scope": "orders:read"}
    ).json()
    assert body["scope"] == "orders:read"
    # The refresh token keeps the original grant, so the next refresh can widen again.
    widened = _refresh(
        client,
        public_client,
        body["refresh_token"],
        signer,
        form={"scope": "orders:read orders:write"},
    )
    assert widened.status_code == 200


def test_scope_cannot_be_widened_on_refresh(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 6749 §6: never a scope not originally granted."""
    first = _tokens(client, public_client, user, signer)
    response = _refresh(
        client, public_client, first["refresh_token"], signer, form={"scope": "profile"}
    )
    assert response.json()["error"] == "invalid_scope"
    # A refused scope request does not spend the token.
    assert _refresh(client, public_client, first["refresh_token"], signer).status_code == 200


def test_an_unknown_refresh_token_is_refused(
    client: HttpClient, public_client: Client, signer: ProofFactory
) -> None:
    assert _refresh(client, public_client, "made-up", signer).json()["error"] == "invalid_grant"


def test_a_missing_refresh_token_is_refused(
    client: HttpClient, public_client: Client, signer: ProofFactory
) -> None:
    form = {"grant_type": "refresh_token", "client_id": public_client.client_id}
    assert post_token(client, form, signer).json()["error"] == "invalid_request"


def test_refresh_tokens_are_stored_only_as_digests(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    first = _tokens(client, public_client, user, signer)
    assert not RefreshToken.objects.filter(token_hash=first["refresh_token"]).exists()
