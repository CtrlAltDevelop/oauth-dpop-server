"""The client credentials grant (OAuth 2.1 §4.2)."""

from typing import TYPE_CHECKING

import pytest
from django.test import Client as HttpClient
from joserfc import jwt
from joserfc.jwk import KeySet

from authserver.keys import published_jwks
from authserver.models import Client
from tests.flows import basic_auth, post_token
from tests.proofs import ProofFactory

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

pytestmark = pytest.mark.django_db


@pytest.fixture
def signer() -> ProofFactory:
    return ProofFactory()


def _request(
    http: HttpClient, client: Client, secret: str, signer: ProofFactory, **form: str
) -> "TestResponse":
    return post_token(
        http,
        {"grant_type": "client_credentials", **form},
        signer,
        HTTP_AUTHORIZATION=basic_auth(client.client_id, secret),
    )


def test_a_service_gets_a_dpop_bound_token_for_itself(
    client: HttpClient, confidential_client: tuple[Client, str], signer: ProofFactory
) -> None:
    """OAuth 2.1 §4.2 with RFC 9449 §5: sub is the client, cnf.jkt the proof key."""
    oauth_client, secret = confidential_client
    response = _request(client, oauth_client, secret, signer, scope="orders:read")
    assert response.status_code == 200, response.content
    body = response.json()
    assert body["token_type"] == "DPoP"
    assert body["scope"] == "orders:read"
    assert "refresh_token" not in body  # OAuth 2.1 §4.2.3
    claims = jwt.decode(body["access_token"], KeySet.import_key_set(published_jwks())).claims
    assert claims["sub"] == oauth_client.client_id
    assert claims["cnf"] == {"jkt": signer.jkt}


def test_without_a_scope_the_registered_scopes_are_granted(
    client: HttpClient, confidential_client: tuple[Client, str], signer: ProofFactory
) -> None:
    oauth_client, secret = confidential_client
    body = _request(client, oauth_client, secret, signer).json()
    assert body["scope"] == "profile orders:read orders:write"


def test_a_scope_beyond_the_registration_is_refused(
    client: HttpClient, confidential_client: tuple[Client, str], signer: ProofFactory
) -> None:
    oauth_client, secret = confidential_client
    response = _request(client, oauth_client, secret, signer, scope="orders:read admin")
    assert response.json()["error"] == "invalid_scope"


def test_a_malformed_scope_is_refused(
    client: HttpClient, confidential_client: tuple[Client, str], signer: ProofFactory
) -> None:
    oauth_client, secret = confidential_client
    response = _request(client, oauth_client, secret, signer, scope='bad"scope')
    assert response.json()["error"] == "invalid_scope"


def test_a_public_client_cannot_use_the_grant(
    client: HttpClient, public_client: Client, signer: ProofFactory
) -> None:
    public_client.grant_types = ["client_credentials"]
    public_client.save()
    response = post_token(
        client,
        {"grant_type": "client_credentials", "client_id": public_client.client_id},
        signer,
    )
    assert response.json()["error"] == "unauthorized_client"


def test_the_grant_needs_a_proof(
    client: HttpClient, confidential_client: tuple[Client, str]
) -> None:
    oauth_client, secret = confidential_client
    response = post_token(
        client,
        {"grant_type": "client_credentials"},
        None,
        HTTP_AUTHORIZATION=basic_auth(oauth_client.client_id, secret),
    )
    assert response.json()["error"] == "invalid_dpop_proof"
