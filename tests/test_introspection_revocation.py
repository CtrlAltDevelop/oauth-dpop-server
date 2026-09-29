"""Token introspection (RFC 7662) and revocation (RFC 7009)."""

from datetime import timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import pytest
from django.contrib.auth.models import User
from django.test import Client as HttpClient
from django.utils import timezone

from authserver.clients import register_client
from authserver.models import AccessToken, Client, TokenFamily
from tests.flows import ISSUER, basic_auth, code_grant_form, obtain_code, post_token
from tests.proofs import ProofFactory

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

pytestmark = pytest.mark.django_db


@pytest.fixture
def signer() -> ProofFactory:
    return ProofFactory()


@pytest.fixture
def resource_server(db: None) -> tuple[Client, str]:
    client, secret = register_client(
        name="Orders API",
        client_type="confidential",
        grant_types=["client_credentials"],
        redirect_uris=[],
        scopes=[],
        can_introspect=True,
    )
    assert secret is not None
    return client, secret


@pytest.fixture
def issued(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> dict[str, Any]:
    """A public client's access and refresh token from the code grant."""
    code = obtain_code(public_client, user)
    body: dict[str, Any] = post_token(client, code_grant_form(public_client, code), signer).json()
    return body


def _post(http: HttpClient, path: str, form: dict[str, str], **headers: Any) -> "TestResponse":
    return http.post(
        path, urlencode(form), content_type="application/x-www-form-urlencoded", **headers
    )


def _introspect(http: HttpClient, caller: tuple[Client, str], token: str) -> dict[str, Any]:
    oauth_client, secret = caller
    response = _post(
        http,
        "/oauth/introspect",
        {"token": token},
        HTTP_AUTHORIZATION=basic_auth(oauth_client.client_id, secret),
    )
    assert response.status_code == 200, response.content
    assert response["Cache-Control"] == "no-store"
    body: dict[str, Any] = response.json()
    return body


# --- Introspection -----------------------------------------------------------


def test_an_active_access_token_is_described_with_its_dpop_binding(
    client: HttpClient,
    resource_server: tuple[Client, str],
    issued: dict[str, Any],
    public_client: Client,
    user: User,
    signer: ProofFactory,
) -> None:
    """RFC 7662 §2.2 with RFC 9449 §6.2: token_type DPoP and cnf.jkt."""
    body = _introspect(client, resource_server, issued["access_token"])
    assert body["active"] is True
    assert body["token_type"] == "DPoP"
    assert body["cnf"] == {"jkt": signer.jkt}
    assert body["client_id"] == public_client.client_id
    assert body["sub"] == str(user.pk)
    assert body["scope"] == "orders:read"
    assert body["iss"] == ISSUER
    assert body["exp"] > body["iat"]


def test_an_active_refresh_token_is_described(
    client: HttpClient, resource_server: tuple[Client, str], issued: dict[str, Any]
) -> None:
    body = _introspect(client, resource_server, issued["refresh_token"])
    assert body["active"] is True
    assert body["token_type"] == "refresh_token"


def test_an_expired_access_token_is_inactive(
    client: HttpClient, resource_server: tuple[Client, str], issued: dict[str, Any]
) -> None:
    AccessToken.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    assert _introspect(client, resource_server, issued["access_token"]) == {"active": False}


def test_a_rotated_refresh_token_is_inactive(
    client: HttpClient,
    resource_server: tuple[Client, str],
    issued: dict[str, Any],
    public_client: Client,
    signer: ProofFactory,
) -> None:
    post_token(
        client,
        {
            "grant_type": "refresh_token",
            "refresh_token": issued["refresh_token"],
            "client_id": public_client.client_id,
        },
        signer,
    )
    assert _introspect(client, resource_server, issued["refresh_token"]) == {"active": False}


@pytest.mark.parametrize("token", ["garbage", "a.b.c", "x" * 43])
def test_an_unknown_token_is_simply_inactive(
    client: HttpClient, resource_server: tuple[Client, str], token: str
) -> None:
    """RFC 7662 §2.2: an invalid token is {"active": false}, not an error."""
    assert _introspect(client, resource_server, token) == {"active": False}


def test_a_jwt_from_another_issuer_is_inactive(
    client: HttpClient, resource_server: tuple[Client, str], issued: dict[str, Any]
) -> None:
    head, payload, _ = issued["access_token"].split(".")
    forged = ProofFactory().proof("GET", "https://x.test/").split(".")[2]
    assert _introspect(client, resource_server, f"{head}.{payload}.{forged}") == {"active": False}


def test_a_client_can_introspect_its_own_tokens(
    client: HttpClient,
    confidential_client: tuple[Client, str],
    signer: ProofFactory,
) -> None:
    oauth_client, secret = confidential_client
    token = post_token(
        client,
        {"grant_type": "client_credentials"},
        signer,
        HTTP_AUTHORIZATION=basic_auth(oauth_client.client_id, secret),
    ).json()["access_token"]
    assert _introspect(client, confidential_client, token)["active"] is True


def test_a_client_learns_nothing_about_another_clients_tokens(
    client: HttpClient, confidential_client: tuple[Client, str], issued: dict[str, Any]
) -> None:
    """RFC 7662 §4: without authorization, the answer is indistinguishable from unknown."""
    assert _introspect(client, confidential_client, issued["access_token"]) == {"active": False}
    assert _introspect(client, confidential_client, issued["refresh_token"]) == {"active": False}


def test_introspection_requires_client_authentication(
    client: HttpClient, issued: dict[str, Any]
) -> None:
    """RFC 7662 §2.1: the endpoint MUST require authorization."""
    response = _post(client, "/oauth/introspect", {"token": issued["access_token"]})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_a_public_client_cannot_introspect(
    client: HttpClient, public_client: Client, issued: dict[str, Any]
) -> None:
    response = _post(
        client,
        "/oauth/introspect",
        {"token": issued["access_token"], "client_id": public_client.client_id},
    )
    assert response.status_code == 401


def test_introspection_needs_a_token(
    client: HttpClient, resource_server: tuple[Client, str]
) -> None:
    oauth_client, secret = resource_server
    response = _post(
        client,
        "/oauth/introspect",
        {},
        HTTP_AUTHORIZATION=basic_auth(oauth_client.client_id, secret),
    )
    assert response.json()["error"] == "invalid_request"


# --- Revocation --------------------------------------------------------------


def _revoke(http: HttpClient, client: Client, token: str) -> "TestResponse":
    return _post(http, "/oauth/revoke", {"token": token, "client_id": client.client_id})


def test_revoking_an_access_token_makes_it_inactive(
    client: HttpClient,
    public_client: Client,
    resource_server: tuple[Client, str],
    issued: dict[str, Any],
) -> None:
    """RFC 7009 §2.2: 200 on success, and the token is no longer valid."""
    response = _revoke(client, public_client, issued["access_token"])
    assert response.status_code == 200
    assert _introspect(client, resource_server, issued["access_token"]) == {"active": False}
    # The refresh token of the same grant is untouched.
    assert _introspect(client, resource_server, issued["refresh_token"])["active"] is True


def test_revoking_a_refresh_token_revokes_the_whole_grant(
    client: HttpClient,
    public_client: Client,
    resource_server: tuple[Client, str],
    issued: dict[str, Any],
) -> None:
    """RFC 7009 §2.1: revoking a refresh token SHOULD revoke the grant's access tokens."""
    assert _revoke(client, public_client, issued["refresh_token"]).status_code == 200
    assert TokenFamily.objects.get().revoked_reason == "client_request"
    assert _introspect(client, resource_server, issued["access_token"]) == {"active": False}
    assert _introspect(client, resource_server, issued["refresh_token"]) == {"active": False}


def test_revoking_an_unknown_token_succeeds(client: HttpClient, public_client: Client) -> None:
    """RFC 7009 §2.2: invalid tokens do not cause an error response."""
    assert _revoke(client, public_client, "never-issued").status_code == 200


def test_a_client_cannot_revoke_another_clients_token(
    client: HttpClient,
    confidential_client: tuple[Client, str],
    resource_server: tuple[Client, str],
    issued: dict[str, Any],
) -> None:
    other, secret = confidential_client
    response = _post(
        client,
        "/oauth/revoke",
        {"token": issued["refresh_token"]},
        HTTP_AUTHORIZATION=basic_auth(other.client_id, secret),
    )
    # Answered like an unknown token, so it reveals nothing — but changes nothing.
    assert response.status_code == 200
    assert _introspect(client, resource_server, issued["refresh_token"])["active"] is True


def test_revocation_requires_client_identification(
    client: HttpClient, issued: dict[str, Any]
) -> None:
    """RFC 7009 §2.1: the client authenticates (or, if public, identifies) itself."""
    response = _post(client, "/oauth/revoke", {"token": issued["access_token"]})
    assert response.status_code == 401


def test_metadata_advertises_both_endpoints(client: HttpClient) -> None:
    body = client.get("/.well-known/oauth-authorization-server").json()
    assert body["introspection_endpoint"] == f"{ISSUER}/oauth/introspect"
    assert body["revocation_endpoint"] == f"{ISSUER}/oauth/revoke"
    assert "none" not in body["introspection_endpoint_auth_methods_supported"]
