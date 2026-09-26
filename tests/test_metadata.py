import pytest
from django.test import Client as HttpClient

pytestmark = pytest.mark.django_db

ISSUER = "https://auth.example.test"


def test_metadata_is_served_at_the_rfc_8414_well_known_path(client: HttpClient) -> None:
    response = client.get("/.well-known/oauth-authorization-server")
    assert response.status_code == 200
    assert response.json()["issuer"] == ISSUER


def test_metadata_advertises_the_dpop_algorithms_the_server_accepts(client: HttpClient) -> None:
    """RFC 9449 §5.1: dpop_signing_alg_values_supported."""
    algs = client.get("/.well-known/oauth-authorization-server").json()[
        "dpop_signing_alg_values_supported"
    ]
    assert "ES256" in algs
    assert "none" not in algs
    assert not any(alg.startswith("HS") for alg in algs)


def test_metadata_points_at_the_jwks(client: HttpClient) -> None:
    body = client.get("/.well-known/oauth-authorization-server").json()
    assert body["jwks_uri"] == f"{ISSUER}/oauth/jwks"


def test_metadata_advertises_s256_pkce_only(client: HttpClient) -> None:
    """OAuth 2.1 §4.1.1: plain is not offered."""
    body = client.get("/.well-known/oauth-authorization-server").json()
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["response_types_supported"] == ["code"]
    assert body["authorization_endpoint"] == f"{ISSUER}/oauth/authorize"
    assert body["authorization_response_iss_parameter_supported"] is True


def test_metadata_describes_the_token_endpoint(client: HttpClient) -> None:
    body = client.get("/.well-known/oauth-authorization-server").json()
    assert body["token_endpoint"] == f"{ISSUER}/oauth/token"
    assert "authorization_code" in body["grant_types_supported"]
    assert set(body["token_endpoint_auth_methods_supported"]) == {
        "client_secret_basic",
        "client_secret_post",
        "none",
    }
