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
