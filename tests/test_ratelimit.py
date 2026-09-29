"""Rate limiting on the token endpoint."""

import pytest
from django.test import Client as HttpClient
from django.test import override_settings

from authserver.models import Client
from tests.flows import post_token
from tests.proofs import ProofFactory

pytestmark = pytest.mark.django_db


@override_settings(OAUTH_TOKEN_RATE_LIMIT=3, OAUTH_TOKEN_RATE_WINDOW=60)
def test_the_token_endpoint_answers_429_past_the_limit(
    client: HttpClient, public_client: Client
) -> None:
    signer = ProofFactory()
    form = {"grant_type": "authorization_code", "client_id": public_client.client_id}
    for _ in range(3):
        assert post_token(client, form, signer).status_code == 400
    limited = post_token(client, form, signer)
    assert limited.status_code == 429
    assert limited.json()["error"] == "temporarily_unavailable"
    assert 0 < int(limited["Retry-After"]) <= 60


@override_settings(OAUTH_TOKEN_RATE_LIMIT=1, OAUTH_TOKEN_RATE_WINDOW=60)
def test_the_limit_is_per_client_address(client: HttpClient, public_client: Client) -> None:
    signer = ProofFactory()
    form = {"grant_type": "authorization_code", "client_id": public_client.client_id}
    assert post_token(client, form, signer, REMOTE_ADDR="10.0.0.1").status_code == 400
    assert post_token(client, form, signer, REMOTE_ADDR="10.0.0.1").status_code == 429
    assert post_token(client, form, signer, REMOTE_ADDR="10.0.0.2").status_code == 400
