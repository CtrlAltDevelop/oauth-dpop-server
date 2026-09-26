from collections.abc import Iterator

import fakeredis
import pytest
from django.contrib.auth.models import User

from authserver.clients import register_client
from authserver.models import Client
from authserver.redis import use_redis

REDIRECT_URI = "https://app.example.test/callback"


@pytest.fixture(autouse=True)
def fake_redis() -> Iterator[fakeredis.FakeRedis]:
    """Every test gets an empty Redis of its own, wired into the server."""
    client = fakeredis.FakeRedis(server=fakeredis.FakeServer())
    use_redis(client)
    yield client
    use_redis(None)


@pytest.fixture
def user(db: None) -> User:
    return User.objects.create_user("alice", password="correct horse battery staple")


@pytest.fixture
def public_client(db: None) -> Client:
    client, _ = register_client(
        name="Mobile app",
        client_type="public",
        grant_types=["authorization_code", "refresh_token"],
        redirect_uris=[REDIRECT_URI],
        scopes=["profile", "orders:read", "orders:write"],
    )
    return client


@pytest.fixture
def confidential_client(db: None) -> tuple[Client, str]:
    client, secret = register_client(
        name="Web backend",
        client_type="confidential",
        grant_types=["authorization_code", "refresh_token", "client_credentials"],
        redirect_uris=[REDIRECT_URI],
        scopes=["profile", "orders:read", "orders:write"],
    )
    assert secret is not None
    return client, secret
