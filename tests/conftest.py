from collections.abc import Iterator

import fakeredis
import pytest
from django.contrib.auth.models import User

from authserver.clients import register_client
from authserver.models import Client

REDIRECT_URI = "https://app.example.test/callback"


@pytest.fixture
def fake_redis() -> Iterator[fakeredis.FakeRedis]:
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server)
    yield client
    client.flushall()


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
