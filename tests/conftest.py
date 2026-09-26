from collections.abc import Iterator

import fakeredis
import pytest


@pytest.fixture
def fake_redis() -> Iterator[fakeredis.FakeRedis]:
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server)
    yield client
    client.flushall()
