import json
from io import StringIO

import pytest
from django.core.management import CommandError, call_command

from authserver.clients import register_client, validate_redirect_uri
from authserver.credentials import digest
from authserver.models import Client

pytestmark = pytest.mark.django_db


def test_a_confidential_client_gets_a_secret_that_is_stored_only_as_a_digest() -> None:
    client, secret = register_client(
        name="Backend",
        client_type="confidential",
        grant_types=["client_credentials"],
        redirect_uris=[],
        scopes=["orders:read"],
    )
    assert secret is not None
    assert client.secret_hash == digest(secret)
    assert secret not in client.secret_hash


def test_a_public_client_has_no_secret() -> None:
    client, secret = register_client(
        name="Mobile app",
        client_type="public",
        grant_types=["authorization_code", "refresh_token"],
        redirect_uris=["com.example.app:/callback"],
        scopes=["profile"],
    )
    assert secret is None
    assert client.secret_hash == ""


def test_a_public_client_cannot_use_client_credentials() -> None:
    with pytest.raises(ValueError, match="client_credentials"):
        register_client(
            name="Mobile app",
            client_type="public",
            grant_types=["client_credentials"],
            redirect_uris=[],
            scopes=[],
        )


def test_unknown_scopes_are_refused() -> None:
    with pytest.raises(ValueError, match="unknown scopes"):
        register_client(
            name="Greedy",
            client_type="confidential",
            grant_types=["client_credentials"],
            redirect_uris=[],
            scopes=["admin"],
        )


@pytest.mark.parametrize(
    "uri",
    [
        "https://app.example.com/callback",
        "http://localhost:8080/callback",
        "http://127.0.0.1/cb",
        "com.example.app:/oauth2redirect",
    ],
)
def test_acceptable_redirect_uris(uri: str) -> None:
    validate_redirect_uri(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "http://app.example.com/callback",  # plain http off loopback
        "https://app.example.com/callback#frag",  # RFC 6749 §3.1.2
        "myapp:/callback",  # private-use scheme without reverse-domain form
        "/relative",
    ],
)
def test_unacceptable_redirect_uris(uri: str) -> None:
    with pytest.raises(ValueError, match="redirect URI"):
        validate_redirect_uri(uri)


def test_the_command_prints_the_secret_once_and_stores_its_digest() -> None:
    out = StringIO()
    call_command(
        "create_client",
        "Service",
        "--grant",
        "client_credentials",
        "--scope",
        "orders:read",
        "--json",
        stdout=out,
    )
    printed = json.loads(out.getvalue())
    client = Client.objects.get(client_id=printed["client_id"])
    assert client.secret_hash == digest(printed["client_secret"])


def test_the_command_reports_invalid_registrations() -> None:
    with pytest.raises(CommandError):
        call_command("create_client", "App", "--grant", "authorization_code", stdout=StringIO())
