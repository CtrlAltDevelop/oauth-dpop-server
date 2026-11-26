"""Resource indicators (RFC 8707): the ``resource`` parameter picks a token's ``aud``."""

from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from django.test import Client as HttpClient
from joserfc import jwt
from joserfc.jwk import KeySet

from authserver import pkce
from authserver.keys import published_jwks
from authserver.models import AccessToken, AuthorizationCode, Client, TokenFamily
from tests.conftest import REDIRECT_URI
from tests.flows import ISSUER, VERIFIER, basic_auth, code_grant_form, obtain_code, post_token
from tests.proofs import ProofFactory

pytestmark = pytest.mark.django_db

DEFAULT = f"{ISSUER}/api"
ORDERS = "https://orders.example.test"
BILLING = "https://billing.example.test"


@pytest.fixture(autouse=True)
def registered_resources(settings: Any) -> None:
    settings.OAUTH_RESOURCES = [ORDERS, BILLING]


@pytest.fixture
def public_client(public_client: Client) -> Client:
    public_client.resources = [ORDERS, BILLING]
    public_client.save()
    return public_client


@pytest.fixture
def confidential_client(confidential_client: tuple[Client, str]) -> tuple[Client, str]:
    client, secret = confidential_client
    client.resources = [ORDERS, BILLING]
    client.save()
    return client, secret


@pytest.fixture
def signer() -> ProofFactory:
    return ProofFactory()


def _aud(body: dict[str, Any]) -> Any:
    return jwt.decode(body["access_token"], KeySet.import_key_set(published_jwks())).claims["aud"]


def _code_tokens(
    http: HttpClient,
    client: Client,
    user: Any,
    signer: ProofFactory,
    *,
    authorize: list[str] | None = None,
    token: dict[str, str] | None = None,
) -> Any:
    extra: dict[str, Any] = {} if authorize is None else {"resource": authorize}
    code = obtain_code(client, user, **extra)
    return post_token(http, code_grant_form(client, code, **(token or {})), signer)


def test_without_a_resource_the_default_audience_is_kept(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory
) -> None:
    body = _code_tokens(client, public_client, user, signer).json()
    assert _aud(body) == DEFAULT


def test_the_authorized_resource_becomes_the_audience(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory
) -> None:
    body = _code_tokens(client, public_client, user, signer, authorize=[ORDERS]).json()
    assert _aud(body) == ORDERS
    assert AccessToken.objects.get().audience == ORDERS
    assert AuthorizationCode.objects.get().resources == [ORDERS]


def test_the_token_request_picks_one_of_several_authorized_resources(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory
) -> None:
    response = _code_tokens(
        client,
        public_client,
        user,
        signer,
        authorize=[ORDERS, BILLING],
        token={"resource": BILLING},
    )
    assert _aud(response.json()) == BILLING


def test_several_authorized_resources_need_the_token_request_to_choose(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory
) -> None:
    """One token, one audience: a token good at two servers is replayable at either."""
    response = _code_tokens(client, public_client, user, signer, authorize=[ORDERS, BILLING])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_target"


def test_a_token_request_cannot_widen_the_authorized_resources(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory
) -> None:
    """RFC 8707 §2.2: the token request's resources must stay within the grant."""
    response = _code_tokens(
        client, public_client, user, signer, authorize=[ORDERS], token={"resource": BILLING}
    )
    assert response.json()["error"] == "invalid_target"


def test_a_grant_without_a_resource_covers_only_the_default_audience(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory
) -> None:
    response = _code_tokens(client, public_client, user, signer, token={"resource": ORDERS})
    assert response.json()["error"] == "invalid_target"


def test_an_unregistered_resource_is_reported_at_the_redirect_uri(
    public_client: Client, user: Any
) -> None:
    browser = HttpClient()
    browser.force_login(user)
    response = browser.get(
        "/oauth/authorize",
        {
            "response_type": "code",
            "client_id": public_client.client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": "orders:read",
            "code_challenge": pkce.s256(VERIFIER),
            "code_challenge_method": "S256",
            "resource": "https://evil.example.test",
        },
    )
    assert response.status_code == 302
    assert parse_qs(urlsplit(response["Location"]).query)["error"] == ["invalid_target"]


def test_a_repeated_resource_at_the_token_endpoint_is_refused(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory
) -> None:
    code = obtain_code(public_client, user, resource=[ORDERS])
    form = (
        urlencode({**code_grant_form(public_client, code)})
        + f"&resource={ORDERS}&resource={ORDERS}"
    )
    response = client.post(
        "/oauth/token",
        form,
        content_type="application/x-www-form-urlencoded",
        HTTP_DPOP=signer.proof("POST", f"{ISSUER}/oauth/token", nonce=_nonce()),
    )
    assert response.json()["error"] == "invalid_request"


def _nonce() -> str:
    from authserver.proofs import nonce_store

    return nonce_store().current()


def test_a_refresh_keeps_to_the_granted_resources(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory
) -> None:
    first = _code_tokens(
        client, public_client, user, signer, authorize=[ORDERS, BILLING], token={"resource": ORDERS}
    ).json()
    assert TokenFamily.objects.get().resources == [ORDERS, BILLING]

    def refresh(token: str, **extra: str) -> Any:
        return post_token(
            client,
            {
                "grant_type": "refresh_token",
                "refresh_token": token,
                "client_id": public_client.client_id,
                **extra,
            },
            signer,
        )

    outside = refresh(first["refresh_token"], resource="https://evil.example.test")
    assert outside.json()["error"] == "invalid_target"
    ambiguous = refresh(first["refresh_token"])
    assert ambiguous.json()["error"] == "invalid_target"
    # Neither failure rotated the token, so it still works.
    narrowed = refresh(first["refresh_token"], resource=BILLING)
    assert _aud(narrowed.json()) == BILLING


def test_client_credentials_can_name_a_registered_resource(
    client: HttpClient, confidential_client: tuple[Client, str], signer: ProofFactory
) -> None:
    oauth_client, secret = confidential_client

    def request(**form: str) -> Any:
        return post_token(
            client,
            {"grant_type": "client_credentials", "scope": "orders:read", **form},
            signer,
            HTTP_AUTHORIZATION=basic_auth(oauth_client.client_id, secret),
        )

    assert _aud(request().json()) == DEFAULT
    assert _aud(request(resource=BILLING).json()) == BILLING
    assert request(resource="https://evil.example.test").json()["error"] == "invalid_target"


def test_a_pushed_request_carries_its_resources(public_client: Client, user: Any) -> None:
    """RFC 9126 with RFC 8707: the pushed ``resource`` ends up on the code."""
    form = urlencode(
        {
            "client_id": public_client.client_id,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": "orders:read",
            "code_challenge": pkce.s256(VERIFIER),
            "code_challenge_method": "S256",
            "resource": BILLING,
        }
    )
    pushed = HttpClient().post("/oauth/par", form, content_type="application/x-www-form-urlencoded")
    assert pushed.status_code == 201, pushed.content
    browser = HttpClient()
    browser.force_login(user)
    consent = browser.get(
        "/oauth/authorize",
        {"client_id": public_client.client_id, "request_uri": pushed.json()["request_uri"]},
    )["Location"]
    browser.post(consent, {"decision": "approve"})
    assert AuthorizationCode.objects.get().resources == [BILLING]


def _refresh(
    http: HttpClient, client: Client, token: str, signer: ProofFactory, **extra: str
) -> Any:
    form = {"grant_type": "refresh_token", "refresh_token": token, "client_id": client.client_id}
    return post_token(http, {**form, **extra}, signer)


def test_a_legacy_family_covers_only_the_default_audience(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory
) -> None:
    """Families from before migration 0002 have no resources recorded."""
    first = _code_tokens(client, public_client, user, signer).json()
    assert TokenFamily.objects.get().resources == []
    assert (
        _refresh(client, public_client, first["refresh_token"], signer, resource=ORDERS).json()[
            "error"
        ]
        == "invalid_target"
    )
    assert _aud(_refresh(client, public_client, first["refresh_token"], signer).json()) == DEFAULT


def test_a_resource_removed_from_the_registry_stops_refreshing(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory, settings: Any
) -> None:
    first = _code_tokens(client, public_client, user, signer, authorize=[ORDERS]).json()
    settings.OAUTH_RESOURCES = [BILLING]
    response = _refresh(client, public_client, first["refresh_token"], signer)
    assert response.json()["error"] == "invalid_target"


def test_a_bad_resource_burns_the_code(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory
) -> None:
    """A code gets one attempt, whatever fails."""
    code = obtain_code(public_client, user, resource=[ORDERS])
    bad = post_token(client, code_grant_form(public_client, code, resource=BILLING), signer)
    assert bad.json()["error"] == "invalid_target"
    again = post_token(client, code_grant_form(public_client, code), signer)
    assert again.json()["error"] == "invalid_grant"


def test_an_empty_resource_is_refused(
    client: HttpClient, public_client: Client, user: Any, signer: ProofFactory
) -> None:
    response = _code_tokens(client, public_client, user, signer, token={"resource": ""})
    assert response.json()["error"] == "invalid_target"


def test_a_client_may_only_request_its_own_resources(
    public_client: Client, confidential_client: tuple[Client, str], user: Any, signer: ProofFactory
) -> None:
    public_client.resources = [ORDERS]
    public_client.save()
    browser = HttpClient()
    browser.force_login(user)
    params = {
        "response_type": "code",
        "client_id": public_client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "orders:read",
        "code_challenge": pkce.s256(VERIFIER),
        "code_challenge_method": "S256",
    }
    refused = browser.get("/oauth/authorize", {**params, "resource": BILLING})
    assert parse_qs(urlsplit(refused["Location"]).query)["error"] == ["invalid_target"]
    assert browser.get("/oauth/authorize", {**params, "resource": ORDERS}).status_code == 302

    service, secret = confidential_client
    service.resources = []
    service.save()
    response = post_token(
        HttpClient(),
        {"grant_type": "client_credentials", "scope": "orders:read", "resource": BILLING},
        signer,
        HTTP_AUTHORIZATION=basic_auth(service.client_id, secret),
    )
    assert response.json()["error"] == "invalid_target"


def test_registration_rejects_an_unregistered_resource(db: None) -> None:
    from authserver.clients import register_client

    with pytest.raises(ValueError, match="unregistered resources"):
        register_client(
            name="x",
            client_type="confidential",
            grant_types=["client_credentials"],
            redirect_uris=[],
            scopes=["profile"],
            resources=["https://evil.example.test"],
        )


def test_the_consent_page_names_the_resources(public_client: Client, user: Any) -> None:
    browser = HttpClient()
    browser.force_login(user)
    consent = browser.get(
        "/oauth/authorize",
        {
            "response_type": "code",
            "client_id": public_client.client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": "orders:read",
            "code_challenge": pkce.s256(VERIFIER),
            "code_challenge_method": "S256",
            "resource": [ORDERS, BILLING],
        },
    )["Location"]
    page = browser.get(consent).content.decode()
    assert ORDERS in page
    assert BILLING in page
