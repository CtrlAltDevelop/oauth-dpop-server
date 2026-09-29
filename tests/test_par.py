"""Pushed Authorization Requests (RFC 9126), with DPoP (RFC 9449 §10.1)."""

from datetime import timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from django.contrib.auth.models import User
from django.test import Client as HttpClient
from django.utils import timezone

from authserver import pkce
from authserver.models import AuthorizationCode, Client, PushedAuthorizationRequest
from authserver.proofs import nonce_store
from tests.conftest import REDIRECT_URI
from tests.flows import ISSUER, VERIFIER, basic_auth, code_grant_form, post_token
from tests.proofs import ProofFactory

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

pytestmark = pytest.mark.django_db

PAR_URL = f"{ISSUER}/oauth/par"


def _params(**overrides: str) -> dict[str, str]:
    params = {
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "orders:read",
        "state": "abc",
        "code_challenge": pkce.s256(VERIFIER),
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return params


def _push(http: HttpClient, form: dict[str, str], **headers: Any) -> "TestResponse":
    return http.post(
        "/oauth/par", urlencode(form), content_type="application/x-www-form-urlencoded", **headers
    )


def _authorize(user: User, client_id: str, request_uri: str) -> "TestResponse":
    browser = HttpClient()
    browser.force_login(user)
    response = browser.get("/oauth/authorize", {"client_id": client_id, "request_uri": request_uri})
    if response.status_code != 302:
        return response
    return browser.post(response["Location"], {"decision": "approve"})


def test_a_pushed_request_gets_a_one_time_request_uri(
    client: HttpClient, public_client: Client
) -> None:
    """RFC 9126 §2.2: 201 with request_uri and expires_in."""
    response = _push(client, {"client_id": public_client.client_id, **_params()})
    assert response.status_code == 201, response.content
    body = response.json()
    assert body["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")
    assert body["expires_in"] == 60
    assert response["Cache-Control"] == "no-store"


def test_the_request_uri_completes_the_flow(
    client: HttpClient, public_client: Client, user: User
) -> None:
    """RFC 9126 §4: the authorization endpoint takes client_id and request_uri only."""
    request_uri = _push(client, {"client_id": public_client.client_id, **_params()}).json()[
        "request_uri"
    ]
    callback = _authorize(user, public_client.client_id, request_uri)["Location"]
    query = parse_qs(urlsplit(callback).query)
    assert query["state"] == ["abc"]
    signer = ProofFactory()
    token = post_token(client, code_grant_form(public_client, query["code"][0]), signer)
    assert token.status_code == 200, token.content


def test_a_request_uri_works_once(client: HttpClient, public_client: Client, user: User) -> None:
    """RFC 9126 §4: request_uri values are one-time use."""
    request_uri = _push(client, {"client_id": public_client.client_id, **_params()}).json()[
        "request_uri"
    ]
    _authorize(user, public_client.client_id, request_uri)
    assert _authorize(user, public_client.client_id, request_uri).status_code == 400


def test_a_request_uri_is_bound_to_the_client_that_pushed_it(
    client: HttpClient,
    public_client: Client,
    confidential_client: tuple[Client, str],
    user: User,
) -> None:
    request_uri = _push(client, {"client_id": public_client.client_id, **_params()}).json()[
        "request_uri"
    ]
    other, _ = confidential_client
    assert _authorize(user, other.client_id, request_uri).status_code == 400


def test_an_expired_request_uri_is_refused(
    client: HttpClient, public_client: Client, user: User
) -> None:
    request_uri = _push(client, {"client_id": public_client.client_id, **_params()}).json()[
        "request_uri"
    ]
    PushedAuthorizationRequest.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    assert _authorize(user, public_client.client_id, request_uri).status_code == 400


def test_an_invented_request_uri_is_refused(public_client: Client, user: User) -> None:
    response = _authorize(user, public_client.client_id, "urn:ietf:params:oauth:request_uri:x")
    assert response.status_code == 400
    assert _authorize(user, public_client.client_id, "https://x.test/r").status_code == 400


def test_a_confidential_client_must_authenticate_to_push(
    client: HttpClient, confidential_client: tuple[Client, str]
) -> None:
    """RFC 9126 §2: the endpoint authenticates the client as the token endpoint does."""
    oauth_client, secret = confidential_client
    assert _push(client, {"client_id": oauth_client.client_id, **_params()}).status_code == 401
    ok = _push(client, _params(), HTTP_AUTHORIZATION=basic_auth(oauth_client.client_id, secret))
    assert ok.status_code == 201


def test_invalid_parameters_are_refused_as_json_not_redirected(
    client: HttpClient, public_client: Client
) -> None:
    """RFC 9126 §2.3: errors are returned as in RFC 6749 §5.2."""
    response = _push(
        client,
        {"client_id": public_client.client_id, **_params(code_challenge_method="plain")},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    wrong_uri = _push(
        client,
        {"client_id": public_client.client_id, **_params(redirect_uri="https://evil.test/cb")},
    )
    assert wrong_uri.json()["error"] == "invalid_request"
    bad_scope = _push(client, {"client_id": public_client.client_id, **_params(scope="admin")})
    assert bad_scope.json()["error"] == "invalid_scope"


def test_a_request_uri_cannot_be_pushed(client: HttpClient, public_client: Client) -> None:
    """RFC 9126 §2.1: request_uri MUST NOT be provided in a pushed request."""
    response = _push(
        client, {"client_id": public_client.client_id, "request_uri": "urn:x", **_params()}
    )
    assert response.json()["error"] == "invalid_request"


def test_a_dpop_proof_on_the_push_binds_the_code_to_its_key(
    client: HttpClient, public_client: Client, user: User
) -> None:
    """RFC 9449 §10.1: a DPoP proof at the PAR endpoint acts as dpop_jkt."""
    signer = ProofFactory()
    proof = signer.proof("POST", PAR_URL, nonce=nonce_store().current())
    pushed = _push(client, {"client_id": public_client.client_id, **_params()}, HTTP_DPOP=proof)
    assert pushed.status_code == 201, pushed.content

    callback = _authorize(user, public_client.client_id, pushed.json()["request_uri"])["Location"]
    code = parse_qs(urlsplit(callback).query)["code"][0]
    assert AuthorizationCode.objects.get().dpop_jkt == signer.jkt

    stranger = post_token(client, code_grant_form(public_client, code), ProofFactory())
    assert stranger.json()["error"] == "invalid_dpop_proof"


def test_a_proof_that_contradicts_dpop_jkt_is_refused(
    client: HttpClient, public_client: Client
) -> None:
    """RFC 9449 §10.1: both present means both must name the same key."""
    signer = ProofFactory()
    proof = signer.proof("POST", PAR_URL, nonce=nonce_store().current())
    response = _push(
        client,
        {"client_id": public_client.client_id, **_params(dpop_jkt=ProofFactory().jkt)},
        HTTP_DPOP=proof,
    )
    assert response.json()["error"] == "invalid_dpop_proof"


def test_metadata_advertises_par(client: HttpClient) -> None:
    body = client.get("/.well-known/oauth-authorization-server").json()
    assert body["pushed_authorization_request_endpoint"] == PAR_URL
    assert body["require_pushed_authorization_requests"] is False
