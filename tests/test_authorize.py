"""The authorization endpoint, login and consent (OAuth 2.1 §4.1.1-4.1.2)."""

from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from django.contrib.auth.models import User
from django.test import Client as HttpClient

from authserver import pkce
from authserver.credentials import digest
from authserver.models import AuthorizationCode, Client
from tests.conftest import REDIRECT_URI

ISSUER = "https://auth.example.test"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


def authorize_params(client: Client, **overrides: str | None) -> dict[str, str]:
    params: dict[str, str | None] = {
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "orders:read",
        "state": "xyz",
        "code_challenge": pkce.s256(VERIFIER),
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return {k: v for k, v in params.items() if v is not None}


def _query(location: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}


def _start(http: HttpClient, client: Client, **overrides: str | None) -> str:
    response = http.get("/oauth/authorize", authorize_params(client, **overrides))
    assert response.status_code == 302, response.content
    return str(response["Location"])


def approve(http: HttpClient, client: Client, **overrides: str | None) -> dict[str, str]:
    """Run the browser half of the flow as a signed-in user; return the callback query."""
    consent_url = _start(http, client, **overrides)
    assert consent_url.startswith("/oauth/consent")
    response = http.post(consent_url, {"decision": "approve"})
    assert response.status_code == 302
    location = str(response["Location"])
    assert location.startswith(REDIRECT_URI)
    return _query(location)


@pytest.fixture
def signed_in(client: HttpClient, user: User) -> HttpClient:
    client.force_login(user)
    return client


# --- Happy path --------------------------------------------------------------


def test_an_approved_request_returns_a_code_state_and_issuer(
    signed_in: HttpClient, public_client: Client
) -> None:
    """OAuth 2.1 §4.1.2 and RFC 9207 §2: code, the client's state, and iss."""
    query = approve(signed_in, public_client)
    assert query["state"] == "xyz"
    assert query["iss"] == ISSUER
    stored = AuthorizationCode.objects.get()
    assert stored.code_hash == digest(query["code"])
    assert stored.code_challenge == pkce.s256(VERIFIER)
    assert stored.scope == "orders:read"


def test_a_signed_out_user_is_sent_to_login_and_back(
    client: HttpClient, public_client: Client, user: User
) -> None:
    consent_url = _start(client, public_client)
    response = client.get(consent_url)
    assert response.status_code == 302
    login_url = str(response["Location"])
    assert login_url.startswith("/oauth/login")

    response = client.post(
        login_url,
        {
            "username": "alice",
            "password": "correct horse battery staple",
            "next": consent_url,
        },
    )
    assert response["Location"] == consent_url
    assert b"wants to access your account" in client.get(consent_url).content


def test_the_consent_page_names_the_client_and_the_scopes(
    signed_in: HttpClient, public_client: Client
) -> None:
    page = signed_in.get(_start(signed_in, public_client, scope="orders:read orders:write"))
    body = page.content.decode()
    assert "Mobile app" in body
    assert "See your orders" in body
    assert "Place orders on your behalf" in body
    assert "app.example.test" in body


def test_the_consent_page_cannot_be_framed(signed_in: HttpClient, public_client: Client) -> None:
    page = signed_in.get(_start(signed_in, public_client))
    assert page["X-Frame-Options"] == "DENY"


def test_approving_consent_requires_a_csrf_token(user: User, public_client: Client) -> None:
    http = HttpClient(enforce_csrf_checks=True)
    http.force_login(user)
    consent_url = _start(http, public_client)
    assert http.post(consent_url, {"decision": "approve"}).status_code == 403
    assert not AuthorizationCode.objects.exists()


def test_a_denied_request_reports_access_denied(
    signed_in: HttpClient, public_client: Client
) -> None:
    """RFC 6749 §4.1.2.1: access_denied, with state and iss."""
    response = signed_in.post(_start(signed_in, public_client), {"decision": "deny"})
    query = _query(str(response["Location"]))
    assert query == {"error": "access_denied", "state": "xyz", "iss": ISSUER}
    assert not AuthorizationCode.objects.exists()


def test_a_pending_request_can_be_decided_only_once(
    signed_in: HttpClient, public_client: Client
) -> None:
    consent_url = _start(signed_in, public_client)
    signed_in.post(consent_url, {"decision": "approve"})
    assert signed_in.post(consent_url, {"decision": "approve"}).status_code == 400
    assert AuthorizationCode.objects.count() == 1


def test_dpop_jkt_is_recorded_against_the_code(
    signed_in: HttpClient, public_client: Client
) -> None:
    """RFC 9449 §10: the key committed to at the authorization endpoint."""
    jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    approve(signed_in, public_client, dpop_jkt=jkt)
    assert AuthorizationCode.objects.get().dpop_jkt == jkt


def test_an_existing_query_on_the_redirect_uri_is_kept(
    signed_in: HttpClient, public_client: Client
) -> None:
    public_client.redirect_uris = [f"{REDIRECT_URI}?tenant=acme"]
    public_client.save()
    response = signed_in.post(
        _start(signed_in, public_client, redirect_uri=f"{REDIRECT_URI}?tenant=acme"),
        {"decision": "approve"},
    )
    query = _query(str(response["Location"]))
    assert query["tenant"] == "acme"
    assert "code" in query


# --- Never redirect to an unverified URI ------------------------------------


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://attacker.example.test/callback",
        f"{REDIRECT_URI}/extra",  # prefix match
        f"{REDIRECT_URI}?x=1",  # added query
        "https://APP.example.test/callback",  # case variation
        "https://app.example.test:443/callback",  # default port spelled out
        None,
    ],
)
def test_a_redirect_uri_that_is_not_exactly_registered_is_never_redirected_to(
    signed_in: HttpClient, public_client: Client, redirect_uri: str | None
) -> None:
    """OAuth 2.1 §2.3.1 and §4.1.2.1: exact match, else show an error, never redirect."""
    response = signed_in.get(
        "/oauth/authorize", authorize_params(public_client, redirect_uri=redirect_uri)
    )
    assert response.status_code == 400
    assert "Location" not in response


def test_an_unknown_client_is_never_redirected_to(signed_in: HttpClient) -> None:
    response = signed_in.get(
        "/oauth/authorize",
        {"response_type": "code", "client_id": "nope", "redirect_uri": REDIRECT_URI},
    )
    assert response.status_code == 400
    assert "Location" not in response


def test_a_repeated_redirect_uri_is_never_redirected_to(
    signed_in: HttpClient, public_client: Client
) -> None:
    """RFC 6749 §3.1: parameters MUST NOT be included more than once."""
    query = urlencode(authorize_params(public_client)) + "&redirect_uri=https://x.test/cb"
    response = signed_in.get(f"/oauth/authorize?{query}")
    assert response.status_code == 400
    assert "Location" not in response


# --- Errors reported to the client ------------------------------------------


def _error(signed_in: HttpClient, client: Client, **overrides: str | None) -> dict[str, str]:
    response = signed_in.get("/oauth/authorize", authorize_params(client, **overrides))
    assert response.status_code == 302
    location = str(response["Location"])
    assert location.startswith(REDIRECT_URI)
    query = _query(location)
    assert query["state"] == overrides.get("state", "xyz")
    assert query["iss"] == ISSUER
    return query


def test_a_missing_code_challenge_is_refused(signed_in: HttpClient, public_client: Client) -> None:
    """OAuth 2.1 §4.1.1: code_challenge is REQUIRED."""
    query = _error(signed_in, public_client, code_challenge=None, code_challenge_method=None)
    assert query["error"] == "invalid_request"


def test_the_plain_pkce_method_is_refused(signed_in: HttpClient, public_client: Client) -> None:
    """OAuth 2.1 §4.1.1 / RFC 7636 §4.2: only S256 is accepted here."""
    query = _error(signed_in, public_client, code_challenge=VERIFIER, code_challenge_method="plain")
    assert query["error"] == "invalid_request"


def test_an_absent_pkce_method_is_refused_because_it_means_plain(
    signed_in: HttpClient, public_client: Client
) -> None:
    """RFC 7636 §4.3: code_challenge_method defaults to "plain"."""
    query = _error(signed_in, public_client, code_challenge_method=None)
    assert query["error"] == "invalid_request"


def test_a_malformed_code_challenge_is_refused(
    signed_in: HttpClient, public_client: Client
) -> None:
    query = _error(signed_in, public_client, code_challenge="too-short")
    assert query["error"] == "invalid_request"


def test_only_the_code_response_type_is_supported(
    signed_in: HttpClient, public_client: Client
) -> None:
    """OAuth 2.1 drops the implicit grant."""
    assert _error(signed_in, public_client, response_type="token")["error"] == (
        "unsupported_response_type"
    )


@pytest.mark.parametrize("scope", ["admin", "orders:read admin", "", "bad\\scope", None])
def test_scopes_outside_the_registration_are_refused(
    signed_in: HttpClient, public_client: Client, scope: str | None
) -> None:
    assert _error(signed_in, public_client, scope=scope)["error"] == "invalid_scope"


def test_a_client_without_the_code_grant_is_refused(
    signed_in: HttpClient, public_client: Client
) -> None:
    public_client.grant_types = ["refresh_token"]
    public_client.save()
    assert _error(signed_in, public_client)["error"] == "unauthorized_client"


def test_a_repeated_parameter_is_refused(signed_in: HttpClient, public_client: Client) -> None:
    """RFC 6749 §3.1: parameters MUST NOT be included more than once."""
    query = urlencode(authorize_params(public_client)) + "&scope=profile"
    response = signed_in.get(f"/oauth/authorize?{query}")
    assert _query(str(response["Location"]))["error"] == "invalid_request"


def test_a_malformed_dpop_jkt_is_refused(signed_in: HttpClient, public_client: Client) -> None:
    assert _error(signed_in, public_client, dpop_jkt="short")["error"] == "invalid_request"


def test_an_overlong_state_is_refused(signed_in: HttpClient, public_client: Client) -> None:
    response = signed_in.get("/oauth/authorize", authorize_params(public_client, state="s" * 600))
    assert _query(str(response["Location"]))["error"] == "invalid_request"
