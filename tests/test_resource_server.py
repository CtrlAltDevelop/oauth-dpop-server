"""The ``ninja_dpop`` resource server, exercised through the example API
(RFC 9449 §7 and §9, RFC 9068 §4, RFC 6750 §3)."""

import time
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import pytest
from django.test import Client as HttpClient
from django.test import override_settings

from authserver.keys import rotate, sign_jwt
from authserver.models import Client
from config.settings import resource_server
from ninja_dpop import jwks
from tests.flows import ISSUER, basic_auth, post_token
from tests.proofs import ProofFactory

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

pytestmark = pytest.mark.django_db

ORDERS_URL = f"{ISSUER}/api/orders"


@pytest.fixture(autouse=True)
def _fresh_jwks_cache() -> Iterator[None]:
    # Each test has its own database, and so its own signing keys.
    jwks.clear_cache()
    yield
    jwks.clear_cache()


@pytest.fixture
def signer() -> ProofFactory:
    return ProofFactory()


@pytest.fixture
def access_token(
    client: HttpClient, confidential_client: tuple[Client, str], signer: ProofFactory
) -> str:
    oauth_client, secret = confidential_client
    response = post_token(
        client,
        {"grant_type": "client_credentials", "scope": "orders:read profile"},
        signer,
        HTTP_AUTHORIZATION=basic_auth(oauth_client.client_id, secret),
    )
    token: str = response.json()["access_token"]
    return token


def call(
    http: HttpClient,
    token: str | None,
    signer: ProofFactory | None,
    *,
    method: str = "GET",
    url: str = ORDERS_URL,
    proof: str | None = None,
    scheme: str = "DPoP",
) -> "TestResponse":
    headers: dict[str, Any] = {}
    if token is not None:
        headers["HTTP_AUTHORIZATION"] = f"{scheme} {token}"
    if proof is None and signer is not None:
        proof = signer.proof(method, url, access_token=token)
    if proof is not None:
        headers["HTTP_DPOP"] = proof
    path = url.removeprefix(ISSUER)
    if method == "POST":
        return http.post(path, content_type="application/json", **headers)
    return http.get(path, **headers)


def _challenge(response: "TestResponse") -> str:
    assert response.status_code in {401, 403}, response.content
    challenge: str = response["WWW-Authenticate"]
    assert challenge.startswith("DPoP ")
    return challenge


def _token(**overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "someone",
        "aud": f"{ISSUER}/api",
        "client_id": "c",
        "iat": now,
        "exp": now + 300,
        "jti": "j",
        "scope": "orders:read",
        "cnf": {"jkt": ProofFactory().jkt},
    }
    header = {"typ": overrides.pop("typ", "at+jwt")}
    claims.update(overrides)
    return sign_jwt(header, {k: v for k, v in claims.items() if v is not None})


# --- Success -----------------------------------------------------------------


def test_a_bound_token_with_a_matching_proof_is_accepted(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    """RFC 9449 §7.1: Authorization: DPoP, plus a proof with ath."""
    response = call(client, access_token, signer)
    assert response.status_code == 200, response.content
    assert response.json() == []


def test_the_principal_carries_the_tokens_subject_scopes_and_key(
    client: HttpClient,
    access_token: str,
    signer: ProofFactory,
    confidential_client: tuple[Client, str],
) -> None:
    body = call(client, access_token, signer, url=f"{ISSUER}/api/me").json()
    assert body["subject"] == confidential_client[0].client_id
    assert body["scopes"] == ["orders:read", "profile"]
    assert body["jkt"] == signer.jkt


def test_the_scheme_name_is_case_insensitive(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    """RFC 9110 §11.1: authentication scheme names are case-insensitive."""
    assert call(client, access_token, signer, scheme="dpop").status_code == 200


def test_query_strings_do_not_affect_htu(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    proof = signer.proof("GET", ORDERS_URL, access_token=access_token)
    response = client.get(
        "/api/orders?limit=5", HTTP_AUTHORIZATION=f"DPoP {access_token}", HTTP_DPOP=proof
    )
    assert response.status_code == 200


# --- Missing or misused credentials ------------------------------------------


def test_no_credentials_gets_a_bare_challenge(client: HttpClient) -> None:
    """RFC 6750 §3.1: no error code when the request had no authentication."""
    challenge = _challenge(call(client, None, None))
    assert "error=" not in challenge
    assert 'algs="ES256' in challenge  # RFC 9449 §7.1


def test_a_bound_token_presented_as_bearer_is_refused(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    """RFC 9449 §7.2: a DPoP-bound token MUST NOT be accepted as a Bearer token."""
    challenge = _challenge(call(client, access_token, signer, scheme="Bearer"))
    assert 'error="invalid_token"' in challenge


def test_an_unknown_scheme_is_refused(client: HttpClient, access_token: str) -> None:
    assert 'error="invalid_request"' in _challenge(call(client, access_token, None, scheme="MAC"))


def test_a_token_without_a_proof_is_refused(client: HttpClient, access_token: str) -> None:
    """RFC 9449 §7.1: a DPoP-bound token needs a proof on every request."""
    assert 'error="invalid_dpop_proof"' in _challenge(call(client, access_token, None))


# --- The proof, against the token --------------------------------------------


def test_a_proof_without_ath_is_refused(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    """RFC 9449 §4.3 step 12 / §7: ath is required with an access token."""
    proof = signer.proof("GET", ORDERS_URL)
    assert 'error="invalid_dpop_proof"' in _challenge(call(client, access_token, None, proof=proof))


def test_a_proof_whose_ath_hashes_another_token_is_refused(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    """RFC 9449 §4.3 step 12: ath must be the hash of the token presented."""
    proof = signer.proof("GET", ORDERS_URL, access_token="some-other-token")
    assert 'error="invalid_dpop_proof"' in _challenge(call(client, access_token, None, proof=proof))


def test_a_proof_from_a_key_other_than_cnf_jkt_is_refused(
    client: HttpClient, access_token: str
) -> None:
    """RFC 9449 §6.1 / §7.1: the proof key must match the token's cnf.jkt."""
    thief = ProofFactory()
    assert 'error="invalid_dpop_proof"' in _challenge(call(client, access_token, thief))


def test_a_proof_for_the_wrong_method_is_refused(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    proof = signer.proof("POST", ORDERS_URL, access_token=access_token)
    assert 'error="invalid_dpop_proof"' in _challenge(call(client, access_token, None, proof=proof))


def test_a_proof_for_another_resource_is_refused(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    proof = signer.proof("GET", f"{ISSUER}/api/me", access_token=access_token)
    assert 'error="invalid_dpop_proof"' in _challenge(call(client, access_token, None, proof=proof))


def test_htu_is_compared_with_the_configured_origin_not_the_host_header(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    proof = signer.proof("GET", "http://testserver/api/orders", access_token=access_token)
    assert 'error="invalid_dpop_proof"' in _challenge(call(client, access_token, None, proof=proof))


def test_a_replayed_proof_is_refused(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    """RFC 9449 §11.1: a resource server tracks jti too."""
    proof = signer.proof("GET", ORDERS_URL, access_token=access_token)
    assert call(client, access_token, None, proof=proof).status_code == 200
    assert 'error="invalid_dpop_proof"' in _challenge(call(client, access_token, None, proof=proof))


def test_an_expired_proof_is_refused(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    proof = signer.proof("GET", ORDERS_URL, access_token=access_token, iat=int(time.time()) - 3600)
    assert 'error="invalid_dpop_proof"' in _challenge(call(client, access_token, None, proof=proof))


# --- The token itself (RFC 9068 §4) -----------------------------------------


def _with_matching_proof(client: HttpClient, token: str, key: ProofFactory) -> "TestResponse":
    return call(client, token, key)


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://evil.example.test"},
        {"aud": "https://other-api.example.test"},
        {"exp": int(time.time()) - 60},
        {"iat": int(time.time()) + 3600},
        {"nbf": int(time.time()) + 3600},
        {"typ": "JWT"},
        {"sub": None},
    ],
    ids=["issuer", "audience", "expired", "future-iat", "not-yet-valid", "typ", "no-sub"],
)
def test_tokens_outside_the_rfc_9068_profile_are_refused(
    client: HttpClient, overrides: dict[str, Any]
) -> None:
    key = ProofFactory()
    token = _token(cnf={"jkt": key.jkt}, **overrides)
    assert 'error="invalid_token"' in _challenge(_with_matching_proof(client, token, key))


def test_an_audience_list_containing_this_api_is_accepted(client: HttpClient) -> None:
    key = ProofFactory()
    token = _token(cnf={"jkt": key.jkt}, aud=["https://other.test", f"{ISSUER}/api"])
    assert _with_matching_proof(client, token, key).status_code == 200


def test_an_unbound_token_is_refused(client: HttpClient) -> None:
    """RFC 9449 §6: only tokens carrying cnf.jkt are DPoP tokens."""
    key = ProofFactory()
    token = _token(cnf=None)
    assert 'error="invalid_token"' in _challenge(_with_matching_proof(client, token, key))


def test_a_token_signed_by_a_stranger_is_refused(client: HttpClient, signer: ProofFactory) -> None:
    forged = signer.proof("GET", ORDERS_URL, header={"typ": "at+jwt", "kid": "x"})
    assert 'error="invalid_token"' in _challenge(call(client, forged, signer))


@pytest.mark.parametrize("token", ["not-a-jwt", "a.b.c", "x" * 9000])
def test_garbage_tokens_are_refused(client: HttpClient, signer: ProofFactory, token: str) -> None:
    assert 'error="invalid_token"' in _challenge(call(client, token, signer))


# --- Scope -------------------------------------------------------------------


def test_insufficient_scope_is_403_with_the_scope_needed(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    """RFC 6750 §3.1: insufficient_scope, 403, and the scope required."""
    response = call(client, access_token, signer, method="POST")
    challenge = _challenge(response)
    assert response.status_code == 403
    assert 'error="insufficient_scope"' in challenge
    assert 'scope="orders:write"' in challenge


def test_the_right_scope_can_write(
    client: HttpClient, confidential_client: tuple[Client, str], signer: ProofFactory
) -> None:
    oauth_client, secret = confidential_client
    token = post_token(
        client,
        {"grant_type": "client_credentials", "scope": "orders:write orders:read"},
        signer,
        HTTP_AUTHORIZATION=basic_auth(oauth_client.client_id, secret),
    ).json()["access_token"]
    proof = signer.proof("POST", ORDERS_URL, access_token=token)
    response = client.post(
        "/api/orders",
        {"item": "widget", "quantity": 3},
        content_type="application/json",
        HTTP_AUTHORIZATION=f"DPoP {token}",
        HTTP_DPOP=proof,
    )
    assert response.status_code == 201, response.content
    assert response.json()["placed_by_client"] == oauth_client.client_id
    assert len(call(client, token, signer).json()) == 1


# --- Nonces (RFC 9449 §9) ---------------------------------------------------


def test_a_resource_server_requiring_nonces_says_so_and_accepts_the_retry(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    """RFC 9449 §9: 401, error use_dpop_nonce, and a DPoP-Nonce header."""
    with override_settings(NINJA_DPOP={**resource_server(ISSUER), "REQUIRE_NONCE": True}):
        response = call(client, access_token, signer)
        assert 'error="use_dpop_nonce"' in _challenge(response)
        nonce = response["DPoP-Nonce"]
        proof = signer.proof("GET", ORDERS_URL, access_token=access_token, nonce=nonce)
        assert call(client, access_token, None, proof=proof).status_code == 200


def test_resource_server_and_authorization_server_nonces_are_separate(
    client: HttpClient, access_token: str, signer: ProofFactory
) -> None:
    """A nonce is scoped to the server that issued it (RFC 9449 §8, §9)."""
    from authserver.proofs import nonce_store

    with override_settings(NINJA_DPOP={**resource_server(ISSUER), "REQUIRE_NONCE": True}):
        as_nonce = nonce_store().current()
        proof = signer.proof("GET", ORDERS_URL, access_token=access_token, nonce=as_nonce)
        assert 'error="use_dpop_nonce"' in _challenge(call(client, access_token, None, proof=proof))


# --- Keys --------------------------------------------------------------------


def test_a_token_from_a_freshly_rotated_key_is_picked_up(
    client: HttpClient,
    confidential_client: tuple[Client, str],
    access_token: str,
    signer: ProofFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A kid the cache has not seen triggers a refetch (once the floor has passed)."""
    assert call(client, access_token, signer).status_code == 200  # warms the cache
    rotate()
    rotate()  # the new active key was not in the cached set
    monkeypatch.setattr(jwks, "_REFETCH_FLOOR", 0)
    oauth_client, secret = confidential_client
    fresh = post_token(
        client,
        {"grant_type": "client_credentials", "scope": "orders:read"},
        signer,
        HTTP_AUTHORIZATION=basic_auth(oauth_client.client_id, secret),
    ).json()["access_token"]
    assert call(client, fresh, signer).status_code == 200
    # And the token from before both rotations still verifies (retired, not removed).
    assert call(client, access_token, signer).status_code == 200


def test_keys_can_come_from_a_jwks_url(
    client: HttpClient, access_token: str, signer: ProofFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    from authserver.keys import published_jwks

    fetched: list[str] = []

    def fake_fetch(url: str) -> dict[str, Any]:
        fetched.append(url)
        return dict(published_jwks())

    monkeypatch.setattr(jwks, "_fetch", fake_fetch)
    url = f"{ISSUER}/oauth/jwks"
    with override_settings(NINJA_DPOP={**resource_server(ISSUER), "JWKS": url}):
        assert call(client, access_token, signer).status_code == 200
        assert call(client, access_token, ProofFactory(signer.key)).status_code == 200
    assert fetched == [url]  # cached after the first request
