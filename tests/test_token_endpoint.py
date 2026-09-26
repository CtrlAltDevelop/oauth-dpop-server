"""The token endpoint: the authorization code grant, client authentication and
DPoP binding (OAuth 2.1 §3.2 and §4.1.3, RFC 9449 §5, §6 and §8)."""

from datetime import timedelta

import pytest
from django.contrib.auth.models import User
from django.test import Client as HttpClient
from django.utils import timezone
from joserfc import jwt
from joserfc.jwk import KeySet

from authserver.keys import published_jwks
from authserver.models import AccessToken, AuthorizationCode, Client, RefreshToken, TokenFamily
from authserver.proofs import nonce_store
from tests.flows import (
    ISSUER,
    TOKEN_URL,
    basic_auth,
    code_grant_form,
    obtain_code,
    post_token,
)
from tests.proofs import ProofFactory

pytestmark = pytest.mark.django_db

INVALID_GRANT = "The grant is invalid, expired, revoked, or was issued to another client."


@pytest.fixture
def signer() -> ProofFactory:
    return ProofFactory()


def _decode(token: str) -> jwt.Token:
    return jwt.decode(token, KeySet.import_key_set(published_jwks()))


# --- Success -----------------------------------------------------------------


def test_a_code_is_exchanged_for_a_dpop_bound_token(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §5: token_type DPoP, and the token is bound to the proof's key."""
    code = obtain_code(public_client, user)
    response = post_token(client, code_grant_form(public_client, code), signer)

    assert response.status_code == 200, response.content
    body = response.json()
    assert body["token_type"] == "DPoP"
    assert body["expires_in"] == 300
    assert body["scope"] == "orders:read"
    assert "refresh_token" in body
    assert response["Cache-Control"] == "no-store"
    assert response["Pragma"] == "no-cache"


def test_the_access_token_follows_the_rfc_9068_profile(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9068 §2: typ at+jwt, and iss, exp, aud, sub, client_id, iat, jti."""
    code = obtain_code(public_client, user)
    token = post_token(client, code_grant_form(public_client, code), signer).json()["access_token"]
    decoded = _decode(token)

    assert decoded.header["typ"] == "at+jwt"
    assert decoded.header["alg"] == "ES256"
    assert "kid" in decoded.header
    claims = decoded.claims
    assert claims["iss"] == ISSUER
    assert claims["aud"] == f"{ISSUER}/api"
    assert claims["sub"] == str(user.pk)
    assert claims["client_id"] == public_client.client_id
    assert claims["scope"] == "orders:read"
    assert claims["exp"] - claims["iat"] == 300
    assert "auth_time" in claims
    assert AccessToken.objects.filter(jti=claims["jti"]).exists()


def test_the_access_token_is_bound_to_the_proof_key_by_thumbprint(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §6.1: cnf.jkt is the SHA-256 JWK thumbprint of the proof key."""
    code = obtain_code(public_client, user)
    token = post_token(client, code_grant_form(public_client, code), signer).json()["access_token"]
    assert _decode(token).claims["cnf"] == {"jkt": signer.jkt}


def test_a_public_clients_refresh_token_is_bound_to_its_dpop_key(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §5: refresh tokens issued to public clients are bound to the key."""
    code = obtain_code(public_client, user)
    post_token(client, code_grant_form(public_client, code), signer)
    assert RefreshToken.objects.get().jkt == signer.jkt


def test_a_confidential_clients_refresh_token_is_not_key_bound(
    client: HttpClient,
    confidential_client: tuple[Client, str],
    user: User,
    signer: ProofFactory,
) -> None:
    """RFC 9449 §5: a confidential client's refresh token is bound by client auth."""
    oauth_client, secret = confidential_client
    code = obtain_code(oauth_client, user)
    form = code_grant_form(oauth_client, code)
    del form["client_id"]
    response = post_token(
        client, form, signer, HTTP_AUTHORIZATION=basic_auth(oauth_client.client_id, secret)
    )
    assert response.status_code == 200, response.content
    assert RefreshToken.objects.get().jkt == ""


def test_no_refresh_token_without_the_refresh_grant(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    public_client.grant_types = ["authorization_code"]
    public_client.save()
    code = obtain_code(public_client, user)
    body = post_token(client, code_grant_form(public_client, code), signer).json()
    assert "refresh_token" not in body


# --- DPoP at the token endpoint ----------------------------------------------


def test_a_request_without_a_nonce_is_told_to_use_one(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §8: 400 use_dpop_nonce, with the nonce in a DPoP-Nonce header."""
    code = obtain_code(public_client, user)
    response = post_token(client, code_grant_form(public_client, code), signer, nonce=None)
    assert response.status_code == 400
    assert response.json()["error"] == "use_dpop_nonce"
    nonce = response["DPoP-Nonce"]

    retry = post_token(client, code_grant_form(public_client, code), signer, nonce=nonce)
    assert retry.status_code == 200, retry.content


def test_every_token_response_carries_the_current_nonce(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §8: the server may supply a fresh nonce on any response."""
    code = obtain_code(public_client, user)
    response = post_token(client, code_grant_form(public_client, code), signer)
    assert response["DPoP-Nonce"]


def test_a_token_request_without_a_proof_is_refused(
    client: HttpClient, public_client: Client, user: User
) -> None:
    """RFC 9449 §5: this server binds every token, so a proof is mandatory."""
    code = obtain_code(public_client, user)
    response = post_token(client, code_grant_form(public_client, code), None)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_dpop_proof"


def test_a_proof_for_another_url_is_refused(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §4.3 step 9, at the token endpoint."""
    code = obtain_code(public_client, user)
    proof = signer.proof("POST", "https://auth.example.test/oauth/revoke")
    response = post_token(client, code_grant_form(public_client, code), None, proof=proof)
    assert response.json()["error"] == "invalid_dpop_proof"


def test_htu_is_checked_against_the_issuer_not_the_host_header(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """A proof for whatever Host the request claims is not a proof for this server."""
    code = obtain_code(public_client, user)
    proof = signer.proof("POST", "http://testserver/oauth/token", nonce=nonce_store().current())
    response = post_token(client, code_grant_form(public_client, code), None, proof=proof)
    assert response.json()["error"] == "invalid_dpop_proof"


def test_a_replayed_proof_is_refused_at_the_token_endpoint(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §11.1: the second use of the same proof fails."""
    proof = signer.proof("POST", TOKEN_URL, nonce=nonce_store().current())
    first = post_token(
        client, code_grant_form(public_client, obtain_code(public_client, user)), None, proof=proof
    )
    assert first.status_code == 200
    second = post_token(
        client, code_grant_form(public_client, obtain_code(public_client, user)), None, proof=proof
    )
    assert second.json()["error"] == "invalid_dpop_proof"


def test_two_dpop_headers_are_refused(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §4.3 step 1, through the whole HTTP stack."""
    code = obtain_code(public_client, user)
    folded = f"{signer.proof('POST', TOKEN_URL)},{signer.proof('POST', TOKEN_URL)}"
    response = post_token(client, code_grant_form(public_client, code), None, proof=folded)
    assert response.json()["error"] == "invalid_dpop_proof"


def test_dpop_jkt_from_the_authorization_request_must_match_the_proof(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §10: the proof key must be the one committed to with dpop_jkt."""
    code = obtain_code(public_client, user, dpop_jkt=ProofFactory().jkt)
    response = post_token(client, code_grant_form(public_client, code), signer)
    assert response.json()["error"] == "invalid_dpop_proof"


def test_a_matching_dpop_jkt_is_accepted(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 9449 §10: authorization code binding to the DPoP key."""
    code = obtain_code(public_client, user, dpop_jkt=signer.jkt)
    assert post_token(client, code_grant_form(public_client, code), signer).status_code == 200


# --- The authorization code --------------------------------------------------


def test_a_code_can_be_redeemed_once_and_reuse_revokes_what_it_issued(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """OAuth 2.1 §4.1.3: on reuse, revoke the tokens previously issued from the code."""
    code = obtain_code(public_client, user)
    assert post_token(client, code_grant_form(public_client, code), signer).status_code == 200

    replay = post_token(client, code_grant_form(public_client, code), signer)
    assert replay.json() == {"error": "invalid_grant", "error_description": INVALID_GRANT}
    family = TokenFamily.objects.get()
    assert family.revoked_reason == "authorization_code_reuse"
    assert not AccessToken.objects.filter(revoked_at__isnull=True).exists()


def test_a_wrong_code_verifier_is_refused_and_burns_the_code(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """RFC 7636 §4.6: the verifier must hash to the challenge. One attempt per code."""
    code = obtain_code(public_client, user)
    wrong = post_token(client, code_grant_form(public_client, code, code_verifier="x" * 43), signer)
    assert wrong.json()["error"] == "invalid_grant"
    right = post_token(client, code_grant_form(public_client, code), signer)
    assert right.json()["error"] == "invalid_grant"


def test_a_missing_code_verifier_is_refused(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    code = obtain_code(public_client, user)
    form = code_grant_form(public_client, code)
    del form["code_verifier"]
    assert post_token(client, form, signer).json()["error"] == "invalid_request"


def test_the_redirect_uri_must_match_the_authorization_request(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    """OAuth 2.1 §4.1.3: redirect_uri identical to the authorization request's."""
    code = obtain_code(public_client, user)
    form = code_grant_form(public_client, code, redirect_uri="https://app.example.test/other")
    assert post_token(client, form, signer).json()["error"] == "invalid_grant"


def test_an_expired_code_is_refused(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    code = obtain_code(public_client, user)
    AuthorizationCode.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    assert post_token(client, code_grant_form(public_client, code), signer).json()["error"] == (
        "invalid_grant"
    )


def test_a_code_issued_to_another_client_is_refused(
    client: HttpClient,
    public_client: Client,
    confidential_client: tuple[Client, str],
    user: User,
    signer: ProofFactory,
) -> None:
    """OAuth 2.1 §4.1.3: the code was issued to the authenticated client."""
    other, secret = confidential_client
    code = obtain_code(public_client, user)
    form = code_grant_form(other, code, client_secret=secret)
    response = post_token(client, form, signer)
    assert response.json() == {"error": "invalid_grant", "error_description": INVALID_GRANT}
    # The rightful client can still redeem it: a stranger's guess burns nothing.
    assert post_token(client, code_grant_form(public_client, code), signer).status_code == 200


def test_an_unknown_code_gets_the_same_answer_as_every_other_bad_grant(
    client: HttpClient, public_client: Client, signer: ProofFactory
) -> None:
    response = post_token(client, code_grant_form(public_client, "no-such-code"), signer)
    assert response.json() == {"error": "invalid_grant", "error_description": INVALID_GRANT}


# --- Client authentication ---------------------------------------------------


def test_client_secret_basic_authenticates(
    client: HttpClient, confidential_client: tuple[Client, str], user: User, signer: ProofFactory
) -> None:
    oauth_client, secret = confidential_client
    form = code_grant_form(oauth_client, obtain_code(oauth_client, user))
    del form["client_id"]
    auth = basic_auth(oauth_client.client_id, secret)
    assert post_token(client, form, signer, HTTP_AUTHORIZATION=auth).status_code == 200


def test_client_secret_post_authenticates(
    client: HttpClient, confidential_client: tuple[Client, str], user: User, signer: ProofFactory
) -> None:
    oauth_client, secret = confidential_client
    form = code_grant_form(oauth_client, obtain_code(oauth_client, user), client_secret=secret)
    assert post_token(client, form, signer).status_code == 200


def test_a_wrong_secret_is_refused_with_a_basic_challenge(
    client: HttpClient, confidential_client: tuple[Client, str], signer: ProofFactory
) -> None:
    """RFC 6749 §5.2: 401 and WWW-Authenticate when Basic auth fails."""
    oauth_client, _ = confidential_client
    auth = basic_auth(oauth_client.client_id, "wrong")
    response = post_token(
        client, {"grant_type": "client_credentials"}, signer, HTTP_AUTHORIZATION=auth
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
    assert response["WWW-Authenticate"].startswith("Basic")


def test_an_unknown_client_looks_exactly_like_a_wrong_secret(
    client: HttpClient, confidential_client: tuple[Client, str], signer: ProofFactory
) -> None:
    oauth_client, _ = confidential_client
    wrong_secret = post_token(
        client,
        {
            "grant_type": "client_credentials",
            "client_id": oauth_client.client_id,
            "client_secret": "wrong",
        },
        signer,
    )
    unknown = post_token(
        client,
        {"grant_type": "client_credentials", "client_id": "nobody", "client_secret": "wrong"},
        signer,
    )
    assert wrong_secret.status_code == unknown.status_code == 401
    assert wrong_secret.json() == unknown.json()


def test_a_confidential_client_must_authenticate(
    client: HttpClient, confidential_client: tuple[Client, str], user: User, signer: ProofFactory
) -> None:
    oauth_client, _ = confidential_client
    form = code_grant_form(oauth_client, obtain_code(oauth_client, user))
    assert post_token(client, form, signer).json()["error"] == "invalid_client"


def test_a_public_client_cannot_present_a_secret(
    client: HttpClient, public_client: Client, user: User, signer: ProofFactory
) -> None:
    form = code_grant_form(public_client, obtain_code(public_client, user), client_secret="x")
    assert post_token(client, form, signer).json()["error"] == "invalid_client"


def test_two_authentication_methods_at_once_are_refused(
    client: HttpClient, confidential_client: tuple[Client, str], signer: ProofFactory
) -> None:
    """RFC 6749 §2.3: a client MUST NOT use more than one authentication method."""
    oauth_client, secret = confidential_client
    response = post_token(
        client,
        {"grant_type": "client_credentials", "client_secret": secret},
        signer,
        HTTP_AUTHORIZATION=basic_auth(oauth_client.client_id, secret),
    )
    assert response.json()["error"] == "invalid_request"


def test_malformed_basic_credentials_are_refused(client: HttpClient, signer: ProofFactory) -> None:
    response = post_token(
        client, {"grant_type": "client_credentials"}, signer, HTTP_AUTHORIZATION="Basic !!!"
    )
    assert response.status_code == 401


# --- Request shape -----------------------------------------------------------


def test_the_body_must_be_form_encoded(client: HttpClient, public_client: Client) -> None:
    response = client.post(
        "/oauth/token",
        {"grant_type": "authorization_code", "client_id": public_client.client_id},
        content_type="application/json",
    )
    assert response.json()["error"] == "invalid_request"


def test_a_repeated_parameter_is_refused(
    client: HttpClient, public_client: Client, signer: ProofFactory
) -> None:
    """RFC 6749 §3.1: parameters MUST NOT be included more than once."""
    response = client.post(
        "/oauth/token",
        f"grant_type=authorization_code&code=a&code=b&client_id={public_client.client_id}",
        content_type="application/x-www-form-urlencoded",
        HTTP_DPOP=signer.proof("POST", TOKEN_URL),
    )
    assert response.json()["error"] == "invalid_request"


def test_an_unsupported_grant_type_is_refused(
    client: HttpClient, public_client: Client, signer: ProofFactory
) -> None:
    form = {"grant_type": "password", "client_id": public_client.client_id}
    assert post_token(client, form, signer).json()["error"] == "unsupported_grant_type"


def test_a_grant_the_client_is_not_registered_for_is_refused(
    client: HttpClient, public_client: Client, signer: ProofFactory
) -> None:
    public_client.grant_types = ["refresh_token"]
    public_client.save()
    form = {"grant_type": "authorization_code", "client_id": public_client.client_id}
    assert post_token(client, form, signer).json()["error"] == "unauthorized_client"


def test_a_missing_grant_type_is_refused(
    client: HttpClient, public_client: Client, signer: ProofFactory
) -> None:
    form = {"client_id": public_client.client_id}
    assert post_token(client, form, signer).json()["error"] == "invalid_request"
