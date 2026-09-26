"""Driving the authorization server the way a client would, for tests."""

import base64
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlsplit

from django.contrib.auth.models import User
from django.test import Client as HttpClient

from authserver import pkce
from authserver.models import Client
from authserver.proofs import nonce_store
from tests.conftest import REDIRECT_URI
from tests.proofs import ProofFactory

if TYPE_CHECKING:
    # What the test client really returns: an HttpResponse with .json() bolted
    # on. It exists only in django-stubs.
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

ISSUER = "https://auth.example.test"
TOKEN_URL = f"{ISSUER}/oauth/token"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


def basic_auth(client_id: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


def obtain_code(client: Client, user: User, *, scope: str = "orders:read", **extra: str) -> str:
    """Sign in, approve consent, and return the authorization code."""
    browser = HttpClient()
    browser.force_login(user)
    params = {
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "state": "s",
        "code_challenge": pkce.s256(VERIFIER),
        "code_challenge_method": "S256",
        **extra,
    }
    consent_url = browser.get("/oauth/authorize", params)["Location"]
    callback = browser.post(consent_url, {"decision": "approve"})["Location"]
    return parse_qs(urlsplit(callback).query)["code"][0]


def post_token(
    http: HttpClient,
    form: dict[str, str],
    signer: ProofFactory | None,
    *,
    nonce: str | None = "current",
    proof: str | None = None,
    **headers: Any,
) -> "TestResponse":
    """POST to the token endpoint with a fresh proof carrying the current nonce.

    ``nonce="current"`` fetches the server's nonce directly, standing in for
    the client having kept it from an earlier response.
    """
    if proof is None and signer is not None:
        value = nonce_store().current() if nonce == "current" else nonce
        proof = signer.proof("POST", TOKEN_URL, nonce=value)
    if proof is not None:
        headers["HTTP_DPOP"] = proof
    return http.post(
        "/oauth/token",
        urlencode(form),
        content_type="application/x-www-form-urlencoded",
        **headers,
    )


def code_grant_form(client: Client, code: str, **overrides: str) -> dict[str, str]:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": VERIFIER,
        "redirect_uri": REDIRECT_URI,
        "client_id": client.client_id,
    }
    form.update(overrides)
    return form
