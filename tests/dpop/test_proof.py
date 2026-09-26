"""RFC 9449 §4.3 — checking DPoP proofs, one test per MUST.

Each docstring names the step of §4.3's checklist (or the other section) the
test holds the verifier to.
"""

import json
import time

import pytest
from joserfc.jwk import ECKey, OctKey, OKPKey, RSAKey

from dpop.errors import InvalidDPoPProof
from dpop.proof import ProofPolicy, ProofVerifier, single_proof
from dpop.thumbprint import jwk_thumbprint
from tests.proofs import ProofFactory, b64url, unsigned_proof

URL = "https://api.example.test/orders"
POLICY = ProofPolicy(algorithms=frozenset({"ES256", "ES384", "Ed25519", "PS256"}))
NOW = 1_800_000_000


@pytest.fixture
def signer() -> ProofFactory:
    return ProofFactory()


@pytest.fixture
def verifier() -> ProofVerifier:
    return ProofVerifier(POLICY, clock=lambda: NOW)


def _refused(verifier: ProofVerifier, proof: str, reason: str, **kwargs: object) -> None:
    with pytest.raises(InvalidDPoPProof) as caught:
        verifier.verify(proof, method=kwargs.pop("method", "GET"), url=URL, **kwargs)  # type: ignore[arg-type]
    assert reason in caught.value.reason
    assert caught.value.error == "invalid_dpop_proof"


def test_a_well_formed_proof_is_accepted(verifier: ProofVerifier, signer: ProofFactory) -> None:
    verified = verifier.verify(signer.proof("GET", URL, iat=NOW), method="GET", url=URL)
    assert verified.jkt == signer.jkt
    assert verified.htm == "GET"


# --- Step 1 ----------------------------------------------------------------


def test_more_than_one_dpop_header_is_refused() -> None:
    """§4.3 step 1: not more than one DPoP HTTP request header field."""
    with pytest.raises(InvalidDPoPProof):
        single_proof(["a.b.c", "d.e.f"])


def test_folded_dpop_headers_are_refused() -> None:
    """§4.3 step 1: a proxy may fold two fields into one comma-joined value."""
    with pytest.raises(InvalidDPoPProof):
        single_proof(["a.b.c, d.e.f"])


def test_no_dpop_header_means_no_proof() -> None:
    assert single_proof([]) is None


# --- Step 2 ----------------------------------------------------------------


@pytest.mark.parametrize("garbage", ["", "not-a-jwt", "a.b", "a.b.c.d.e", "é.é.é"])
def test_a_proof_that_is_not_a_jwt_is_refused(verifier: ProofVerifier, garbage: str) -> None:
    """§4.3 step 2: the DPoP header value is a single well-formed JWT."""
    _refused(verifier, garbage, "well-formed")


def test_a_payload_that_is_not_an_object_is_refused(
    verifier: ProofVerifier, signer: ProofFactory
) -> None:
    """§4.3 step 2: the JWT claims set is a JSON object."""
    header = b64url(json.dumps({"typ": "dpop+jwt", "alg": "ES256"}).encode())
    proof = f"{header}.{b64url(b'[1, 2]')}.sig"
    _refused(verifier, proof, "")


def test_an_oversized_proof_is_refused(verifier: ProofVerifier) -> None:
    _refused(verifier, "a" * 9000, "too large")


# --- Step 3 ----------------------------------------------------------------


@pytest.mark.parametrize("member", ["typ", "alg", "jwk", "jti", "htm", "htu", "iat"])
def test_every_required_member_must_be_present(
    verifier: ProofVerifier, signer: ProofFactory, member: str
) -> None:
    """§4.3 step 3 and §4.2: typ, alg, jwk, jti, htm, htu and iat are REQUIRED."""
    with pytest.raises(InvalidDPoPProof):
        verifier.verify(signer.proof("GET", URL, iat=NOW, drop=(member,)), method="GET", url=URL)


@pytest.mark.parametrize("iat", ["1800000000", True, 1.8e9, None])
def test_iat_must_be_an_integer(verifier: ProofVerifier, signer: ProofFactory, iat: object) -> None:
    """§4.2: iat is a NumericDate — and `true` is not one, whatever Python thinks."""
    proof = signer.proof("GET", URL, claims={"iat": iat})
    _refused(verifier, proof, "iat")


def test_an_overlong_jti_is_refused(verifier: ProofVerifier, signer: ProofFactory) -> None:
    _refused(verifier, signer.proof("GET", URL, iat=NOW, jti="x" * 300), "jti")


# --- Step 4 ----------------------------------------------------------------


@pytest.mark.parametrize("typ", ["JWT", "at+jwt", "dpop"])
def test_typ_must_be_dpop_jwt(verifier: ProofVerifier, signer: ProofFactory, typ: str) -> None:
    """§4.3 step 4: the typ JOSE header parameter has the value dpop+jwt."""
    _refused(verifier, signer.proof("GET", URL, iat=NOW, header={"typ": typ}), "typ")


def test_typ_compares_case_insensitively(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 4 with RFC 7515 §4.1.9: typ is a media type, case-insensitive."""
    verifier.verify(
        signer.proof("GET", URL, iat=NOW, header={"typ": "DPoP+JWT"}), method="GET", url=URL
    )


# --- Step 5 ----------------------------------------------------------------


def test_alg_none_is_refused(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 5: alg is not "none"."""
    _refused(verifier, unsigned_proof("GET", URL, signer.public_jwk), "alg")


def test_a_symmetric_alg_is_refused(verifier: ProofVerifier) -> None:
    """§4.3 step 5: alg is an asymmetric algorithm — never a MAC."""
    hmac_signer = ProofFactory(OctKey.generate_key(256), algorithm="HS256")
    _refused(verifier, hmac_signer.proof("GET", URL, iat=NOW), "alg")


def test_an_asymmetric_alg_outside_the_allowlist_is_refused() -> None:
    """§4.3 step 5: alg is supported by the server."""
    strict = ProofVerifier(ProofPolicy(algorithms=frozenset({"ES256"})), clock=lambda: NOW)
    es384 = ProofFactory(ECKey.generate_key("P-384", private=True), algorithm="ES384")
    _refused(strict, es384.proof("GET", URL, iat=NOW), "alg")


def test_a_policy_cannot_allow_an_unsupported_algorithm() -> None:
    with pytest.raises(ValueError, match="HS256"):
        ProofPolicy(algorithms=frozenset({"ES256", "HS256"}))


@pytest.mark.parametrize(
    ("key", "algorithm"),
    [
        (ECKey.generate_key("P-384", private=True), "ES384"),
        (OKPKey.generate_key("Ed25519", private=True), "Ed25519"),
        (RSAKey.generate_key(2048, private=True), "PS256"),
    ],
)
def test_every_allowed_algorithm_verifies(
    verifier: ProofVerifier, key: ECKey | OKPKey | RSAKey, algorithm: str
) -> None:
    proof = ProofFactory(key, algorithm).proof("GET", URL, iat=NOW)
    assert verifier.verify(proof, method="GET", url=URL).jkt == key.thumbprint()


def test_a_key_that_does_not_fit_the_alg_is_refused(verifier: ProofVerifier) -> None:
    """§4.3 steps 5 and 6: an ES256 header over a P-384 key is a confusion attempt."""
    mismatched = ProofFactory(ECKey.generate_key("P-384", private=True), algorithm="ES384")
    proof = mismatched.proof("GET", URL, iat=NOW, header={"alg": "ES256"})
    with pytest.raises(InvalidDPoPProof):
        verifier.verify(proof, method="GET", url=URL)


@pytest.mark.filterwarnings("ignore::joserfc.errors.SecurityWarning")
def test_a_short_rsa_key_is_refused() -> None:
    weak = ProofFactory(RSAKey.generate_key(1024, private=True, auto_kid=False), "PS256")
    verifier = ProofVerifier(POLICY, clock=lambda: NOW)
    _refused(verifier, weak.proof("GET", URL, iat=NOW), "RSA")


# --- Step 6 ----------------------------------------------------------------


def test_a_forged_signature_is_refused(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 6: the JWT signature verifies with the public key in jwk."""
    head, payload, _ = signer.proof("GET", URL, iat=NOW).split(".")
    forged = ProofFactory().proof("GET", URL, iat=NOW).split(".")[2]
    _refused(verifier, f"{head}.{payload}.{forged}", "signature")


def test_a_tampered_payload_is_refused(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 6: the signature covers the claims — swap one and it fails."""
    head, _, signature = signer.proof("GET", URL, iat=NOW).split(".")
    other = b64url(json.dumps({"jti": "x", "htm": "POST", "htu": URL, "iat": NOW}).encode())
    _refused(verifier, f"{head}.{other}.{signature}", "signature")


def test_a_proof_signed_by_a_key_other_than_its_jwk_is_refused(
    verifier: ProofVerifier, signer: ProofFactory
) -> None:
    """§4.3 step 6: the key in jwk is the key that signed."""
    impostor = ProofFactory()
    proof = impostor.proof("GET", URL, iat=NOW, header={"jwk": signer.public_jwk})
    _refused(verifier, proof, "signature")


# --- Step 7 ----------------------------------------------------------------


def test_a_private_key_in_jwk_is_refused(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 7: the jwk JOSE header parameter does not contain a private key."""
    private_jwk = dict(signer.key.as_dict(private=True))
    _refused(verifier, signer.proof("GET", URL, iat=NOW, header={"jwk": private_jwk}), "private")


def test_a_jwk_that_is_not_an_object_is_refused(
    verifier: ProofVerifier, signer: ProofFactory
) -> None:
    """§4.2: jwk is a JSON Web Key — an object."""
    with pytest.raises(InvalidDPoPProof):
        verifier.verify(
            signer.proof("GET", URL, iat=NOW, header={"jwk": "key"}), method="GET", url=URL
        )


# --- Step 8 ----------------------------------------------------------------


def test_htm_must_match_the_request_method(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 8: the htm claim matches the HTTP method of the current request."""
    _refused(verifier, signer.proof("POST", URL, iat=NOW), "htm", method="GET")


def test_htm_is_case_sensitive(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 8 with RFC 9110 §9.1: methods are case-sensitive."""
    _refused(verifier, signer.proof("get", URL, iat=NOW), "htm", method="GET")


# --- Step 9 ----------------------------------------------------------------


def test_htu_must_match_the_request_uri(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 9: the htu claim matches the HTTP URI of the current request."""
    proof = signer.proof("GET", "https://api.example.test/admin", iat=NOW)
    _refused(verifier, proof, "htu")


def test_htu_on_another_host_is_refused(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 9: a proof minted for one server is useless at another."""
    proof = signer.proof("GET", "https://evil.example.test/orders", iat=NOW)
    _refused(verifier, proof, "htu")


def test_htu_ignores_query_and_fragment(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 9: "ignoring any query and fragment parts"."""
    proof = signer.proof("GET", URL, iat=NOW)
    verifier.verify(proof, method="GET", url=f"{URL}?limit=20#top")


def test_htu_must_be_a_uri(verifier: ProofVerifier, signer: ProofFactory) -> None:
    _refused(verifier, signer.proof("GET", "/orders", iat=NOW), "htu")


# --- Step 11 ---------------------------------------------------------------


def test_an_expired_proof_is_refused(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 11: iat is within an acceptable window — not older than it."""
    stale = NOW - POLICY.max_age - POLICY.clock_skew - 1
    _refused(verifier, signer.proof("GET", URL, iat=stale), "expired")


def test_a_proof_from_the_future_is_refused(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 11: iat is within an acceptable window — not ahead of it."""
    _refused(verifier, signer.proof("GET", URL, iat=NOW + POLICY.clock_skew + 1), "future")


def test_a_slightly_fast_client_clock_is_tolerated(
    verifier: ProofVerifier, signer: ProofFactory
) -> None:
    """§4.3 step 11 with §11.1: servers allow for modest clock skew."""
    verifier.verify(signer.proof("GET", URL, iat=NOW + POLICY.clock_skew), method="GET", url=URL)


def test_the_oldest_acceptable_proof_is_accepted(
    verifier: ProofVerifier, signer: ProofFactory
) -> None:
    oldest = NOW - POLICY.max_age - POLICY.clock_skew
    verifier.verify(signer.proof("GET", URL, iat=oldest), method="GET", url=URL)


# --- Step 12 ---------------------------------------------------------------


def test_ath_must_be_present_when_a_token_is_presented(
    verifier: ProofVerifier, signer: ProofFactory
) -> None:
    """§4.3 step 12 and §7: a proof sent with an access token carries ath."""
    _refused(verifier, signer.proof("GET", URL, iat=NOW), "ath", access_token="token-abc")


def test_ath_must_hash_the_presented_token(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 12: ath equals the hash of the access token presented with it."""
    proof = signer.proof("GET", URL, iat=NOW, access_token="token-abc")
    _refused(verifier, proof, "ath", access_token="token-xyz")


def test_a_matching_ath_is_accepted(verifier: ProofVerifier, signer: ProofFactory) -> None:
    proof = signer.proof("GET", URL, iat=NOW, access_token="token-abc")
    verifier.verify(proof, method="GET", url=URL, access_token="token-abc")


def test_the_proof_key_must_be_the_bound_key(verifier: ProofVerifier, signer: ProofFactory) -> None:
    """§4.3 step 12 and §6.1: the public key matches the token's cnf.jkt."""
    other_jkt = ProofFactory().jkt
    _refused(verifier, signer.proof("GET", URL, iat=NOW), "bound key", bound_jkt=other_jkt)


def test_the_bound_key_is_accepted(verifier: ProofVerifier, signer: ProofFactory) -> None:
    verifier.verify(signer.proof("GET", URL, iat=NOW), method="GET", url=URL, bound_jkt=signer.jkt)


# --- RFC 7638 ----------------------------------------------------------------


def test_thumbprints_match_the_rfc_7638_example() -> None:
    """RFC 7638 §3.1: the worked example's thumbprint, to the character."""
    jwk = {
        "kty": "RSA",
        "n": (
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc"
            "_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQ"
            "R0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bF"
            "TWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        ),
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29",
    }
    assert jwk_thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_the_verified_jkt_is_the_rfc_7638_thumbprint_of_the_jwk(
    verifier: ProofVerifier, signer: ProofFactory
) -> None:
    """§6.1: cnf.jkt is the RFC 7638 SHA-256 thumbprint of the proof's key."""
    verified = verifier.verify(signer.proof("GET", URL, iat=NOW), method="GET", url=URL)
    assert verified.jkt == jwk_thumbprint(signer.public_jwk)


def test_the_real_clock_is_used_by_default(signer: ProofFactory) -> None:
    ProofVerifier(POLICY).verify(
        signer.proof("GET", URL, iat=int(time.time())), method="GET", url=URL
    )
