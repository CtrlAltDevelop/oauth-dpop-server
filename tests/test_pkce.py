"""RFC 7636 — the S256 transformation and verifier checks."""

import pytest

from authserver import pkce


def test_s256_matches_the_rfc_7636_appendix_b_example() -> None:
    """RFC 7636 Appendix B: the worked S256 example."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce.s256(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_the_right_verifier_passes() -> None:
    verifier = "a" * 43
    assert pkce.verify(verifier, pkce.s256(verifier))


def test_the_wrong_verifier_fails() -> None:
    assert not pkce.verify("a" * 43, pkce.s256("b" * 43))


@pytest.mark.parametrize(
    "verifier",
    [
        "a" * 42,  # §4.1: at least 43 characters
        "a" * 129,  # §4.1: at most 128
        "a" * 42 + "!",  # outside the unreserved set
    ],
)
def test_malformed_verifiers_fail_even_if_they_hash_right(verifier: str) -> None:
    assert not pkce.verify(verifier, pkce.s256(verifier))


def test_the_challenge_itself_is_not_a_verifier() -> None:
    """Sending the challenge back as the verifier is what "plain" would allow."""
    challenge = pkce.s256("a" * 43)
    assert not pkce.verify(challenge, challenge)
