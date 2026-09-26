"""RFC 9449 §8 and §11.1 — server nonces and jti replay detection."""

import fakeredis
import pytest

from dpop.errors import InvalidDPoPProof, UseDPoPNonce
from dpop.nonce import RedisNonceStore
from dpop.proof import ProofPolicy, ProofVerifier
from dpop.replay import RedisReplayCache
from tests.proofs import ProofFactory

URL = "https://auth.example.test/oauth/token"
NOW = 1_800_000_000
ALGS = frozenset({"ES256"})


@pytest.fixture
def signer() -> ProofFactory:
    return ProofFactory()


@pytest.fixture
def nonces(fake_redis: fakeredis.FakeRedis) -> RedisNonceStore:
    return RedisNonceStore(fake_redis, rotation=300)


def _verifier(
    redis: fakeredis.FakeRedis,
    *,
    nonces: RedisNonceStore | None = None,
    require_nonce: bool = False,
) -> ProofVerifier:
    return ProofVerifier(
        ProofPolicy(algorithms=ALGS, require_nonce=require_nonce),
        replay_cache=RedisReplayCache(redis),
        nonces=nonces,
        clock=lambda: NOW,
    )


# --- jti replay (§11.1) ----------------------------------------------------


def test_a_replayed_proof_is_refused_even_inside_its_time_window(
    fake_redis: fakeredis.FakeRedis, signer: ProofFactory
) -> None:
    """§11.1: the server tracks jti values and rejects one it has already seen."""
    verifier = _verifier(fake_redis)
    proof = signer.proof("POST", URL, iat=NOW)
    verifier.verify(proof, method="POST", url=URL)
    with pytest.raises(InvalidDPoPProof, match="already been used"):
        verifier.verify(proof, method="POST", url=URL)


def test_a_reused_jti_in_a_freshly_signed_proof_is_still_a_replay(
    fake_redis: fakeredis.FakeRedis, signer: ProofFactory
) -> None:
    """§4.2: jti is unique per proof — re-signing does not make it new."""
    verifier = _verifier(fake_redis)
    verifier.verify(signer.proof("POST", URL, iat=NOW, jti="same"), method="POST", url=URL)
    with pytest.raises(InvalidDPoPProof, match="already been used"):
        verifier.verify(signer.proof("POST", URL, iat=NOW - 1, jti="same"), method="POST", url=URL)


def test_jti_values_are_scoped_to_the_signing_key(fake_redis: fakeredis.FakeRedis) -> None:
    """One client cannot pre-spend another client's jti values."""
    verifier = _verifier(fake_redis)
    for _ in range(2):
        proof = ProofFactory().proof("POST", URL, iat=NOW, jti="shared")
        verifier.verify(proof, method="POST", url=URL)


def test_a_refused_proof_does_not_spend_its_jti(
    fake_redis: fakeredis.FakeRedis, signer: ProofFactory
) -> None:
    verifier = _verifier(fake_redis)
    with pytest.raises(InvalidDPoPProof):
        verifier.verify(signer.proof("GET", URL, iat=NOW, jti="j1"), method="POST", url=URL)
    verifier.verify(signer.proof("POST", URL, iat=NOW, jti="j1"), method="POST", url=URL)


def test_a_jti_is_remembered_for_exactly_the_replay_window(
    fake_redis: fakeredis.FakeRedis, signer: ProofFactory
) -> None:
    """§11.1: remembered as long as the proof could pass the iat check."""
    policy = ProofPolicy(algorithms=ALGS, max_age=60, clock_skew=5)
    verifier = ProofVerifier(policy, replay_cache=RedisReplayCache(fake_redis), clock=lambda: NOW)
    verifier.verify(signer.proof("POST", URL, iat=NOW), method="POST", url=URL)
    [key] = fake_redis.keys("dpop:jti:*")
    assert fake_redis.ttl(key) == policy.replay_window == 70


# --- nonces (§8) -------------------------------------------------------------


def test_a_proof_without_a_required_nonce_asks_for_one(
    fake_redis: fakeredis.FakeRedis, nonces: RedisNonceStore, signer: ProofFactory
) -> None:
    """§8: the server rejects a proof lacking a nonce with use_dpop_nonce."""
    verifier = _verifier(fake_redis, nonces=nonces, require_nonce=True)
    with pytest.raises(UseDPoPNonce) as caught:
        verifier.verify(signer.proof("POST", URL, iat=NOW), method="POST", url=URL)
    assert caught.value.error == "use_dpop_nonce"


def test_a_proof_with_the_current_nonce_is_accepted(
    fake_redis: fakeredis.FakeRedis, nonces: RedisNonceStore, signer: ProofFactory
) -> None:
    """§8: the nonce claim carries the value from the DPoP-Nonce header."""
    verifier = _verifier(fake_redis, nonces=nonces, require_nonce=True)
    proof = signer.proof("POST", URL, iat=NOW, nonce=nonces.current())
    assert verifier.verify(proof, method="POST", url=URL).nonce == nonces.current()


def test_an_invented_nonce_asks_for_a_real_one(
    fake_redis: fakeredis.FakeRedis, nonces: RedisNonceStore, signer: ProofFactory
) -> None:
    """§4.3 step 10: the nonce claim matches the server-provided nonce value."""
    verifier = _verifier(fake_redis, nonces=nonces, require_nonce=True)
    proof = signer.proof("POST", URL, iat=NOW, nonce="made-up-nonce-value-1234")
    with pytest.raises(UseDPoPNonce):
        verifier.verify(proof, method="POST", url=URL)


def test_a_nonce_that_is_not_a_string_is_refused(
    fake_redis: fakeredis.FakeRedis, nonces: RedisNonceStore, signer: ProofFactory
) -> None:
    verifier = _verifier(fake_redis, nonces=nonces)
    proof = signer.proof("POST", URL, iat=NOW, claims={"nonce": 42})
    with pytest.raises(InvalidDPoPProof, match="nonce"):
        verifier.verify(proof, method="POST", url=URL)


def test_an_optional_nonce_is_still_checked_when_sent(
    fake_redis: fakeredis.FakeRedis, nonces: RedisNonceStore, signer: ProofFactory
) -> None:
    verifier = _verifier(fake_redis, nonces=nonces, require_nonce=False)
    verifier.verify(signer.proof("POST", URL, iat=NOW), method="POST", url=URL)
    with pytest.raises(UseDPoPNonce):
        verifier.verify(
            signer.proof("POST", URL, iat=NOW, nonce="stale-nonce-value-00000"),
            method="POST",
            url=URL,
        )


def test_a_server_that_issues_no_nonces_ignores_the_claim(
    fake_redis: fakeredis.FakeRedis, signer: ProofFactory
) -> None:
    """§4.3 step 10 applies only "if the server provided a nonce value"."""
    verifier = _verifier(fake_redis)
    verifier.verify(
        signer.proof("POST", URL, iat=NOW, nonce="from-some-other-server"), method="POST", url=URL
    )


def test_a_policy_requiring_nonces_needs_a_store(fake_redis: fakeredis.FakeRedis) -> None:
    with pytest.raises(ValueError, match="nonce store"):
        _verifier(fake_redis, require_nonce=True)


def test_the_current_nonce_is_stable_between_rotations(nonces: RedisNonceStore) -> None:
    assert nonces.current() == nonces.current()


def test_a_nonce_outlives_its_rotation(
    fake_redis: fakeredis.FakeRedis, nonces: RedisNonceStore
) -> None:
    """A client holding the previous nonce is not refused the moment it rotates."""
    old = nonces.current()
    fake_redis.delete("dpop:nonce:current")  # what expiry of the rotation key does
    new = nonces.current()
    assert new != old
    assert nonces.is_valid(old)
    assert nonces.is_valid(new)
    assert fake_redis.ttl(f"dpop:nonce:valid:{new}") == 600


@pytest.mark.parametrize("bad", ["", "short", "has spaces in it....", "x" * 65, "a:b" * 8])
def test_malformed_nonces_are_never_valid(nonces: RedisNonceStore, bad: str) -> None:
    assert not nonces.is_valid(bad)


def test_concurrent_rotation_converges_on_one_nonce(
    fake_redis: fakeredis.FakeRedis, nonces: RedisNonceStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two workers that both find no current nonce end up handing out the same one."""
    real_get = fake_redis.get
    reads = iter([None])

    def racing_get(key: str) -> object:
        # The first read misses; meanwhile another worker publishes its nonce.
        value = next(reads, "unset")
        if value is None:
            fake_redis.set("dpop:nonce:current", "won-by-another-worker-123")
            return None
        return real_get(key)

    monkeypatch.setattr(fake_redis, "get", racing_get)
    assert nonces.current() == "won-by-another-worker-123"
