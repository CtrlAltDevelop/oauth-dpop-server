"""Why a proof was refused, in the vocabulary of RFC 9449 §7.1 and §8."""

from typing import ClassVar


class DPoPError(Exception):
    """A proof was refused.

    ``error`` is the RFC 9449 error code a response carries. ``reason`` says
    precisely what failed; it is for logs, never for the response body, where
    a precise reason is a free lesson in forging the next attempt.
    """

    error: ClassVar[str]

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class InvalidDPoPProof(DPoPError):
    error = "invalid_dpop_proof"


class UseDPoPNonce(DPoPError):
    """The proof lacked a nonce the server requires, or carried a stale one (§8, §9)."""

    error = "use_dpop_nonce"
