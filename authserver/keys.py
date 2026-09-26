"""Access-token signing keys: generation, rotation and the published JWKS.

Rotation is a three-stage pipeline so no resource server ever meets a ``kid``
it has not cached, and no valid token outlives the key that verifies it::

    pending ──rotate──► active ──rotate──► retired ──retention──► deleted

A key is published while ``pending``, one full rotation period before it
signs anything. When it is retired it stays published for
``signing_key_retention`` seconds — longer than any token it signed can live.
At any moment the JWKS therefore holds up to three keys.

Private keys are encrypted at rest with a Fernet key derived (HKDF-SHA256)
from ``OAUTH_KEY_ENCRYPTION_SECRET``, so a database dump alone cannot mint
tokens.
"""

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.db import IntegrityError, transaction
from django.utils import timezone
from joserfc import jwt
from joserfc.jwk import ECKey, KeySetSerialization

from authserver.conf import server_settings
from authserver.models import SigningKey

SIGNING_ALGORITHM = "ES256"
_CURVE = "P-256"
_HKDF_INFO = b"oauth-dpop-server/signing-key-encryption/v1"


def _fernet() -> Fernet:
    secret = server_settings().key_encryption_secret.encode("utf-8")
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(secret)
    return Fernet(base64.urlsafe_b64encode(derived))


def _generate(state: SigningKey.State, now: datetime) -> SigningKey:
    key = ECKey.generate_key(_CURVE, private=True)
    # The RFC 7638 thumbprint makes a stable, collision-free kid for free.
    kid = key.thumbprint()
    public_jwk = {**key.as_dict(private=False), "kid": kid, "use": "sig", "alg": SIGNING_ALGORITHM}
    return SigningKey.objects.create(
        kid=kid,
        algorithm=SIGNING_ALGORITHM,
        state=state,
        public_jwk=public_jwk,
        private_key_encrypted=_fernet().encrypt(key.as_pem(private=True)),
        created_at=now,
        activated_at=now if state == SigningKey.State.ACTIVE else None,
    )


def _load_private(record: SigningKey) -> ECKey:
    pem = _fernet().decrypt(bytes(record.private_key_encrypted))
    return ECKey.import_key(pem, {"kid": record.kid})


def _active_record() -> SigningKey:
    record = SigningKey.objects.filter(state=SigningKey.State.ACTIVE).first()
    if record is not None:
        return record
    # First start: nothing is published yet, so there is no cache to warm and
    # the very first key may sign immediately.
    try:
        with transaction.atomic():
            now = timezone.now()
            record = _generate(SigningKey.State.ACTIVE, now)
            _generate(SigningKey.State.PENDING, now)
            return record
    except IntegrityError:
        # Another worker bootstrapped between our read and our insert.
        return SigningKey.objects.get(state=SigningKey.State.ACTIVE)


def sign_jwt(header: dict[str, Any], claims: dict[str, Any]) -> str:
    """Sign ``claims`` with the active key, adding ``alg`` and ``kid``."""
    record = _active_record()
    protected = {**header, "alg": record.algorithm, "kid": record.kid}
    return jwt.encode(protected, claims, _load_private(record), algorithms=[record.algorithm])


def published_jwks() -> KeySetSerialization:
    """The JWK Set resource servers verify access tokens against."""
    _active_record()
    cutoff = timezone.now() - timedelta(seconds=server_settings().signing_key_retention)
    keys = SigningKey.objects.exclude(
        state=SigningKey.State.RETIRED, retired_at__lt=cutoff
    ).order_by("created_at")
    return {"keys": [dict(record.public_jwk) for record in keys]}


@dataclass(frozen=True, slots=True)
class RotationResult:
    activated: str
    retired: str | None
    pending: str
    deleted: list[str]


@transaction.atomic
def rotate(now: datetime | None = None) -> RotationResult:
    """Advance every key one stage along the pipeline.

    Run it on a schedule (``manage.py rotate_signing_keys``) no more often
    than resource servers refresh their JWKS cache, so the pending key they
    are about to need is always already in it.
    """
    now = now or timezone.now()
    keys = list(SigningKey.objects.select_for_update().order_by("created_at"))
    active = next((k for k in keys if k.state == SigningKey.State.ACTIVE), None)
    pending = next((k for k in reversed(keys) if k.state == SigningKey.State.PENDING), None)

    if active is not None:
        # Retire first: the partial unique index allows one active key only.
        active.state = SigningKey.State.RETIRED
        active.retired_at = now
        active.save(update_fields=["state", "retired_at"])

    if pending is None:
        pending = _generate(SigningKey.State.ACTIVE, now)
    else:
        pending.state = SigningKey.State.ACTIVE
        pending.activated_at = now
        pending.save(update_fields=["state", "activated_at"])

    next_pending = _generate(SigningKey.State.PENDING, now)

    cutoff = now - timedelta(seconds=server_settings().signing_key_retention)
    expired = SigningKey.objects.filter(state=SigningKey.State.RETIRED, retired_at__lt=cutoff)
    deleted = list(expired.values_list("kid", flat=True))
    expired.delete()

    return RotationResult(
        activated=pending.kid,
        retired=active.kid if active else None,
        pending=next_pending.kid,
        deleted=deleted,
    )
