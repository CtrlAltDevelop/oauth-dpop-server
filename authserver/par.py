"""Pushed Authorization Requests (RFC 9126).

The client sends its authorization parameters straight to the server over an
authenticated back channel and gets a one-time ``request_uri`` to put in the
browser redirect instead. The parameters can then be neither read nor
tampered with in the front channel, and a confidential client's request is
authenticated before the user ever sees it.

With DPoP (RFC 9449 §10.1), a proof on the push binds the eventual code to
the proof's key, exactly as ``dpop_jkt`` would.
"""

from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from authserver.authorization import (
    AuthorizationError,
    AuthorizationRequest,
    UntrustedRedirect,
    validate_authorization_request,
)
from authserver.conf import server_settings
from authserver.credentials import constant_time_equals, digest, new_token
from authserver.errors import OAuthError
from authserver.models import Client, PushedAuthorizationRequest
from dpop import VerifiedProof

REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"


def push(
    client: Client, lists: dict[str, list[str]], proof: VerifiedProof | None
) -> tuple[str, int]:
    """Validate and store a pushed request; return its ``request_uri`` and lifetime."""
    if "request_uri" in lists:
        # RFC 9126 §2.1: a pushed request must not itself point elsewhere.
        raise OAuthError("invalid_request", "request_uri may not be pushed")
    if proof is not None:
        committed = lists.get("dpop_jkt")
        if committed is not None and not constant_time_equals(committed[-1], proof.jkt):
            raise OAuthError("invalid_dpop_proof", "dpop_jkt differs from the proof key")
        lists = {**lists, "dpop_jkt": [proof.jkt]}
    # The client authenticated, so client_id in the body is optional (§2.1).
    lists = {"client_id": [client.client_id], **lists}
    try:
        validated = validate_authorization_request(lists, client=client)
    except UntrustedRedirect as exc:
        raise OAuthError("invalid_request", exc.reason) from exc
    except AuthorizationError as exc:
        raise OAuthError(exc.error, exc.reason) from exc

    ttl = server_settings().par_ttl
    handle = new_token()
    PushedAuthorizationRequest.objects.create(
        request_uri_hash=digest(handle),
        client=client,
        parameters=validated.as_session_data(),
        expires_at=timezone.now() + timedelta(seconds=ttl),
    )
    return f"{REQUEST_URI_PREFIX}{handle}", ttl


@transaction.atomic
def redeem(client_id: str, request_uri: str) -> AuthorizationRequest:
    """Swap a ``request_uri`` for the request it stands for, once (RFC 9126 §4).

    Every failure is an ``UntrustedRedirect``: without the pushed parameters
    there is no verified redirect URI to report an error to.
    """
    if not request_uri.startswith(REQUEST_URI_PREFIX):
        raise UntrustedRedirect("request_uri is not one this server issued")
    handle = request_uri.removeprefix(REQUEST_URI_PREFIX)
    record = (
        PushedAuthorizationRequest.objects.select_for_update()
        .select_related("client")
        .filter(request_uri_hash=digest(handle))
        .first()
    )
    if record is None or not constant_time_equals(record.client.client_id, client_id):
        raise UntrustedRedirect("unknown request_uri, or one pushed by another client")
    if record.used_at is not None:
        raise UntrustedRedirect("request_uri already used")
    if record.expires_at <= timezone.now():
        raise UntrustedRedirect("request_uri expired")
    record.used_at = timezone.now()
    record.save(update_fields=["used_at"])
    return AuthorizationRequest.from_session_data(record.parameters)
