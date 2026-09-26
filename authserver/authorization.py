"""Validating authorization requests and issuing authorization codes.

Validation order matters (RFC 6749 §4.1.2.1). Until the client and its
redirect URI are established, nothing may be sent to the redirect URI — doing
so would make this server an open redirector. Those failures are shown to
the user instead (``UntrustedRedirect``). Everything after that is reported
to the client by redirect (``AuthorizationError``).
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from django.contrib.auth.base_user import AbstractBaseUser
from django.utils import timezone

from authserver import pkce
from authserver.conf import server_settings
from authserver.credentials import digest, new_token
from authserver.models import AuthorizationCode, Client
from authserver.scopes import format_scope, parse_scope

_JKT_LENGTH = 43  # base64url SHA-256, as every RFC 7638 thumbprint here is
_MAX_STATE_LENGTH = 512


class UntrustedRedirect(Exception):
    """The client or redirect URI could not be established. Never redirect."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AuthorizationError(Exception):
    """An error reported to the client at its (verified) redirect URI."""

    def __init__(self, error: str, reason: str, redirect_uri: str, state: str | None) -> None:
        super().__init__(reason)
        self.error = error
        self.reason = reason
        self.redirect_uri = redirect_uri
        self.state = state


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """A validated request, waiting for the user's decision."""

    client_id: str
    redirect_uri: str
    scope: list[str]
    state: str | None
    code_challenge: str
    dpop_jkt: str | None

    def as_session_data(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_session_data(cls, data: dict[str, Any]) -> "AuthorizationRequest":
        return cls(**data)


def single_valued(lists: dict[str, list[str]]) -> tuple[dict[str, str], set[str]]:
    """Flatten request parameters, reporting any that were repeated.

    RFC 6749 §3.1: "Request and response parameters MUST NOT be included more
    than once." A repeated parameter is how parameter-pollution attacks make
    two components disagree about what was asked for.
    """
    repeated = {name for name, values in lists.items() if len(values) > 1}
    return {name: values[-1] for name, values in lists.items()}, repeated


def validate_authorization_request(
    lists: dict[str, list[str]], *, client: Client | None = None
) -> AuthorizationRequest:
    """Validate the parameters of an authorization request (OAuth 2.1 §4.1.1).

    ``client`` is passed when the parameters come from a pushed request whose
    client already authenticated (RFC 9126 §2.1).
    """
    params, repeated = single_valued(lists)

    # Stage one: establish who to talk to. Failures here are never redirected.
    if repeated & {"client_id", "redirect_uri"}:
        raise UntrustedRedirect("client_id or redirect_uri is repeated")
    client_id = params.get("client_id", "")
    if client is None:
        client = Client.objects.filter(client_id=client_id).first()
    elif client.client_id != client_id:
        raise UntrustedRedirect("client_id does not match the authenticated client")
    if client is None:
        raise UntrustedRedirect("unknown client_id")
    redirect_uri = params.get("redirect_uri", "")
    # OAuth 2.1 §2.3.1: exact string comparison against the registered URIs.
    # No prefix matching, no normalization, no wildcard — each of those has
    # been an open-redirect or code-theft CVE somewhere.
    if redirect_uri not in client.redirect_uris:
        raise UntrustedRedirect("redirect_uri is not registered for this client")

    # Stage two: report errors to the client.
    state = params.get("state")

    def fail(error: str, reason: str) -> AuthorizationError:
        return AuthorizationError(error, reason, redirect_uri, state)

    if state is not None and len(state) > _MAX_STATE_LENGTH:
        raise fail("invalid_request", "state is too long")
    if repeated:
        raise fail("invalid_request", f"repeated parameters: {sorted(repeated)}")
    if params.get("response_type") != "code":
        raise fail("unsupported_response_type", "response_type must be code")
    if not client.allows_grant(Client.GrantType.AUTHORIZATION_CODE):
        raise fail("unauthorized_client", "client may not use the authorization_code grant")

    challenge = params.get("code_challenge")
    if not challenge:
        raise fail("invalid_request", "code_challenge is required")
    # RFC 7636 §4.3: an absent method means "plain", which is refused.
    if params.get("code_challenge_method") != pkce.S256:
        raise fail("invalid_request", "code_challenge_method must be S256")
    if not pkce.is_valid_challenge(challenge):
        raise fail("invalid_request", "code_challenge is malformed")

    raw_scope = params.get("scope")
    if not raw_scope:
        raise fail("invalid_scope", "scope is required")
    try:
        scope = parse_scope(raw_scope)
    except ValueError:
        raise fail("invalid_scope", "scope is malformed") from None
    if not set(scope) <= set(client.scopes):
        raise fail("invalid_scope", "scope exceeds the client's registration")

    dpop_jkt = params.get("dpop_jkt")
    if dpop_jkt is not None and len(dpop_jkt) != _JKT_LENGTH:
        raise fail("invalid_request", "dpop_jkt is malformed")

    return AuthorizationRequest(
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=challenge,
        dpop_jkt=dpop_jkt,
    )


def redirect_url(redirect_uri: str, params: dict[str, str | None]) -> str:
    """``redirect_uri`` with ``params`` added to any query it already has.

    RFC 9207: every response carries ``iss``, so a client talking to several
    servers can tell which one answered — the defence against mix-up attacks.
    """
    parts = urlsplit(redirect_uri)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query += [(k, v) for k, v in params.items() if v is not None]
    query.append(("iss", server_settings().issuer))
    return urlunsplit(parts._replace(query=urlencode(query)))


def error_redirect(exc: AuthorizationError) -> str:
    return redirect_url(exc.redirect_uri, {"error": exc.error, "state": exc.state})


def issue_code(request: AuthorizationRequest, user: AbstractBaseUser, auth_time: datetime) -> str:
    """Create a one-time code for an approved request; return the redirect URL."""
    code = new_token()
    now = timezone.now()
    AuthorizationCode.objects.create(
        code_hash=digest(code),
        client=Client.objects.get(client_id=request.client_id),
        user_id=user.pk,
        redirect_uri=request.redirect_uri,
        scope=format_scope(request.scope),
        code_challenge=request.code_challenge,
        dpop_jkt=request.dpop_jkt or "",
        auth_time=auth_time,
        expires_at=now + timedelta(seconds=server_settings().authorization_code_ttl),
    )
    return redirect_url(request.redirect_uri, {"code": code, "state": request.state})
