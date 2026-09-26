"""The browser-facing half: the authorization endpoint, login and consent.

Deliberately plain server-rendered pages. The consent screen is the one an
attacker most wants to frame or pre-fill, so it relies on Django's CSRF
protection and ``X-Frame-Options: DENY`` rather than anything clever.
"""

import secrets
from typing import Any
from urllib.parse import urlsplit

from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods

from authserver.authorization import (
    AuthorizationError,
    AuthorizationRequest,
    UntrustedRedirect,
    error_redirect,
    issue_code,
    redirect_url,
    validate_authorization_request,
)
from authserver.conf import server_settings
from authserver.errors import logger
from authserver.models import Client

_SESSION_KEY = "oauth_pending_requests"
# Enough for a few tabs mid-flow; bounded so a script cannot bloat a session.
_MAX_PENDING = 5


def _stash(request: HttpRequest, auth_request: AuthorizationRequest) -> str:
    pending: dict[str, Any] = request.session.get(_SESSION_KEY, {})
    while len(pending) >= _MAX_PENDING:
        pending.pop(next(iter(pending)))
    handle = secrets.token_urlsafe(16)
    pending[handle] = auth_request.as_session_data()
    request.session[_SESSION_KEY] = pending
    return handle


def _take(request: HttpRequest, handle: str, *, remove: bool) -> AuthorizationRequest | None:
    pending: dict[str, Any] = request.session.get(_SESSION_KEY, {})
    data = pending.pop(handle, None) if remove else pending.get(handle)
    if remove:
        request.session[_SESSION_KEY] = pending
    return AuthorizationRequest.from_session_data(data) if data else None


def _error_page(request: HttpRequest, reason: str) -> HttpResponse:
    logger.info("authorization request refused without redirect: %s", reason)
    return render(request, "authserver/error.html", status=400)


@never_cache
@require_GET
def authorize(request: HttpRequest) -> HttpResponse:
    """The authorization endpoint (OAuth 2.1 §4.1.1)."""
    try:
        auth_request = validate_authorization_request(dict(request.GET.lists()))
    except UntrustedRedirect as exc:
        return _error_page(request, exc.reason)
    except AuthorizationError as exc:
        logger.info("authorization request refused: %s", exc.reason)
        return HttpResponseRedirect(error_redirect(exc))
    handle = _stash(request, auth_request)
    return redirect(f"{reverse('authserver:consent')}?request={handle}")


@never_cache
@login_required
@require_http_methods(["GET", "POST"])
def consent(request: HttpRequest) -> HttpResponse:
    """Ask the signed-in user to approve or deny a pending request."""
    handle = request.GET.get("request", "")
    auth_request = _take(request, handle, remove=request.method == "POST")
    if auth_request is None:
        return _error_page(request, "no pending authorization request")

    if request.method == "GET":
        client = Client.objects.get(client_id=auth_request.client_id)
        scopes = server_settings().scopes
        return render(
            request,
            "authserver/consent.html",
            {
                "client": client,
                "scopes": [(name, scopes.get(name, name)) for name in auth_request.scope],
                # Shown so the user can see where they are being sent back to.
                "redirect_target": urlsplit(auth_request.redirect_uri).netloc
                or auth_request.redirect_uri,
                "handle": handle,
            },
        )

    if request.POST.get("decision") != "approve":
        return HttpResponseRedirect(
            redirect_url(
                auth_request.redirect_uri, {"error": "access_denied", "state": auth_request.state}
            )
        )
    user = request.user
    if not user.is_authenticated:  # unreachable behind @login_required; narrows the type
        return _error_page(request, "not signed in")
    auth_time = user.last_login or timezone.now()
    return HttpResponseRedirect(issue_code(auth_request, user, auth_time))


class SignInView(LoginView):
    template_name = "authserver/login.html"
    redirect_authenticated_user = True
