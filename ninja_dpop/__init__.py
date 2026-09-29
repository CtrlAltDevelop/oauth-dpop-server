"""Protect Django Ninja operations with DPoP-bound access tokens (RFC 9449).

::

    from ninja import NinjaAPI
    from ninja_dpop import DPoPAuth, install

    api = NinjaAPI(auth=DPoPAuth())
    install(api)

See ``ninja_dpop.conf`` for the ``NINJA_DPOP`` setting.
"""

from ninja_dpop.auth import DPoPAuth, DPoPPrincipal
from ninja_dpop.errors import DPoPAuthError, install

__all__ = ["DPoPAuth", "DPoPAuthError", "DPoPPrincipal", "install"]
