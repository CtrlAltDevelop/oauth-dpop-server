"""Authorization server metadata (RFC 8414)."""

from typing import Any

from django.urls import reverse

from authserver.conf import server_settings
from authserver.keys import SIGNING_ALGORITHM

METADATA_PATH = "/.well-known/oauth-authorization-server"
JWKS_PATH = "/oauth/jwks"


def server_metadata() -> dict[str, Any]:
    conf = server_settings()
    return {
        # RFC 8414 §3.3: a client MUST check this equals the issuer it asked about.
        "issuer": conf.issuer,
        "authorization_endpoint": conf.endpoint(reverse("authserver:authorize")),
        "jwks_uri": conf.endpoint(JWKS_PATH),
        "scopes_supported": sorted(conf.scopes),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        # OAuth 2.1 §4.1.1: PKCE for every client, and only the S256 method.
        "code_challenge_methods_supported": ["S256"],
        # RFC 9207: authorization responses carry `iss`.
        "authorization_response_iss_parameter_supported": True,
        # RFC 9449 §5.1.
        "dpop_signing_alg_values_supported": sorted(conf.dpop_algorithms),
        # RFC 9068 access tokens are signed with the JWKS keys above.
        "access_token_signing_alg_values_supported": [SIGNING_ALGORITHM],
    }
