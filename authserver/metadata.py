"""Authorization server metadata (RFC 8414)."""

from typing import Any

from authserver.conf import server_settings
from authserver.keys import SIGNING_ALGORITHM

METADATA_PATH = "/.well-known/oauth-authorization-server"
JWKS_PATH = "/oauth/jwks"


def server_metadata() -> dict[str, Any]:
    conf = server_settings()
    return {
        # RFC 8414 §3.3: a client MUST check this equals the issuer it asked about.
        "issuer": conf.issuer,
        "jwks_uri": conf.endpoint(JWKS_PATH),
        "scopes_supported": sorted(conf.scopes),
        # RFC 9449 §5.1.
        "dpop_signing_alg_values_supported": sorted(conf.dpop_algorithms),
        # RFC 9068 access tokens are signed with the JWKS keys above.
        "access_token_signing_alg_values_supported": [SIGNING_ALGORITHM],
    }
