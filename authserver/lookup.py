"""Finding the server's record of a token presented back to it.

Introspection and revocation are handed a token string of unknown kind. An
access token is recognised by verifying it as one of our JWTs — never by
trusting an unverified ``jti`` — and anything else is looked up by digest as
a refresh token.
"""

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from authserver.conf import server_settings
from authserver.credentials import digest
from authserver.keys import SIGNING_ALGORITHM, published_jwks
from authserver.models import AccessToken, RefreshToken
from authserver.tokens import ACCESS_TOKEN_TYP


def find_access_token(token: str) -> AccessToken | None:
    # A compact JWS has exactly two dots and a refresh token has none. The
    # cheap check keeps arbitrary strings away from the JOSE parser.
    if token.count(".") != 2:
        return None
    try:
        decoded = jwt.decode(
            token, KeySet.import_key_set(published_jwks()), algorithms=[SIGNING_ALGORITHM]
        )
    except (JoseError, ValueError):
        return None
    if decoded.header.get("typ") != ACCESS_TOKEN_TYP:
        return None
    if decoded.claims.get("iss") != server_settings().issuer:
        return None
    jti = decoded.claims.get("jti")
    if not isinstance(jti, str):
        return None
    return AccessToken.objects.select_related("client", "family").filter(jti=jti).first()


def find_refresh_token(token: str) -> RefreshToken | None:
    return (
        RefreshToken.objects.select_related("family", "family__client")
        .filter(token_hash=digest(token))
        .first()
    )
