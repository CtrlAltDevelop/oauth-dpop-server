# ninja_dpop

A Django Ninja auth class for resource servers that accept **DPoP-bound
access tokens** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) in the
JWT profile of [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068).

It depends only on the project's framework-free `dpop` package, Django,
Django Ninja, `joserfc` and Redis. Nothing ties it to this authorization
server, so it can protect any Ninja API whose tokens come from an issuer
that publishes a JWKS.

## Use

```python
from ninja import NinjaAPI
from ninja_dpop import DPoPAuth, DPoPPrincipal, install

api = NinjaAPI(auth=DPoPAuth())
install(api)  # turns refusals into WWW-Authenticate: DPoP challenges


@api.get("/orders", auth=DPoPAuth(scopes=["orders:read"]))
def orders(request):
    principal: DPoPPrincipal = request.auth
    return list_orders_for(principal.subject)
```

`request.auth` is a `DPoPPrincipal` with `subject`, `client_id`, `scopes`,
`jkt` (the key the token is bound to) and the full `claims`.

## Configure

```python
NINJA_DPOP = {
    "ISSUER": "https://auth.example.com",
    "AUDIENCE": "https://api.example.com",
    "ORIGIN": "https://api.example.com",  # what htu is checked against
    "JWKS": "https://auth.example.com/oauth/jwks",  # or a dotted callable
    "REDIS": "myproject.redis.get_redis",  # callable returning redis.Redis
    # Optional, defaults shown:
    "ALGORITHMS": ["ES256"],  # accepted DPoP proof algorithms
    "TOKEN_ALGORITHMS": ["ES256"],  # accepted access token algorithms
    "PROOF_MAX_AGE": 60,
    "CLOCK_SKEW": 5,
    "REQUIRE_NONCE": False,
    "NONCE_ROTATION": 300,
    "JWKS_CACHE_SECONDS": 300,
}
```

Set `ORIGIN` in production. Without it the origin is rebuilt from the
request's `Host` header, which is only as trustworthy as `ALLOWED_HOSTS`
and whatever proxy sits in front.

## What is checked, in order

1. `Authorization: DPoP <token>` is present. `Bearer` is refused outright
   with `invalid_token`, because a bound token presented as a bearer token is
   either a confused client or someone hoping the proof goes unchecked
   (§7.2).
2. The token is an `at+jwt`, signed by a key in the issuer's JWKS under an
   allowed algorithm, with the exact `iss`, an `aud` naming this API, a
   current `exp`/`iat`/`nbf`, a `sub`, and a `cnf.jkt` (RFC 9068 §4,
   RFC 9449 §6.1).
3. The `DPoP` proof passes every step of RFC 9449 §4.3. That includes `ath`
   matching this exact token, a signature from the `cnf.jkt` key, and a
   `jti` never seen before (replay cache in Redis).
4. The token grants every scope the operation declares.

## Responses

| Situation | Status | `WWW-Authenticate` |
|---|---|---|
| No credentials | 401 | `DPoP algs="ES256"` (no error, RFC 6750 §3.1) |
| Bad, expired or Bearer-presented token | 401 | `DPoP error="invalid_token", …` |
| Missing or bad proof, replay, wrong key, bad `ath` | 401 | `DPoP error="invalid_dpop_proof", …` |
| Nonce required (`REQUIRE_NONCE`) | 401 | `DPoP error="use_dpop_nonce", …`, plus a `DPoP-Nonce` header |
| Scope missing | 403 | `DPoP error="insufficient_scope", scope="…", …` |

Error descriptions are fixed per error code. The precise reason stays in
the exception's `reason`, for your logs.

## Key rotation

Keys fetched from a JWKS URL are cached for `JWKS_CACHE_SECONDS`. A token
whose `kid` is not in the cache triggers one early refetch, at most once
every 30 seconds, so invented `kid`s cannot be used to flood the issuer.
`ninja_dpop.jwks.clear_cache()` forgets everything, for use after an
emergency rotation.
