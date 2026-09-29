# oauth-dpop-server

[![CI](https://github.com/CtrlAltDevelop/oauth-dpop-server/actions/workflows/ci.yml/badge.svg)](https://github.com/CtrlAltDevelop/oauth-dpop-server/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A small, standards-exact **OAuth 2.1 authorization server** whose every
access token is **sender-constrained with DPoP**
([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)). A token lifted from a
log, a proxy or a browser extension is inert without the private key it is
bound to.

It is the server-side counterpart of
[`dpop_client`](https://github.com/CtrlAltDevelop/dpop_client), the Dart
package that signs DPoP proofs, and CI runs that client against this server
on every push.

Django 5.2, Django Ninja, PostgreSQL, Redis and `joserfc`. There are no
hand-rolled cryptographic primitives.

## What it does

- **Authorization Code with mandatory PKCE.** S256 only; `plain` is refused.
  Redirect URIs match exactly. Login and consent are server-rendered, CSRF-
  and frame-protected, and responses carry `iss` (RFC 9207).
- **Client Credentials** for service-to-service calls.
- **Refresh tokens**: opaque, hashed at rest, rotated on every use. Reuse
  revokes the whole family.
- **DPoP everywhere**: the full RFC 9449 §4.3 checklist, `jti` replay cache,
  server nonces with the `use_dpop_nonce` flow, `cnf.jkt` binding by RFC 7638
  thumbprint, `dpop_jkt` authorization code binding (§10), and `token_type`
  `DPoP`.
- **JWT access tokens** in the RFC 9068 profile, signed with ES256 keys that
  rotate through *pending → active → retired*, several at once in the JWKS.
- **Metadata** (RFC 8414), **Introspection** (RFC 7662), **Revocation**
  (RFC 7009) and **Pushed Authorization Requests** (RFC 9126).
- **`ninja_dpop`**: a reusable Django Ninja auth class for resource servers.
  It validates the token, the proof and `ath`, with RFC-shaped
  `WWW-Authenticate: DPoP` errors. See [its README](ninja_dpop/README.md).
- **Rate limiting** on `/token`, constant-time comparisons for every secret,
  and error descriptions that never say *which* check failed.

## The DPoP flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (dpop_client)
    participant AS as Authorization server
    participant R as Redis
    participant RS as Resource server (ninja_dpop)

    Note over C: generates an ES256 key pair once;<br/>the private key never leaves the device
    C->>AS: POST /oauth/token<br/>DPoP: proof{htm, htu, iat, jti}
    AS->>R: nonce current?
    AS-->>C: 400 use_dpop_nonce<br/>DPoP-Nonce: n1
    C->>AS: POST /oauth/token<br/>DPoP: proof{…, nonce: n1}
    AS->>AS: verify typ, alg, jwk is public, signature,<br/>htm, htu, iat window, nonce
    AS->>R: SET jkt:jti NX EX 70 (replay cache)
    AS-->>C: 200 {access_token: JWT{cnf.jkt = thumbprint(jwk)},<br/>token_type: "DPoP", refresh_token}<br/>DPoP-Nonce: n1
    C->>RS: GET /api/orders<br/>Authorization: DPoP <token><br/>DPoP: proof{…, ath = SHA-256(token)}
    RS->>RS: verify token (JWKS, iss, aud, exp, cnf.jkt)
    RS->>RS: verify proof: key = cnf.jkt, ath matches, htm/htu
    RS->>R: SET jkt:jti NX EX 70
    RS-->>C: 200 orders
    Note over C,RS: a stolen token without the key fails at the proof step,<br/>and a replayed proof fails at the jti step
```

## Quickstart

With Docker:

```bash
docker compose up --build -d
docker compose exec web python manage.py createsuperuser
docker compose exec web python manage.py create_client "My service" \
    --grant client_credentials --scope orders:read --scope orders:write
curl -s localhost:8000/.well-known/oauth-authorization-server | jq
```

Locally, with [uv](https://docs.astral.sh/uv/) and a Redis on `localhost:6379`:

```bash
make install
make run               # migrations, then runserver on :8000 (SQLite)
```

Register an app that signs users in:

```bash
DJANGO_DEBUG=true uv run python manage.py create_client "Mobile app" --type public \
    --grant authorization_code --grant refresh_token \
    --redirect-uri com.example.app:/oauth2redirect --scope profile --scope orders:read
```

A confidential client's secret is printed once and stored only as a digest.
Signing keys are generated on first use and encrypted in the database. Rotate
them on a schedule with `make keys` (`manage.py rotate_signing_keys`).

### Getting a token from Dart

```dart
final client = DPoPClient(DPoPKeyPair.generate());
final basic = 'Basic ${base64.encode(utf8.encode('$clientId:$clientSecret'))}';
final tokenUrl = Uri.parse('https://auth.example.com/oauth/token');

var proof = client.createProof(url: tokenUrl, method: 'POST');
var response = await http.post(tokenUrl, headers: {...proof.headers(), 'Authorization': basic},
    body: {'grant_type': 'client_credentials'});

// 400 use_dpop_nonce: retry with the nonce the server just sent.
proof = client.createProof(url: tokenUrl, method: 'POST',
    nonce: response.headers['dpop-nonce']);
response = await http.post(tokenUrl, headers: {...proof.headers(), 'Authorization': basic},
    body: {'grant_type': 'client_credentials'});
```

The full program, with the API calls and the negative checks, is
[`interop/dart/bin/interop.dart`](interop/dart/bin/interop.dart).

## Endpoints

| Endpoint | Method | Spec | Notes |
|---|---|---|---|
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 | Includes `dpop_signing_alg_values_supported`. |
| `/oauth/jwks` | GET | RFC 7517 | Pending, active and retired keys. |
| `/oauth/authorize` | GET | OAuth 2.1 §4.1.1, RFC 9126 §4 | `response_type=code`, S256 PKCE, optional `dpop_jkt`, or a PAR `request_uri`. |
| `/oauth/login`, `/oauth/consent` | GET, POST | | Server-rendered; CSRF-protected; `X-Frame-Options: DENY`. |
| `/oauth/par` | POST | RFC 9126 | A `DPoP` proof here binds the code to its key (RFC 9449 §10.1). |
| `/oauth/token` | POST | OAuth 2.1 §3.2, RFC 9449 §5 | `authorization_code`, `refresh_token`, `client_credentials`. Proof required. Rate-limited. |
| `/oauth/introspect` | POST | RFC 7662 | Confidential clients; returns `cnf.jkt` and `token_type: DPoP`. |
| `/oauth/revoke` | POST | RFC 7009 | A refresh token revokes its whole grant. |
| `/oauth/docs` | GET | | OpenAPI docs for the endpoints above. |
| `/api/me`, `/api/orders` | GET, POST | RFC 9449 §7 | The example resource server (`demo_api`), behind `ninja_dpop`. |

Client authentication: `client_secret_basic` and `client_secret_post` for
confidential clients, and `none` for public clients, which rely on PKCE and
DPoP instead.

## Standards, section by section, test by test

Every MUST in RFC 9449 §4.3 has its own test, with the step number in the
docstring. File paths are relative to `tests/`.

| RFC | Section | Requirement | Tests |
|---|---|---|---|
| 9449 | §4.3 step 1 | At most one `DPoP` header | `dpop/test_proof.py::test_more_than_one_dpop_header_is_refused`, `::test_folded_dpop_headers_are_refused`, `test_token_endpoint.py::test_two_dpop_headers_are_refused` |
| 9449 | §4.3 step 2 | A well-formed JWT | `dpop/test_proof.py::test_a_proof_that_is_not_a_jwt_is_refused`, `::test_a_payload_that_is_not_an_object_is_refused` |
| 9449 | §4.3 step 3, §4.2 | `typ`, `alg`, `jwk`, `jti`, `htm`, `htu`, `iat` present | `dpop/test_proof.py::test_every_required_member_must_be_present`, `::test_iat_must_be_an_integer` |
| 9449 | §4.3 step 4 | `typ` is `dpop+jwt` | `dpop/test_proof.py::test_typ_must_be_dpop_jwt`, `::test_typ_compares_case_insensitively` |
| 9449 | §4.3 step 5 | Asymmetric, supported, not `none` | `dpop/test_proof.py::test_alg_none_is_refused`, `::test_a_symmetric_alg_is_refused`, `::test_an_asymmetric_alg_outside_the_allowlist_is_refused`, `::test_a_key_that_does_not_fit_the_alg_is_refused` |
| 9449 | §4.3 step 6 | The signature verifies with `jwk` | `dpop/test_proof.py::test_a_forged_signature_is_refused`, `::test_a_tampered_payload_is_refused`, `::test_a_proof_signed_by_a_key_other_than_its_jwk_is_refused` |
| 9449 | §4.3 step 7 | `jwk` is not a private key | `dpop/test_proof.py::test_a_private_key_in_jwk_is_refused` |
| 9449 | §4.3 step 8 | `htm` matches | `dpop/test_proof.py::test_htm_must_match_the_request_method`, `::test_htm_is_case_sensitive`, `test_resource_server.py::test_a_proof_for_the_wrong_method_is_refused` |
| 9449 | §4.3 step 9 | `htu` matches, ignoring query and fragment | `dpop/test_htu.py` (RFC 3986 §6.2 normalization), `dpop/test_proof.py::test_htu_must_match_the_request_uri`, `test_token_endpoint.py::test_htu_is_checked_against_the_issuer_not_the_host_header` |
| 9449 | §4.3 step 10, §8 | The server nonce, when provided | `dpop/test_replay_and_nonce.py::test_a_proof_without_a_required_nonce_asks_for_one`, `::test_an_invented_nonce_asks_for_a_real_one`, `test_token_endpoint.py::test_a_request_without_a_nonce_is_told_to_use_one` |
| 9449 | §4.3 step 11 | `iat` within the window | `dpop/test_proof.py::test_an_expired_proof_is_refused`, `::test_a_proof_from_the_future_is_refused`, `::test_a_slightly_fast_client_clock_is_tolerated` |
| 9449 | §4.3 step 12 | `ath` matches; key matches `cnf.jkt` | `dpop/test_proof.py::test_ath_must_hash_the_presented_token`, `::test_the_proof_key_must_be_the_bound_key`, `test_resource_server.py::test_a_proof_from_a_key_other_than_cnf_jkt_is_refused` |
| 9449 | §5 | `token_type` `DPoP`; public clients' refresh tokens are key-bound | `test_token_endpoint.py::test_a_code_is_exchanged_for_a_dpop_bound_token`, `::test_a_public_clients_refresh_token_is_bound_to_its_dpop_key`, `test_refresh.py::test_a_public_clients_refresh_needs_a_proof_from_the_bound_key` |
| 9449 | §5.1 | `dpop_signing_alg_values_supported` | `test_metadata.py::test_metadata_advertises_the_dpop_algorithms_the_server_accepts` |
| 9449 | §6.1 | `cnf.jkt` is the RFC 7638 thumbprint | `test_token_endpoint.py::test_the_access_token_is_bound_to_the_proof_key_by_thumbprint`, `dpop/test_proof.py::test_thumbprints_match_the_rfc_7638_example` |
| 9449 | §6.2 | Introspection shows the binding | `test_introspection_revocation.py::test_an_active_access_token_is_described_with_its_dpop_binding` |
| 9449 | §7.1 | `Authorization: DPoP`, `WWW-Authenticate: DPoP algs=…` | `test_resource_server.py::test_no_credentials_gets_a_bare_challenge`, `::test_a_token_without_a_proof_is_refused` |
| 9449 | §7.2 | A bound token is never accepted as Bearer | `test_resource_server.py::test_a_bound_token_presented_as_bearer_is_refused` |
| 9449 | §9 | Resource server nonces | `test_resource_server.py::test_a_resource_server_requiring_nonces_says_so_and_accepts_the_retry` |
| 9449 | §10, §10.1 | `dpop_jkt` and PAR binding | `test_token_endpoint.py::test_dpop_jkt_from_the_authorization_request_must_match_the_proof`, `test_par.py::test_a_dpop_proof_on_the_push_binds_the_code_to_its_key` |
| 9449 | §11.1 | `jti` replay detection | `dpop/test_replay_and_nonce.py::test_a_replayed_proof_is_refused_even_inside_its_time_window`, `::test_a_jti_is_remembered_for_exactly_the_replay_window`, `test_resource_server.py::test_a_replayed_proof_is_refused` |
| 7636 | §4.2, App. B | S256 transformation | `test_pkce.py::test_s256_matches_the_rfc_7636_appendix_b_example` |
| OAuth 2.1 | §4.1.1 | PKCE required; `plain` refused | `test_authorize.py::test_a_missing_code_challenge_is_refused`, `::test_the_plain_pkce_method_is_refused`, `::test_an_absent_pkce_method_is_refused_because_it_means_plain` |
| OAuth 2.1 | §2.3.1, §4.1.2.1 | Exact redirect URI; never redirect to an unverified one | `test_authorize.py::test_a_redirect_uri_that_is_not_exactly_registered_is_never_redirected_to` |
| OAuth 2.1 | §4.1.3 | One-time codes; reuse revokes | `test_token_endpoint.py::test_a_code_can_be_redeemed_once_and_reuse_revokes_what_it_issued` |
| OAuth 2.1 | §4.3.1; RFC 9700 §4.14.2 | Refresh rotation, reuse detection | `test_refresh.py::test_a_refresh_rotates_the_token`, `::test_reusing_a_rotated_refresh_token_revokes_the_whole_family` |
| 6749 | §3.1 | No repeated parameters | `test_authorize.py::test_a_repeated_parameter_is_refused`, `test_token_endpoint.py::test_a_repeated_parameter_is_refused` |
| 9068 | §2, §4 | JWT access token profile | `test_token_endpoint.py::test_the_access_token_follows_the_rfc_9068_profile`, `test_resource_server.py::test_tokens_outside_the_rfc_9068_profile_are_refused` |
| 9207 | §2 | `iss` in authorization responses | `test_authorize.py::test_an_approved_request_returns_a_code_state_and_issuer` |
| 8414 | §2, §3 | Metadata | `test_metadata.py` |
| 7662 | §2.1, §2.2, §4 | Introspection | `test_introspection_revocation.py::test_introspection_requires_client_authentication`, `::test_a_client_learns_nothing_about_another_clients_tokens` |
| 7009 | §2.1, §2.2 | Revocation | `test_introspection_revocation.py::test_revoking_a_refresh_token_revokes_the_whole_grant`, `::test_revoking_an_unknown_token_succeeds` |
| 9126 | §2, §4 | PAR | `test_par.py` |
| — | — | Interop with `dpop_client` | `interop/test_dart_client.py` (skipped without the Dart SDK) |

## Threat model

**Protected against:**

- **Stolen access tokens** (logs, proxies, browser storage, a compromised
  resource server). Every token is bound to a key through `cnf.jkt`, and every
  use needs a fresh proof signed by that key.
- **Stolen refresh tokens.** A public client's refresh token is bound to its
  key. A confidential client's needs client authentication. Any token
  presented after rotation revokes the whole grant.
- **Proof replay.** Inside the `iat` window, the `jti` cache stops it
  (atomic, per key). Outside it, `iat` does. Pre-generated proofs are stopped
  by the server nonce (ADR 0002).
- **Proofs aimed at another endpoint or server.** `htm` and `htu` are checked
  against the URL derived from configuration, never from the `Host` header.
  `ath` ties each proof to one token.
- **Authorization code interception.** S256 PKCE is mandatory, codes are
  single-use and live 60 s, and reuse revokes what the code produced.
  `dpop_jkt` and PAR can bind the code to the client's key.
- **Open redirects and code leakage through redirects.** Redirect URIs match
  exactly, and nothing is ever redirected to before the client and redirect
  URI are verified.
- **Mix-up attacks.** `iss` goes in every authorization response (RFC 9207).
- **Clickjacking and CSRF on consent**: `X-Frame-Options: DENY` and Django's
  CSRF protection.
- **Credential theft from the database.** Client secrets, codes, refresh
  tokens and PAR handles are stored as SHA-256 digests, and signing keys are
  encrypted.
- **Oracles.** Comparisons are constant-time, unknown clients take the same
  path as wrong secrets, error descriptions are uniform, and introspection and
  revocation answer another client's tokens as if they were unknown.
- **Online guessing at `/token`**, through a per-address rate limit.
- **Algorithm confusion.** `none` and MACs cannot be enabled at all, each
  algorithm is pinned to its key type and curve, and short RSA keys are
  refused.

**Not protected against:**

- **A stolen DPoP private key.** DPoP binds tokens to a key; it cannot tell
  the key's owner from someone who copied it. Keep it in the platform
  keystore, as `dpop_client` advises. Nonces limit how far ahead a thief can
  work, and rotation limits how long a stolen refresh token lives, but neither
  helps while the thief has live access.
- **A compromised client device or app** that signs proofs on the attacker's
  behalf.
- **Revocation at resource servers that validate locally.** A revoked access
  token is accepted until it expires, at most five minutes (ADR 0001).
  Resource servers that need instant revocation must introspect.
- **Loss of Redis.** Without the replay cache, replays inside the window
  succeed. There is deliberately no fallback.
- **Phishing of the user's password** on a look-alike login page. Nothing
  here offers phishing-resistant authentication.
- **A compromised host**, or a leaked `OAUTH_KEY_ENCRYPTION_SECRET` together
  with the database.
- **Volumetric denial of service.** The rate limit only slows guessing.

## Configuration

Everything is set through the environment (see [`.env.example`](.env.example))
or Django settings. The `OAUTH_*` settings are listed in
[`authserver/conf.py`](authserver/conf.py) and the `NINJA_DPOP` settings in
[`ninja_dpop/conf.py`](ninja_dpop/conf.py).

| Setting | Default | |
|---|---|---|
| `OAUTH_ISSUER` | `http://localhost:8000` | The issuer identifier. Every `htu` at this server is checked against it. |
| `OAUTH_ACCESS_TOKEN_TTL` | 300 s | |
| `OAUTH_REFRESH_TOKEN_TTL` / `OAUTH_REFRESH_FAMILY_TTL` | 14 / 30 days | Per token, and the absolute lifetime of a grant. |
| `OAUTH_DPOP_ALGORITHMS` | ES256, ES384, Ed25519, PS256 | |
| `OAUTH_DPOP_PROOF_MAX_AGE` / `OAUTH_DPOP_CLOCK_SKEW` | 60 s / 5 s | |
| `OAUTH_DPOP_REQUIRE_NONCE` | true | |
| `OAUTH_TOKEN_RATE_LIMIT` / `OAUTH_TOKEN_RATE_WINDOW` | 60 per 60 s | Per client address. |
| `OAUTH_KEY_ENCRYPTION_SECRET` | `DJANGO_SECRET_KEY` | Set it separately in production. |

## Development

```bash
make check         # ruff, ruff format --check, mypy --strict, pytest
make test-postgres # the suite against Postgres at $DATABASE_URL
make interop       # the Dart client against a real server and Redis
```

The suite runs on SQLite with fakeredis by default, and on Postgres whenever
`DATABASE_URL` is set, as CI does. The interop test runs when the Dart SDK is
on `PATH` and [`dpop_client`](https://github.com/CtrlAltDevelop/dpop_client)
is checked out next to this repository.

Layout:

```text
authserver/   the authorization server (Django app)
dpop/         RFC 9449 proof verification, replay cache, nonces (no Django)
ninja_dpop/   the resource-server auth class for Django Ninja
demo_api/     an example protected API
interop/dart/ the dpop_client interop program
docs/adr/     architecture decision records
```

## Known limitations

- **No OpenID Connect.** There are no ID tokens, no `userinfo` and no
  discovery beyond RFC 8414.
- **No dynamic client registration** (RFC 7591). Clients are registered with
  `manage.py create_client` or the admin.
- **One audience.** Resource indicators (RFC 8707) are not implemented, so
  every token's `aud` is `OAUTH_ACCESS_TOKEN_AUDIENCE`.
- **DPoP only.** There is no bearer-token fallback and no mTLS (RFC 8705);
  see ADR 0005.
- **Consent is not remembered.** Every authorization asks again.
- **Login is not rate-limited or MFA-protected.** It is a stand-in for a real
  identity provider.
- **Signing keys live in the database**, encrypted, rather than in an HSM or
  KMS.
- **The rate limit keys on `REMOTE_ADDR`.** Behind a proxy, that must be set
  to the real client address.
- **Nonces are required for every client** at the token endpoint when
  enabled; there is no per-client policy.

## Related

- [`dpop_client`](https://github.com/CtrlAltDevelop/dpop_client): DPoP proofs
  for Dart and Flutter, the client this server is tested against.
- [`ci-workflows`](https://github.com/CtrlAltDevelop/ci-workflows): the shared
  CI this repository calls.

## License

[MIT](LICENSE) © 2026 Mohammad Zarif
