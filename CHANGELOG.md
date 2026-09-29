# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-29

The first release.

### Added

- Authorization Code grant with mandatory S256 PKCE, exact redirect URI
  matching, server-rendered login and consent, and `iss` in responses
  (RFC 9207).
- Client Credentials grant for confidential clients.
- Refresh tokens: opaque, stored as SHA-256 digests, and rotated on every
  use. Reuse revokes the whole token family, and a public client's refresh
  token is bound to its DPoP key.
- DPoP (RFC 9449) at the token endpoint, covering every check of §4.3, a
  Redis `jti` replay cache, server nonces with the `use_dpop_nonce` flow,
  `cnf.jkt` binding, `dpop_jkt` authorization code binding, and `token_type`
  `DPoP`.
- RFC 9068 JWT access tokens signed with ES256 keys that rotate through
  pending, active and retired; private keys are encrypted at rest.
- Authorization server metadata (RFC 8414), a JWKS endpoint, token
  introspection (RFC 7662), token revocation (RFC 7009) and pushed
  authorization requests (RFC 9126).
- A per-address rate limit on the token endpoint.
- `ninja_dpop`: a Django Ninja auth class for resource servers that checks
  the token, the proof and `ath`, and answers with `WWW-Authenticate: DPoP`
  challenges.
- An example protected orders API.
- Interop with the Dart `dpop_client`, in-process under pytest and against
  a live server in CI.
- `manage.py create_client` and `manage.py rotate_signing_keys`.
- A Docker image, a Compose stack, and CI through the shared
  `ci-workflows`.

[Unreleased]: https://github.com/CtrlAltDevelop/oauth-dpop-server/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/CtrlAltDevelop/oauth-dpop-server/releases/tag/v0.1.0
