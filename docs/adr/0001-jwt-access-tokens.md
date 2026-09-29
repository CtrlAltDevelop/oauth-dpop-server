# 1. Access tokens are JWTs; refresh tokens are opaque

- Status: accepted
- Date: 2026-09-26

## Context

A resource server has two ways to learn what an access token means. It can
validate a self-contained token locally (a JWT, RFC 9068), or it can ask the
authorization server about an opaque one (introspection, RFC 7662).

- **Local validation** costs a signature check and no network, and the
  authorization server can be down without taking every API with it. The
  price is revocation: a signed token stays valid until it expires, whatever
  the authorization server later decides.
- **Introspection** gives instant revocation. It also puts the authorization
  server on the hot path of every API call, and makes it a single point of
  failure and a latency floor.

DPoP changes the calculation. A DPoP-bound token is useless without the
private key it is bound to (`cnf.jkt`), so a leaked token on its own is no
longer something that has to be revoked at once. Instant revocation is worth
less than it is for bearer tokens.

Refresh tokens are different. Only the authorization server ever reads them,
and they must be revocable: they are the grant.

## Decision

- **Access tokens are JWTs** in the RFC 9068 profile (`typ: at+jwt`, `iss`,
  `sub`, `aud`, `client_id`, `exp`, `iat`, `jti`, `scope`, plus `cnf.jkt`),
  signed with ES256. They live for **five minutes**
  (`OAUTH_ACCESS_TOKEN_TTL`).
- The server **keeps a row per issued access token** (`AccessToken`), keyed by
  `jti`. Resource servers never read it. It exists so that introspection and
  revocation give true answers.
- **Refresh tokens are opaque** 256-bit random strings, stored only as SHA-256
  digests. They are useless outside this server, and they die the moment their
  row says so.

## Consequences

- Revoking an access token (RFC 7009) takes effect at once for anyone who
  introspects. A resource server validating locally keeps accepting it until
  `exp`, at most five minutes away. This is stated in the README's threat
  model rather than papered over.
- Revoking a grant revokes its refresh tokens at once, so the damage window
  after revocation is bounded by one access-token lifetime.
- Resource servers need the JWKS and a key-rotation story; see ADR 0004.
- A deployment that needs instant revocation everywhere can have its resource
  servers introspect every token. Nothing in the token format prevents it.
