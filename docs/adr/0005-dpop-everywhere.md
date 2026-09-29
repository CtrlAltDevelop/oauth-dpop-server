# 5. Every token is DPoP-bound, with a narrow algorithm allowlist

- Status: accepted
- Date: 2026-09-26

## Context

RFC 9449 lets a server mix DPoP-bound and bearer tokens: a client that sends
a proof gets a bound token, and one that does not gets a bearer token. Each
option has a cost.

- **Mixed mode** keeps every legacy client working. It also means every
  resource server must handle both kinds correctly, and a downgrade is always
  available to whoever strips the `DPoP` header.
- **DPoP only** removes the downgrade and halves the resource-server logic.
  The cost is that every client must be able to sign proofs.

The algorithm list is a similar trade. Every algorithm accepted is one more
code path an attacker can aim at.

## Decision

- **The token endpoint refuses any request without a valid proof.** Every
  access token carries `cnf.jkt`, and `token_type` is always `DPoP`.
  `ninja_dpop` refuses unbound tokens, and refuses bound tokens presented
  under `Bearer` (RFC 9449 §7.2).
- DPoP proofs may use **ES256, ES384, Ed25519 and PS256**. `Ed25519` is the
  RFC 9864 name for what used to be `EdDSA`. ES256 is what `dpop_client` and
  most clients sign with. RS256 is supported by the verifier but off by
  default: PKCS #1 v1.5 padding has no advantage over PSS here. MAC
  algorithms and `none` cannot be enabled at all, because the verifier has no
  code path for them. Each algorithm is pinned to its key type and curve, and
  RSA keys shorter than 2048 bits are refused.
- `htu` is compared with the endpoint URL **derived from the configured
  issuer** (authorization server) or the configured `ORIGIN` (resource
  servers). It is never compared with the request's `Host` header, which the
  client controls.

## Consequences

- Clients without DPoP support cannot use this server. For a portfolio
  project about DPoP that is the point. A deployment that needs bearer tokens
  would add a per-client flag, not a global one.
- Metadata advertises exactly what is accepted
  (`dpop_signing_alg_values_supported`), so clients do not have to guess.
