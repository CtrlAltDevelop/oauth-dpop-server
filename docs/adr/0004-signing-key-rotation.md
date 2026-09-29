# 4. Signing keys rotate through pending, active and retired

- Status: accepted
- Date: 2026-09-26

## Context

Resource servers verify access tokens against the JWKS and cache it. Rotating
the signing key naively breaks one of two things:

- **Too early.** The new key signs tokens before resource servers have
  fetched it. They see an unknown `kid` and refuse valid tokens.
- **Too late.** The old key leaves the JWKS while tokens it signed are still
  unexpired. They fail verification before their `exp`.

## Decision

Keys move through three published states. `manage.py rotate_signing_keys`
advances every key one step:

```text
pending ──rotate──► active ──rotate──► retired ──retention──► deleted
```

- **pending**: published in the JWKS, not yet signing. It sits there for a
  whole rotation period, so every resource server has it cached before the
  first token carries its `kid`.
- **active**: signs every new token. A partial unique index on the table
  enforces exactly one.
- **retired**: signs nothing, still published for `OAUTH_SIGNING_KEY_RETENTION`
  seconds. That defaults to the access-token lifetime plus an hour, longer
  than any token it signed can live.

During overlap the JWKS therefore holds three keys: retired, active and
pending.

Further choices:

- **ES256** (P-256), generated with `cryptography` through `joserfc`. The
  `kid` is the key's RFC 7638 thumbprint: stable, unique, and derived from the
  key itself.
- **Private keys are encrypted at rest** with Fernet, under a key derived by
  HKDF-SHA256 from `OAUTH_KEY_ENCRYPTION_SECRET`. A database dump alone
  cannot mint tokens. Keys are generated at runtime, never committed, and
  never leave the database unencrypted.
- **First start bootstraps** an active and a pending key, since nothing is
  cached anywhere yet. Two workers bootstrapping at once converge through the
  unique index.
- `ninja_dpop` caches the JWKS for `JWKS_CACHE_SECONDS` (300 s). An unknown
  `kid` triggers one early refetch, rate-limited to once every 30 s, so invented
  `kid` values cannot make a resource server hammer the issuer.

## Consequences

- Rotation must run **less often than resource servers refresh their cache**,
  or a pending key could become active before it is cached. Daily rotation
  against a five-minute cache has a wide margin.
- Emergency rotation (a leaked key) is one run of the command, which retires
  the leaked key and activates the already-cached pending key, followed by
  **deleting the leaked key's row**. While a key is published, retired or
  not, anyone holding its private half can mint tokens that verify. Deleting
  it invalidates every token it signed, legitimate ones included, and resource
  servers stop accepting them once their cache expires, or at once after
  `ninja_dpop.jwks.clear_cache()`.
- There is no HSM or KMS integration; see the README's known limitations.
