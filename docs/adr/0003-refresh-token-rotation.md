# 3. Refresh tokens rotate, and reuse revokes the family

- Status: accepted
- Date: 2026-09-26

## Context

A refresh token outlives any access token by weeks. OAuth 2.1 §4.3.1 requires
refresh tokens issued to public clients to be sender-constrained or rotated.
RFC 9700 §4.14.2 describes why rotation works. When a token is used, it is
replaced. If the old one ever comes back, two parties hold the same lineage:
the legitimate client and whoever copied the token. The server cannot tell
which request is which, so the only safe move is to end the lineage for both.

DPoP already sender-constrains a public client's refresh token (RFC 9449 §5),
so rotation there is defence in depth: it matters if the DPoP private key
leaks together with the token. A confidential client's refresh token is
bound by client authentication instead, and RFC 9449 lets the client move to
a new DPoP key between refreshes.

## Decision

- Every grant creates a **`TokenFamily`**. Every refresh token and access
  token descended from it points at the family.
- A refresh **rotates**. The presented token gets `rotated_at`, and a new one
  is issued in the same family, carrying the family's original scope even
  when the new access token was narrowed (RFC 6749 §6).
- Presenting a **rotated** token revokes the family: every refresh token
  stops working, and every access token of the family introspects as
  inactive. The reason is recorded (`refresh_token_reuse`).
- The token row and the family row are locked (`SELECT … FOR UPDATE`) for the
  whole rotation, so a legitimate rotation and a reuse cannot interleave.
- The same logic covers **authorization codes** (OAuth 2.1 §4.1.3). A code is
  burned on the first attempt whatever the outcome, and a second redemption
  revokes whatever the first one produced.
- **Refusals that must leave a trace commit first.** The grant handlers return
  the error from inside the transaction and raise it only after the
  transaction has committed. Raising inside would roll the revocation back.
- A public client's refresh token is **bound to its DPoP key** (`jkt`). A
  proof from any other key is refused *without* rotating, so a thief holding
  the token but not the key cannot knock the real client off its lineage.
  Confidential clients' refresh tokens are not key-bound.
- Families have an **absolute lifetime** (30 days). Rotation extends a refresh
  token (14 days each), never the family.

## Consequences

- A client that retries a refresh after a network failure, having never seen
  the response, looks like a thief and loses the grant. This is the accepted
  cost of rotation everywhere. There is deliberately no grace period, because
  a grace period is also a window for the attacker.
- Revoking one refresh token through RFC 7009 revokes the whole grant, which
  is what §2.1 of that RFC recommends.
