# 2. Replay defence: jti, iat and server nonces, all three

- Status: accepted
- Date: 2026-09-26

## Context

A DPoP proof is a signed statement: "the holder of this key wants to do
`htm` on `htu`, now". RFC 9449 gives a server three tools for making sure
"now" really is now. Each closes a different gap, and no two of them cover
everything.

| Mechanism | Stops | Does not stop |
|---|---|---|
| `iat` window (§4.3 step 11) | A proof captured yesterday and replayed today. | A replay a few seconds after capture, inside the window. Proofs **pre-generated** with a future `iat` by someone who briefly had the key (an XSS payload, a compromised dependency). |
| `jti` replay cache (§11.1) | Any second use of the same proof inside the window. | Pre-generated proofs, each of which is unique. Without `iat` bounding it, the cache would have to remember forever. |
| Server nonce (§8, §9) | Pre-generation: a proof cannot carry a nonce the server had not yet issued. | Replays of a proof made after the nonce was issued, which is why `jti` is still needed. |

`iat` bounds the replay cache, which makes `jti` affordable. `jti` closes the
window that `iat` leaves open. The nonce removes the attacker's ability to
mint proofs in advance, which neither of the others addresses.

## Decision

- **`iat`** must fall within `[now - PROOF_MAX_AGE - CLOCK_SKEW, now +
  CLOCK_SKEW]`: 60 s of age and 5 s of skew by default. This check always
  applies. RFC 9449 allows a server to use the nonce *instead* of `iat` for
  freshness; this server uses both, because the nonce's lifetime (up to
  10 minutes) is far longer than the proof's.
- **`jti`** is recorded in Redis with one atomic `SET NX EX`, so two
  concurrent copies of a proof cannot both win. The TTL is exactly the
  window in which the proof could still pass the `iat` check:
  `PROOF_MAX_AGE + 2 × CLOCK_SKEW`. Keys are the SHA-256 of `jkt:jti`, which
  makes them bounded in size and scoped per client key, so one client cannot
  spend another's `jti` values. The `jti` is recorded **last**, after every
  other check has passed, so a refused proof spends nothing.
- **Nonces** are required at the token endpoint by default
  (`OAUTH_DPOP_REQUIRE_NONCE`), and optional at resource servers
  (`NINJA_DPOP["REQUIRE_NONCE"]`). A nonce is random, lives in Redis, is
  current for `NONCE_ROTATION` seconds and valid for twice that. A client
  holding the previous nonce is not refused the moment it rotates. The
  current nonce goes out in a `DPoP-Nonce` header on every token-endpoint
  response, success or failure, so rotation never costs the client an extra
  round trip. An unknown or expired nonce gets the same `use_dpop_nonce`
  answer as a missing one. The authorization server and resource servers
  keep separate nonce namespaces.

## Consequences

- Every token request costs one extra round trip the first time a client
  talks to the server: `400 use_dpop_nonce`, then a retry. `dpop_client`
  documents exactly this loop, and the interop test exercises it.
- Redis is a hard dependency. Losing it loses the replay cache, and a server
  that forgets which proofs it has seen accepts every replay inside the
  window. There is deliberately no in-memory fallback for production.
- A client whose clock is more than `CLOCK_SKEW` seconds out is refused.
  Its fix is the clock. Widening the window weakens the defence for every
  client.
