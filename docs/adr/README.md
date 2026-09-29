# Architecture decision records

| # | Decision |
|---|---|
| [0001](0001-jwt-access-tokens.md) | Access tokens are JWTs; refresh tokens are opaque |
| [0002](0002-replay-defence.md) | Replay defence: jti, iat and server nonces, all three |
| [0003](0003-refresh-token-rotation.md) | Refresh tokens rotate, and reuse revokes the family |
| [0004](0004-signing-key-rotation.md) | Signing keys rotate through pending, active and retired |
| [0005](0005-dpop-everywhere.md) | Every token is DPoP-bound, with a narrow algorithm allowlist |
