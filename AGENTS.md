# AGENTS.md — oauth-dpop-server

Canonical instructions for any AI agent or human working in this repo.
`CLAUDE.md` is a pointer only; new rules go **here**.

A small OAuth 2.1 authorization server whose every access token is sender-constrained with DPoP
([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)). Packages: `authserver/`, `dpop/`, `ninja_dpop/`, `demo_api/`, `interop/`.
Read `README.md`, `CONTRIBUTING.md` and `SECURITY.md` first.

## Commands (`make help` lists all)

- `make check` — lint, mypy strict, tests (SQLite + fakeredis, no services needed): what CI runs.
- `make test-postgres` — the suite against Postgres at `$DATABASE_URL`.
- `make interop` — the Dart `dpop_client` against a live server (needs Dart, Redis, `../dpop_client`).
- `make requirements` — regenerate `requirements.txt` from `uv.lock`; CI's `lockfile` job fails if you forget.

## Rules

- Follow the RFC to the letter: proof validation, `htm`/`htu`/`iat`/`jti`/`ath`, server nonces, `cnf.jkt` binding. A shortcut here is a security bug.
- A token without a valid proof from the bound key must be rejected, always.
- Never log tokens, proofs, or private keys. Signing keys rotate `pending -> active -> retired` (`make keys`).
- Security-relevant changes get a test that fails without the fix.
- CI workflows are reusable ones from `CtrlAltDevelop/ci-workflows`; change checks there, not here.
