# Contributing

Thanks for taking the time. This is an authorization server, so the bar for
changes is correctness first and cleverness never.

## Setup

```bash
make install   # uv sync --all-groups
make check     # ruff, format check, mypy --strict, pytest
```

The suite needs no services: SQLite and fakeredis by default. Set
`DATABASE_URL` to run it on Postgres as CI does. For the Dart interop test,
install the Dart SDK and check out
[`dpop_client`](https://github.com/CtrlAltDevelop/dpop_client) next to this
repository.

## Rules of the road

- **Standards first.** A behaviour that an RFC specifies cites the section,
  in a comment or docstring, and has a test whose docstring names the same
  section. Deviations are deliberate, explained, and recorded in an ADR under
  `docs/adr/`.
- **No hand-rolled cryptography.** JOSE goes through `joserfc`, and
  primitives through `cryptography`. Secrets are compared with
  `hmac.compare_digest`.
- **Errors stay uniform.** Error descriptions sent to clients never say which
  check failed; the precise reason goes to the log.
- **Negative tests.** A new check comes with a test that the thing it forbids
  is refused.
- **Types and lint are gates, not suggestions.** `mypy --strict` and ruff
  must pass. Prefer fixing the cause over `# type: ignore` or `# noqa`, and
  justify any you keep.
- **Dependencies.** Add them with `uv add`, then run `make requirements`. CI
  installs from `requirements.txt` and fails if it disagrees with `uv.lock`.
- **Never commit** keys, secrets, `.env` files or databases. Signing keys are
  generated at runtime and live encrypted in the database.

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
  `fix:`, `test:`, `docs:`, `refactor:`, `build:`, `ci:`, `chore:`, with a
  short imperative subject in plain English.
- One coherent change per commit, each one passing `make check`.
- Update `CHANGELOG.md` under *Unreleased* for anything user-visible.

Security issues go through [SECURITY.md](SECURITY.md), not pull requests or
issues.
