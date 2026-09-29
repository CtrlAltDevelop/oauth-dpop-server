# Security policy

This project is an authorization server, so a vulnerability here is a
vulnerability in everything that trusts its tokens. Reports are welcome and
taken seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub's
[private vulnerability reporting](https://github.com/CtrlAltDevelop/oauth-dpop-server/security/advisories/new)
("Report a vulnerability" on the Security tab).

Include what you can of:

- the component (authorization endpoint, token endpoint, DPoP verification,
  `ninja_dpop`, key handling…) and the commit or version;
- the steps or a proof of concept, ideally as a failing test;
- the impact as you see it, such as token forgery, replay, binding bypass or
  information disclosure;
- the RFC section you believe is violated, if one is.

## What to expect

- An acknowledgement within **3 working days**.
- An assessment, and a fix plan or a reasoned "not a vulnerability", within
  **14 days**.
- A fix on `main` with a regression test, a CHANGELOG entry and a GitHub
  security advisory crediting you, unless you ask not to be named.

Please give a reasonable window, 90 days by default, before disclosing
publicly, and do not test against deployments you do not own.

## Scope

In scope: this repository's code, meaning the `authserver`, `dpop`,
`ninja_dpop` and `demo_api` packages, the Docker image and the CI
configuration.

Out of scope: the limitations the README lists as not protected against
(for example a stolen DPoP private key, or revocation latency at resource
servers that validate locally); the development defaults in
`docker-compose.yml` and `.env.example`, which are not secrets; and
vulnerabilities in dependencies, which should go to their maintainers,
though a heads-up here is appreciated.

## Supported versions

Only the latest release on `main` receives security fixes.
