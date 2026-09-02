# Security Policy

## Supported versions

Security fixes are accepted against the latest `0.1.x` line of `uf-oauth-boot`.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

Prefer one of the following:

1. **GitHub Security Advisories** — use [Report a vulnerability](https://github.com/unified-field-dev/uf-oauth-boot/security/advisories/new) on this repository when available.
2. Contact the maintainers privately via the repository owner listed at https://github.com/unified-field-dev/uf-oauth-boot.

Include:

- a description of the issue and its impact
- steps to reproduce or a proof of concept when possible
- affected crate names and versions

We will acknowledge receipt as soon as practical and coordinate a fix and disclosure timeline with you.

## Scope

In scope: this crate's resolve helper, teaching host, and docs, including defaults that could leak OAuth client secrets.

Out of scope: OAuth protocol, PKCE, and CSRF in `lepton-auth`; Neutrino vault UI and Gauge authorization; vulnerabilities solely in third-party dependencies unless this project mishandles them.

## OAuth client secrets

`resolve_oauth_config_from_neutrino` loads Neutrino sealed rows named
`oauth.google.client_secret` / `oauth.github.client_secret` under
`/lepton/oauth`. Public client ids come from env (`UF_OAUTH_*_CLIENT_ID`).
Client secrets stay in Neutrino (or a first-boot env seed that writes a sealed
row).

A sealed row with kind `oauth_client_secret` becomes a Lepton
`OAuthClientConfig` via `ResolvedOAuthClientConfig::into_lepton`.

Missing a usable id+secret pair returns `Ok(None)` (OAuth stays off). The
latest name+scope row with a different kind returns
`ResolveOAuthConfigError::WrongKind` and does not call Neutrino `get`.

An existing sealed row always wins over `UF_OAUTH_*_CLIENT_SECRET` when
`seed_from_env` is true. Rotate through Neutrino, not by reseeding env.

## Leakage

`ResolveOAuthConfigError` Display includes the stable secret **name** and, for
`WrongKind`, the observed kind. It must not include client-secret plaintext.
`ResolvedOAuthClientConfig` Debug prints `<redacted>` for secret fields.

Do not log env secret values, Debug the lepton `OAuthClientConfig` after
`into_lepton()`, or print teaching-host JSON that contains plaintext.
Tracing on resolve records `operation` and `outcome` only.

`lepton-auth`'s `OAuthClientConfig` still derives Debug with secret fields.
That type is owned by lepton-auth.

## Teaching host

`oauth-boot-host` is an Axum oneshot. `/auth/oauth/boot` requires the
`x-demo-user` header and returns inventory **names**, not secret values. It is
not a production route and does not implement Higgs session or live OAuth.

## Master key

Tests and the teaching host set `NEUTRINO_MASTER_KEY` to a local fixture.
Production hosts must follow Neutrino's master-key rules (64 hex characters).
