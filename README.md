# uf-oauth-boot

[![CI](https://github.com/deathbreakfast/uf-oauth-boot/actions/workflows/ci.yml/badge.svg)](https://github.com/deathbreakfast/uf-oauth-boot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[GitHub](https://github.com/deathbreakfast/uf-oauth-boot) · `cargo doc -p uf-oauth-boot --open`

`uf-oauth-boot` resolves Google and GitHub OAuth client settings from Neutrino
sealed secrets during application startup. It returns a redacted configuration
wrapper that can be passed to Lepton auth.

Existing vault rows take precedence over environment variables. An application
may also seed a missing client secret from the environment on its first run.

## Features

- **OAuth configuration resolution** — Load provider credentials from Neutrino
  and pass the result to Lepton without exposing client secrets through
  `Debug`. [Get started](#getting-started).
- **Stable secret conventions** — Use fixed names, scope, kind, and callback
  path across application code and vault administration.
  [See the storage contract](#secret-storage).

## Getting started

```toml
[dependencies]
# Pin a release tag or revision. Do not track a moving branch.
uf-oauth-boot = { git = "https://github.com/unified-field-dev/uf-oauth-boot", rev = "REPLACE_WITH_PIN" }
```

Create the Neutrino store after Valence is available, then resolve the OAuth
configuration once during server startup:

```rust,ignore
use neutrino::vault::store_from_valence;
use uf_oauth_boot::resolve_oauth_config_from_neutrino;

let store = store_from_valence(oauth_valence);
match resolve_oauth_config_from_neutrino(&store, &public_base_url, true).await {
    Ok(Some(cfg)) => builder = builder.oauth(cfg.into_lepton()),
    Ok(None) => tracing::info!("OAuth is not configured"),
    Err(e) => tracing::warn!(error = %e, "OAuth Neutrino resolve skipped"),
}
```

The third argument enables first-run seeding from
`UF_OAUTH_*_CLIENT_SECRET`. Set it to `false` when credentials must already
exist in Neutrino.

`Ok(None)` means that neither provider has a complete client ID and secret pair.
The application can continue without installing OAuth services. Errors identify
the failed vault operation and secret name without including secret plaintext.

## Configuration

| Variable | Purpose |
|----------|---------|
| `UF_OAUTH_GOOGLE_CLIENT_ID` | Public Google client ID |
| `UF_OAUTH_GOOGLE_CLIENT_SECRET` | First-run seed for the Google client secret |
| `UF_OAUTH_GITHUB_CLIENT_ID` | Public GitHub client ID |
| `UF_OAUTH_GITHUB_CLIENT_SECRET` | First-run seed for the GitHub client secret |
| `UF_OAUTH_USE_MOCK` | Enables the mock provider for tests and local development |
| `UF_MOCK_OIDC_URL` | Overrides the mock OIDC issuer URL |

Empty and whitespace-only values are treated as unset. When a sealed row
already exists, its value is loaded and the corresponding environment secret
is ignored. Rotate an existing secret through Neutrino rather than reseeding
the process environment.

With `UF_OAUTH_USE_MOCK=1` and no client-secret environment variables, the
resolver returns a mock configuration without accessing Neutrino.

## Secret storage

OAuth client secrets use the following public constants:

| Constant | Value |
|----------|-------|
| `OAUTH_GOOGLE_SECRET_NAME` | `oauth.google.client_secret` |
| `OAUTH_GITHUB_SECRET_NAME` | `oauth.github.client_secret` |
| `OAUTH_SECRET_SCOPE` | `/lepton/oauth` |
| `OAUTH_SECRET_KIND` | `oauth_client_secret` |
| `OAUTH_REDIRECT_PATH` | `/auth/oauth/callback` |

The resolver loads the newest matching row for each provider. A row with the
wrong kind returns `ResolveOAuthConfigError::WrongKind` without decrypting its
contents.

## Errors

`resolve_oauth_config_from_neutrino` returns `ResolveOAuthConfigError` for:

- failures while listing, storing, or retrieving Neutrino secrets;
- client-secret bytes that are not valid UTF-8;
- rows whose kind is not `oauth_client_secret`.

Applications where OAuth is optional can log the error once during startup and
continue without calling `builder.oauth(...)`.

## Examples

The [`oauth-boot-host`](examples/oauth-boot-host/) example exercises the mock
provider, first-run seeding, and the Lepton handoff:

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-uf-oauth-boot
cargo run -p oauth-boot-host
```

Success prints:

```text
oauth_boot_host: OK — mock + seed resolve + /auth/oauth/boot
```

See [`examples/README.md`](examples/README.md) for the runnable example index and
[`examples/oauth-boot-host/README.md`](examples/oauth-boot-host/README.md) for
the complete dependency and startup setup.

## Security

Keep client secrets in Neutrino sealed rows. Public client IDs may come from the
environment. Do not log secret values, and do not format the Lepton
`OAuthClientConfig` returned by `into_lepton()` with `Debug`; that upstream type
contains plaintext secret fields.

OAuth protocol handling, callback routes, PKCE, and CSRF checks are provided by
`lepton-auth`. See [`SECURITY.md`](SECURITY.md) for reporting instructions and
the full secret-handling contract.

## Development

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-uf-oauth-boot
cargo fmt -p uf-oauth-boot -p oauth-boot-host -- --check
cargo clippy -p uf-oauth-boot --all-targets -- -D warnings
cargo clippy -p oauth-boot-host --all-targets -- -D warnings
cargo test -p uf-oauth-boot
cargo check -p oauth-boot-host
cargo run -p oauth-boot-host | tee /tmp/oauth-boot-host.out
grep -F 'oauth_boot_host: OK — mock + seed resolve + /auth/oauth/boot' /tmp/oauth-boot-host.out
RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc -p uf-oauth-boot --no-deps
```

[`docs/VERIFICATION.md`](docs/VERIFICATION.md) describes the CI checks and local
prerequisites. Live provider tests run in applications that supply OAuth routes
and a working Neutrino vault.

## License

MIT. See [LICENSE](LICENSE).
