# oauth-boot-host

Embedded Valence host for uf-oauth-boot: resolve Lepton `OAuthClientConfig` from
Neutrino (mock path + first-boot env seed), then expose the handoff contract
under a session-gated Axum route.

Production L5 hosts call `resolve_oauth_config_from_neutrino` at SSR boot and
pass `Some(cfg)` into `LeptonAuthServicesBuilder::oauth`. This example proves
mock + seed resolve without the SSR/WASM / Orbital graph. The oneshot path
`/auth/oauth/boot` is a teaching stand-in for host boot; the live OAuth
callback stays `/auth/oauth/callback`.

| | |
|---|---|
| **When to use** | First smoke of Neutrino resolve → Lepton OAuth config in an embedded host |
| **Command** | `CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=target-uf-oauth-boot cargo run -p oauth-boot-host` |
| **Success** | Stdout: `oauth_boot_host: OK — mock + seed resolve + /auth/oauth/boot` |
| **Look next** | Wire `.oauth(cfg)` in an L5 host (`unified-field-site` / embedded / remote-fleet) |

**Open first:** [`src/main.rs`](src/main.rs)

## Copy into your host

| File | What to take |
|------|----------------|
| This [`Cargo.toml`](Cargo.toml) | Axum oneshot shape + `uf-oauth-boot` + Neutrino `ssr` |
| Product mount `Cargo.toml` (below) | `uf-oauth-boot` + `lepton-auth` / Neutrino pins used by your host |
| [`src/main.rs`](src/main.rs) | `store_from_valence` → resolve → optional `.oauth(cfg)` |
| Builder sketch (below) | `LeptonAuthServicesBuilder` handoff at SSR boot |

### Product mount dependencies

```toml
[dependencies]
uf-oauth-boot = { git = "https://github.com/unified-field-dev/uf-oauth-boot", rev = "REPLACE_WITH_PIN" }
lepton-auth = { /* your pin */, default-features = false, features = ["ssr"] }
neutrino = { /* your pin */, default-features = false, features = ["ssr"] }
```

### SSR boot sketch

```rust,ignore
use lepton_auth::services::LeptonAuthServicesBuilder;
use neutrino::vault::store_from_valence;
use uf_oauth_boot::resolve_oauth_config_from_neutrino;

let mut builder = LeptonAuthServicesBuilder::new().public_base_url(public_base.clone());
let store = store_from_valence(oauth_valence);
match resolve_oauth_config_from_neutrino(&store, &public_base, true).await {
    Ok(Some(cfg)) => builder = builder.oauth(cfg.into_lepton()),
    Ok(None) => {}
    Err(e) => tracing::warn!(error = %e, "OAuth Neutrino resolve skipped"),
}
```

Inventory names match stable Neutrino rows (`oauth.google.client_secret` /
`oauth.github.client_secret` under `/lepton/oauth`, kind
`oauth_client_secret`) and the Lepton callback path `/auth/oauth/callback`.
Do not log client secret values or Debug the lepton config after
`into_lepton()`.

For shell chrome (layout, fonts, Axum + Leptos boot), copy
[`shell-chrome-host`](https://github.com/unified-field-dev/unified-field-product/tree/main/examples/shell-chrome-host)
from unified-field-product, then wire the builder sketch above.

## Run (documented gate)

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-uf-oauth-boot
cargo check -p oauth-boot-host
cargo run -p oauth-boot-host
```

**Success:** stdout prints `oauth_boot_host: OK — mock + seed resolve + /auth/oauth/boot`.

## Hydrate / browser

This host is an Axum oneshot. It does not hydrate a Leptos UI and does not run
Playwright. Live OAuth in the browser needs an L5 product binary with
`cargo-leptos`, `wasm32`, Lepton auth routes, and a working Neutrino vault.
Run the oneshot above for resolve + inventory; live IdP round-trips stay on
L5 hosts / lepton-e2e.
