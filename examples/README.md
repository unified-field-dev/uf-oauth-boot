# Examples

Runnable teaching hosts for this product. Each card: when to use · command ·
success · look next. Copy `Cargo.toml` + `main.rs` (and the product mount
snippets in the host README) into your composite host.

## Canonical path

### `oauth-boot-host` — mock + seed resolve → builder handoff

**Teaches:** `store_from_valence` → `resolve_oauth_config_from_neutrino` (mock
and first-boot env seed), then `into_lepton()` for
`LeptonAuthServicesBuilder::oauth`. Stable Neutrino names, kind
`oauth_client_secret`, and `/lepton/oauth` match the public API. This host is
an Axum oneshot; it does not hydrate a browser UI.

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-uf-oauth-boot
cargo run -p oauth-boot-host
```

**Success:** stdout prints `oauth_boot_host: OK — mock + seed resolve + /auth/oauth/boot`.

**Next step:** Wire `.oauth(cfg)` in an L5 host (site / embedded / remote-fleet).
Copy table + product mount `Cargo.toml`: [`oauth-boot-host/README.md`](oauth-boot-host/README.md).

| Host | When to use | Command | Success | Look next |
|------|-------------|---------|---------|-----------|
| [`oauth-boot-host`](oauth-boot-host/) | Neutrino resolve → OAuth config | `cargo run -p oauth-boot-host` | Mock + seed + boot route | L5 host with `LeptonAuthServicesBuilder::oauth` |
