# uf-oauth-boot verification

Re-run after code or doc changes. This workspace is a single host-boot helper
crate plus a teaching host: resolve Lepton `OAuthClientConfig` from Neutrino
sealed secrets (optional env seed). It has no Leptos UI or IsolatedLab host of
its own — L5 hosts exercise live OAuth wiring. The teaching host is an Axum
oneshot (`oauth-boot-host`), not a hydrate UI.

## Regression layers

| Layer | What it covers | Where it runs |
|-------|----------------|---------------|
| **This CI** | fmt, clippy `-D warnings`, lib + integ tests (`resolve_oauth_config`, surface contracts), teaching-host check/run + OK-line assert, rustdoc link deny | `.github/workflows/ci.yml` on `deathbreakfast/uf-oauth-boot` (PR + `main`) |
| **Teaching host** | Mock + env seed resolve, session-gated `/auth/oauth/boot` oneshot, inventory JSON (no secret echo) | CI `test` job + local `cargo run -p oauth-boot-host` |
| **Out of this crate** | Live Google/GitHub OAuth, hydrate UI, Playwright / lepton-e2e, AWS campaign | L5 product hosts (`unified-field-site`, embedded, remote-fleet) |

Browser / provider E2E is intentionally **not** enabled here: there is no operator UI
or product binary in this repo. Merging to `main` on this crate is gated by the
Layer 1 table above once sibling clones authenticate (see below).

## Environment

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-uf-oauth-boot
```

## CI sibling clones (required for clippy / test / docs)

Path patches expect a Unified Field monorepo tree. Jobs clone deathbreakfast
siblings via [`.github/scripts/clone-uf-siblings.sh`](../.github/scripts/clone-uf-siblings.sh).

Private forks (`lepton`, `gauge`, `neutrino`, `unified-field-product`,
`lepton-uf-app`, `record-history`, …) need a PAT. Set repo secret **`UF_CI_CLONE_TOKEN`**
(Contents: Read on those repos):

```bash
gh secret set UF_CI_CLONE_TOKEN --repo deathbreakfast/uf-oauth-boot
```

Without that secret, jobs fail at clone with exit 128 (`could not
read Username`). `Cargo.toml` path-patches private `record-history` so Cargo
does not need `unified-field-dev` git credentials for that dep.

## Rustdoc policy

Workspace `Cargo.toml` denies `rustdoc::broken_intra_doc_links`. Local and CI:

```bash
cargo doc -p uf-oauth-boot --no-deps
```

CI still sets `RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links"` as a belt-and-suspenders
check. `#![deny(missing_docs)]` is on for this crate; workspace clippy also denies
`missing_errors_doc` and `missing_panics_doc`.

## Teaching host

Axum oneshot under [`examples/oauth-boot-host`](../examples/oauth-boot-host/).

```bash
cargo check -p oauth-boot-host
cargo run -p oauth-boot-host
```

**Success:** stdout prints `oauth_boot_host: OK — mock + seed resolve + /auth/oauth/boot`.
CI greps that line after `cargo run`.

Hydrate / browser OAuth is out of gate (needs an L5 product binary + lepton-e2e).

## Unit + integration (CI)

GitHub Actions (`.github/workflows/ci.yml`) covers Layer 1 above. Local mirror:

```bash
cargo fmt -p uf-oauth-boot -p oauth-boot-host -- --check
cargo clippy -p uf-oauth-boot --all-targets -- -D warnings
cargo clippy -p oauth-boot-host --all-targets -- -D warnings
cargo test -p uf-oauth-boot
cargo check -p oauth-boot-host
cargo run -p oauth-boot-host | tee /tmp/oauth-boot-host.out
grep -F 'oauth_boot_host: OK — mock + seed resolve + /auth/oauth/boot' /tmp/oauth-boot-host.out
RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc -p uf-oauth-boot --no-deps
```

Named integ suite: `tests/resolve_oauth_config.rs` (unconfigured / mock+OIDC /
seed / vault-load / seed=false / wrong-kind / InvalidUtf8 / Get / List /
latest-row / Debug redaction / store-err leak / tracing outcomes).
Host sync: `workspace_members` / `product_surface` (included in `cargo test -p uf-oauth-boot`).

No `deny.toml` in this repo — `cargo deny` is not part of the gate. Live OAuth
against real providers stays on L5 hosts. Playwright is not in this gate: this
crate has no operator UI.
