//! Resolve Lepton OAuth client configuration from Neutrino sealed secrets at host boot.
//!
//! OAuth client secrets live in Neutrino under stable names and scope paths. This crate
//! loads those rows (or seeds them once from env), builds [`lepton_auth::oauth::OAuthClientConfig`],
//! and returns a [`ResolvedOAuthClientConfig`] wrapper whose [`Debug`] output redacts secrets.
//! Protocol work (PKCE, CSRF, callback routes) stays in `lepton-auth`; vault UI and Gauge
//! authz stay in Neutrino and Gauge.
//!
//! ## Start here
//!
//! 1. [Resolve OAuth config at SSR boot](#resolve-oauth-config-at-ssr-boot) — call
//!    [`resolve_oauth_config_from_neutrino`], then `into_lepton()`.
//! 2. [Stable secret vocabulary](#stable-secret-vocabulary) and [Env contract](#env-contract) —
//!    names hosts and operators share.
//! 3. [Concern → API](#concern--api) — public symbols by job.
//! 4. Workspace example `oauth-boot-host` — Axum oneshot; see crate `SECURITY.md` for leak rules.
//!
//! ## Features
//!
//! - **OAuth config resolver** — Loads Google/GitHub client secrets from Neutrino (with optional
//!   first-boot env seed) and hands a Lepton-ready config to `LeptonAuthServicesBuilder::oauth`.
//!   Call once at SSR host boot after the Neutrino store is available.
//!   [Get started](#resolve-oauth-config-at-ssr-boot)
//! - **Stable Neutrino secret vocabulary** — Canonical secret names, `/lepton/oauth` scope,
//!   `oauth_client_secret` kind, and callback redirect path for vault rows and operators.
//!   [Get started](#stable-secret-vocabulary)
//! - **Redacted config wrapper** — [`ResolvedOAuthClientConfig`] hides client secrets from
//!   [`Debug`] while preserving plaintext for [`ResolvedOAuthClientConfig::into_lepton`].
//! - **Typed resolve failures** — [`ResolveOAuthConfigError`] names the Neutrino operation and
//!   stable secret name without echoing ciphertext in [`std::fmt::Display`].
//!
//! ## Resolve OAuth config at SSR boot
//!
//! At SSR host boot, after Valence and the Neutrino sealed store exist, call
//! [`resolve_oauth_config_from_neutrino`] before `LeptonAuthServicesBuilder::oauth`. The resolver
//! reads existing Neutrino rows by stable name and scope, optionally seeds missing rows from
//! `UF_OAUTH_*_CLIENT_SECRET` on first boot, and returns `Ok(None)` when OAuth is not configured.
//!
//! **Prerequisites:** Neutrino store from [`neutrino::vault::store_from_valence`]; public base
//! URL for redirect assembly; `seed_from_env` when env should fill missing vault rows on first
//! boot (existing sealed rows always win over env).
//!
//! ```rust,ignore
//! use neutrino::vault::store_from_valence;
//! use uf_oauth_boot::{resolve_oauth_config_from_neutrino, OAUTH_REDIRECT_PATH};
//!
//! let store = store_from_valence(oauth_valence);
//! let resolved = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true).await?;
//! if let Some(cfg) = resolved {
//!     let lepton = cfg.into_lepton();
//!     assert_eq!(lepton.redirect_path, OAUTH_REDIRECT_PATH);
//!     builder = builder.oauth(lepton);
//! }
//! ```
//!
//! On success `into_lepton()` carries the callback path and provider credentials Lepton expects.
//! `Ok(None)` means no mock flag and no usable provider pair — skip `.oauth(...)`. Errors map to
//! [`ResolveOAuthConfigError`] (wrong Neutrino kind, store I/O, invalid UTF-8); optional OAuth
//! hosts log once at SSR boot (`error = %e`) and continue without mounting OAuth routes.
//!
//! **Variant — mock CI without Neutrino I/O:** set `UF_OAUTH_USE_MOCK=1` with no client-secret
//! env vars; resolve returns a mock provider config without vault reads.
//!
//! ```rust,ignore
//! use uf_oauth_boot::resolve_oauth_config_from_neutrino;
//!
//! std::env::set_var("UF_OAUTH_USE_MOCK", "1");
//! let mock = resolve_oauth_config_from_neutrino(&store, "http://example.test", false).await?
//!     .expect("mock config");
//! let lepton = mock.into_lepton();
//! assert!(lepton.use_mock_provider);
//! ```
//!
//! ## Stable secret vocabulary
//!
//! Neutrino rows for OAuth client secrets use fixed names, scope, and kind so hosts, Gauge, and
//! operators can agree on vault layout without ad hoc strings. Import these constants when
//! seeding vault rows, writing Gauge policies, or correlating audit logs with resolve failures.
//!
//! ```rust,ignore
//! use uf_oauth_boot::{
//!     OAUTH_GITHUB_SECRET_NAME, OAUTH_GOOGLE_SECRET_NAME, OAUTH_REDIRECT_PATH,
//!     OAUTH_SECRET_KIND, OAUTH_SECRET_SCOPE,
//! };
//!
//! assert_eq!(OAUTH_GOOGLE_SECRET_NAME, "oauth.google.client_secret");
//! assert_eq!(OAUTH_GITHUB_SECRET_NAME, "oauth.github.client_secret");
//! assert_eq!(OAUTH_SECRET_SCOPE, "/lepton/oauth");
//! assert_eq!(OAUTH_SECRET_KIND, "oauth_client_secret");
//! assert_eq!(OAUTH_REDIRECT_PATH, "/auth/oauth/callback");
//! ```
//!
//! [`resolve_oauth_config_from_neutrino`] writes and loads rows with these literals; rows with a
//! different kind fail closed as [`ResolveOAuthConfigError::WrongKind`] without decrypting
//! ciphertext. [`OAUTH_REDIRECT_PATH`] is copied into
//! [`lepton_auth::oauth::OAuthClientConfig::redirect_path`] on every successful resolve.
//!
//! ## Env contract
//!
//! Public client ids and optional first-boot seeds come from process env (not Neutrino names):
//!
//! | Variable | Role |
//! |----------|------|
//! | `UF_OAUTH_GOOGLE_CLIENT_ID` | Google client id (public) |
//! | `UF_OAUTH_GOOGLE_CLIENT_SECRET` | Google client secret seed when `seed_from_env` and vault row missing |
//! | `UF_OAUTH_GITHUB_CLIENT_ID` | GitHub client id (public) |
//! | `UF_OAUTH_GITHUB_CLIENT_SECRET` | GitHub client secret seed when `seed_from_env` and vault row missing |
//! | `UF_OAUTH_USE_MOCK` | Truthy → mock provider path (CI / teaching) |
//! | `UF_MOCK_OIDC_URL` | Optional mock OIDC issuer URL |
//!
//! Empty or whitespace-only values are treated as unset. Existing sealed Neutrino rows always
//! win over `UF_OAUTH_*_CLIENT_SECRET` when present.
//!
//! ## Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Resolve config at SSR boot | [`resolve_oauth_config_from_neutrino`], [`ResolveOAuthConfigError`] |
//! | Redacted Debug / lepton handoff | [`ResolvedOAuthClientConfig`], [`ResolvedOAuthClientConfig::into_lepton`] |
//! | Stable Neutrino names | [`OAUTH_GOOGLE_SECRET_NAME`], [`OAUTH_GITHUB_SECRET_NAME`] |
//! | Kind / scope | [`OAUTH_SECRET_KIND`], [`OAUTH_SECRET_SCOPE`] |
//! | Callback redirect path | [`OAUTH_REDIRECT_PATH`] |
//!
//! README Owns / Concern tables mirror this surface for product orientation.
//!
//! ## Examples
//!
//! Start with [Resolve OAuth config at SSR boot](#resolve-oauth-config-at-ssr-boot).
//! `tests/resolve_oauth_config.rs` exercises vault load, env seed, missing rows, and wrong kind.
//! Workspace example `oauth-boot-host` runs an Axum oneshot without a hydrate UI.

#![deny(missing_docs)]

mod config;
mod env;
mod error;
mod resolve;

pub use config::ResolvedOAuthClientConfig;
pub use error::ResolveOAuthConfigError;
pub use resolve::resolve_oauth_config_from_neutrino;

/// Stable Neutrino secret name for the Google OAuth client secret.
pub const OAUTH_GOOGLE_SECRET_NAME: &str = "oauth.google.client_secret";
/// Stable Neutrino secret name for the GitHub OAuth client secret.
pub const OAUTH_GITHUB_SECRET_NAME: &str = "oauth.github.client_secret";
/// Scope path for OAuth client secrets.
pub const OAUTH_SECRET_SCOPE: &str = "/lepton/oauth";
/// Neutrino `kind` required for OAuth client secrets. Other kinds fail closed.
pub const OAUTH_SECRET_KIND: &str = "oauth_client_secret";
/// Lepton OAuth callback path written into [`lepton_auth::oauth::OAuthClientConfig::redirect_path`].
pub const OAUTH_REDIRECT_PATH: &str = "/auth/oauth/callback";
