//! OAuth boot host: Neutrino resolve → optional `.oauth(cfg)` handoff under a
//! session-gated teaching route.
//!
//! Copy surfaces for L5 hosts: this package's `Cargo.toml` + `main.rs`, plus the
//! product-mount dependency / builder sketches in the host README. Oneshot path
//! `/auth/oauth/boot` is a teaching stand-in for host SSR boot; live callback
//! stays `/auth/oauth/callback` (see JSON `inventory`).
//!
//! ## When to use
//! Smoke `resolve_oauth_config_from_neutrino` (mock + env seed) without mounting
//! a full Lepton auth UI.
//!
//! ## Command
//! ```bash
//! export CARGO_BUILD_JOBS=1
//! export CARGO_TARGET_DIR=target-uf-oauth-boot
//! cargo run -p oauth-boot-host
//! ```
//!
//! ## Success
//! Stdout prints `oauth_boot_host: OK — mock + seed resolve + /auth/oauth/boot`.
//!
//! ## Look next
//! Wire `LeptonAuthServicesBuilder::oauth(cfg)` in an L5 host (site / embedded /
//! remote-fleet).

#![allow(clippy::print_stdout, clippy::unwrap_used, clippy::expect_used)]
#![allow(missing_docs)]

mod boot;
mod routes;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uf_oauth_boot::{
    OAUTH_GITHUB_SECRET_NAME, OAUTH_GOOGLE_SECRET_NAME, OAUTH_REDIRECT_PATH, OAUTH_SECRET_KIND,
    OAUTH_SECRET_SCOPE,
};

use boot::bootstrap_host;
use routes::app;

const PUBLIC_BASE: &str = "http://127.0.0.1:3000";

#[tokio::main]
async fn main() {
    let state = bootstrap_host().await;

    let denied = app(state.clone())
        .oneshot(
            Request::builder()
                .uri("/auth/oauth/boot")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot")
        .status();
    assert_eq!(denied, StatusCode::UNAUTHORIZED);

    let response = app(state)
        .oneshot(
            Request::builder()
                .uri("/auth/oauth/boot")
                .header("x-demo-user", "demo-ops")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["path"], "/auth/oauth/boot");
    assert_eq!(body["has_google_secret"], true);
    assert_eq!(body["inventory"]["secret_scope"], OAUTH_SECRET_SCOPE);
    assert_eq!(body["inventory"]["secret_kind"], OAUTH_SECRET_KIND);
    assert_eq!(
        body["inventory"]["google_secret_name"],
        OAUTH_GOOGLE_SECRET_NAME
    );
    assert_eq!(
        body["inventory"]["github_secret_name"],
        OAUTH_GITHUB_SECRET_NAME
    );
    assert_eq!(body["inventory"]["redirect_path"], OAUTH_REDIRECT_PATH);
    assert_eq!(
        body["inventory"]["builder_hook"],
        "LeptonAuthServicesBuilder::oauth"
    );
    let body_text = String::from_utf8_lossy(&bytes);
    assert!(
        !body_text.contains("demo-google-secret"),
        "response must not echo client secret"
    );

    println!("oauth_boot_host: OK — mock + seed resolve + /auth/oauth/boot");
}
