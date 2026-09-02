//! Session gate + teaching `/auth/oauth/boot` inventory route.

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use uf_oauth_boot::{
    OAUTH_GITHUB_SECRET_NAME, OAUTH_GOOGLE_SECRET_NAME, OAUTH_REDIRECT_PATH, OAUTH_SECRET_KIND,
    OAUTH_SECRET_SCOPE,
};

use crate::PUBLIC_BASE;

#[derive(Clone)]
pub struct DemoSession {
    pub user_id: String,
}

#[derive(Clone)]
pub struct HostState {
    pub redirect_path: String,
    pub use_mock_provider: bool,
    pub has_google_secret: bool,
}

async fn require_session(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    if req.extensions().get::<DemoSession>().is_some() {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn inject_demo_session(mut req: Request<Body>, next: Next) -> Response {
    if let Some(user) = req
        .headers()
        .get("x-demo-user")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
    {
        req.extensions_mut().insert(DemoSession { user_id: user });
    }
    next.run(req).await
}

async fn oauth_boot_api(
    Extension(session): Extension<DemoSession>,
    Extension(state): Extension<HostState>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "path": "/auth/oauth/boot",
        "user": session.user_id,
        "public_base_url": PUBLIC_BASE,
        "redirect_path": state.redirect_path,
        "use_mock_provider": state.use_mock_provider,
        "google_client_id_set": true,
        "has_google_secret": state.has_google_secret,
        "has_github_secret": false,
        // Matches L5 host handoff + Neutrino stable names (not secret values).
        "inventory": {
            "builder_hook": "LeptonAuthServicesBuilder::oauth",
            "resolve_api": "resolve_oauth_config_from_neutrino",
            "redirect_path": OAUTH_REDIRECT_PATH,
            "secret_scope": OAUTH_SECRET_SCOPE,
            "secret_kind": OAUTH_SECRET_KIND,
            "google_secret_name": OAUTH_GOOGLE_SECRET_NAME,
            "github_secret_name": OAUTH_GITHUB_SECRET_NAME,
        },
    }))
}

pub fn app(state: HostState) -> Router {
    Router::new()
        .route("/auth/oauth/boot", get(oauth_boot_api))
        .route_layer(from_fn(require_session))
        .layer(Extension(state))
        .layer(from_fn(inject_demo_session))
}
