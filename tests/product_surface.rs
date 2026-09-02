//! Gate: oauth-boot-host inventory stays aligned with public constants.
//!
//! Featureless sibling-source contract (gauge / neutrino pattern).

#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn oauth_boot_host_matches_public_api_happy_path() {
    let host_src = workspace_root().join("examples/oauth-boot-host/src");
    let host = [
        fs::read_to_string(host_src.join("main.rs")).expect("oauth-boot-host main.rs"),
        fs::read_to_string(host_src.join("boot.rs")).expect("oauth-boot-host boot.rs"),
        fs::read_to_string(host_src.join("routes.rs")).expect("oauth-boot-host routes.rs"),
    ]
    .join("\n");
    for needle in [
        "resolve_oauth_config_from_neutrino",
        "\"builder_hook\": \"LeptonAuthServicesBuilder::oauth\"",
        "OAUTH_REDIRECT_PATH",
        "OAUTH_SECRET_SCOPE",
        "OAUTH_SECRET_KIND",
        "OAUTH_GOOGLE_SECRET_NAME",
        "OAUTH_GITHUB_SECRET_NAME",
        "/auth/oauth/boot",
        "into_lepton",
    ] {
        assert!(
            host.contains(needle),
            "oauth-boot-host missing contract `{needle}`"
        );
    }

    let crate_src = [
        fs::read_to_string(workspace_root().join("src/lib.rs")).expect("lib.rs"),
        fs::read_to_string(workspace_root().join("src/error.rs")).expect("error.rs"),
        fs::read_to_string(workspace_root().join("src/resolve.rs")).expect("resolve.rs"),
        fs::read_to_string(workspace_root().join("src/config.rs")).expect("config.rs"),
    ]
    .join("\n");
    for needle in [
        "oauth.google.client_secret",
        "oauth.github.client_secret",
        "/lepton/oauth",
        "oauth_client_secret",
        "/auth/oauth/callback",
        "ResolveOAuthConfigError",
        "ResolvedOAuthClientConfig",
        "OAUTH_REDIRECT_PATH",
        "into_lepton",
    ] {
        assert!(
            crate_src.contains(needle),
            "crate src missing stable constant surface `{needle}`"
        );
    }
}
