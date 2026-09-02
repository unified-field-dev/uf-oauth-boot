//! Valence / Neutrino bootstrap and env prep for the teaching host.

use std::sync::Arc;

use neutrino::create_initial_neutrino_groups;
use neutrino::vault::store_from_valence;
use neutrino::ValenceSealedStore;
use uf_oauth_boot::{resolve_oauth_config_from_neutrino, OAUTH_REDIRECT_PATH};
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter,
    RegisterBackendLogicalNamesOptions, SqliteBackend, Valence, SQLITE_ENGINE_ID,
};

use crate::routes::HostState;
use crate::PUBLIC_BASE;

const OAUTH_ENV_KEYS: &[&str] = &[
    "UF_OAUTH_GOOGLE_CLIENT_ID",
    "UF_OAUTH_GOOGLE_CLIENT_SECRET",
    "UF_OAUTH_GITHUB_CLIENT_ID",
    "UF_OAUTH_GITHUB_CLIENT_SECRET",
    "UF_OAUTH_USE_MOCK",
    "UF_MOCK_OIDC_URL",
    "NEUTRINO_MASTER_KEY",
];

fn clear_oauth_env() {
    for key in OAUTH_ENV_KEYS {
        // SAFETY: single-threaded teaching host; no concurrent tests.
        unsafe {
            std::env::remove_var(key);
        }
    }
}

fn set_env(key: &str, value: &str) {
    // SAFETY: single-threaded teaching host.
    unsafe {
        std::env::set_var(key, value);
    }
}

fn prepare_env() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    clear_oauth_env();
    set_env("NEUTRINO_MASTER_KEY", &"0".repeat(64));
    if std::env::var_os("VALENCE_OWNERSHIP_UNIFIED_FETCH").is_none() {
        set_env("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    }
}

async fn boot_valence() -> Valence {
    prepare_env();
    let backend: Arc<dyn DatabaseBackend> = Arc::new(
        SqliteBackend::connect_memory()
            .await
            .expect("SqliteBackend::connect_memory"),
    );
    let mut router = DatabaseRouter::new();
    register_backend_logical_names(
        &mut router,
        backend,
        neutrino::embedded_surreal::EMBEDDED_SURREAL_LOGICAL_NAMES,
        RegisterBackendLogicalNamesOptions::default(),
    );
    let v = Valence::builder()
        .database_router(Arc::new(router))
        .default_backend_key(router_key(
            neutrino::embedded_surreal::LOGICAL_NAME,
            SQLITE_ENGINE_ID,
        ))
        .with_actor(Actor::System {
            operation: "oauth-boot-host".into(),
        })
        .build()
        .expect("build valence");
    gauge::touch_schema_inventory();
    create_initial_neutrino_groups(&v)
        .await
        .expect("create_initial_neutrino_groups");
    v
}

fn store(v: Valence) -> ValenceSealedStore {
    store_from_valence(v)
}

/// Mock resolve + first-boot seed; returns inventory flags for the teaching route.
pub async fn bootstrap_host() -> HostState {
    let store = store(boot_valence().await);

    // CI / local mock path: no Neutrino I/O when client secrets are unset.
    clear_oauth_env();
    set_env("NEUTRINO_MASTER_KEY", &"0".repeat(64));
    set_env("UF_OAUTH_USE_MOCK", "1");
    let mock = resolve_oauth_config_from_neutrino(&store, PUBLIC_BASE, false)
        .await
        .expect("mock resolve")
        .expect("mock config")
        .into_lepton();
    assert!(mock.use_mock_provider);
    assert_eq!(mock.redirect_path, OAUTH_REDIRECT_PATH);

    // First-boot seed: env client id + secret → sealed row + usable config.
    clear_oauth_env();
    set_env("NEUTRINO_MASTER_KEY", &"0".repeat(64));
    set_env("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    set_env("UF_OAUTH_GOOGLE_CLIENT_SECRET", "demo-google-secret");
    let seeded = resolve_oauth_config_from_neutrino(&store, PUBLIC_BASE, true)
        .await
        .expect("seed resolve")
        .expect("seeded config");
    let seeded_dbg = format!("{seeded:?}");
    assert!(
        !seeded_dbg.contains("demo-google-secret"),
        "teaching host must not Debug client secret: {seeded_dbg}"
    );
    let seeded = seeded.into_lepton();
    assert!(!seeded.use_mock_provider);
    assert_eq!(seeded.redirect_path, OAUTH_REDIRECT_PATH);
    assert_eq!(seeded.google_client_id.as_deref(), Some("google-client-id"));
    assert!(seeded
        .google_client_secret
        .as_ref()
        .is_some_and(|s| !s.is_empty()));
    // Never print or return secret plaintext from the teaching host.

    assert!(seeded.google_client_id.is_some());
    assert!(seeded.github_client_secret.is_none());

    HostState {
        redirect_path: seeded.redirect_path.clone(),
        use_mock_provider: seeded.use_mock_provider,
        has_google_secret: seeded.google_client_secret.is_some(),
    }
}
